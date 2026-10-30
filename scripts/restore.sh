#!/usr/bin/env bash
set -euo pipefail

# TrueID Database Restore Script
# Usage: ./scripts/restore.sh <backup_file>
# Requires stopped TrueID services; activation remains manual.

BACKUP_FILE="${1:?Usage: $0 <backup_file.db.gz>}"
if [[ "${DATABASE_URL+x}" == x ]]; then
    DB_PATH="$DATABASE_URL"
else
    DB_PATH=net-identity.db
fi
DB_PATH="${DB_PATH%%\?*}"
case "$DB_PATH" in
    sqlite://*) DB_PATH="${DB_PATH#sqlite://}" ;;
    sqlite:*) DB_PATH="${DB_PATH#sqlite:}" ;;
    *)
        if [[ "$DB_PATH" =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]]; then
            printf 'ERROR: Unsupported DATABASE_URL scheme\n' >&2
            exit 1
        fi
        ;;
esac
case "$DB_PATH" in
    ""|:memory:)
        printf 'ERROR: Invalid database path\n' >&2
        exit 1
        ;;
esac
umask 077
export LC_ALL=C

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
resolve_path() {
    local path=$1 part current=/
    local -a parts
    [[ "$path" = /* ]] || path="$PWD/$path"
    [[ ! "$path" =~ [[:cntrl:]] && "$path" != */ ]] || fail 'Unsafe file path'
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [[ -d "$current" ]] || fail 'Non-directory path component'
        case "$part" in ''|.) continue;; ..) current=${current%/*}; current=${current:-/};;
            *) current="${current%/}/$part";; esac
        [[ -e "$current" && ! -L "$current" ]] || fail 'Missing or linked path component'
    done
    printf '%s\n' "$current"
}
regular_file() {
    [[ -f "$1" && ! -L "$1" && $(stat -c '%h' -- "$1") = 1 ]]
}
no_sidecars() {
    local suffix
    for suffix in -wal -shm -journal; do
        [[ ! -e "$1$suffix" && ! -L "$1$suffix" ]] || fail 'SQLite sidecar present; preserved'
    done
}
check_sqlite() {
    local file=$1 uri result
    regular_file "$file" && [[ -s "$file" ]] || fail 'Empty or unsafe SQLite file'
    no_sidecars "$file"
    uri=${file//%/%25}; uri=${uri//\?/%3F}; uri=${uri//#/%23}
    result=$(sqlite3 -readonly "file:$uri?immutable=1" 'PRAGMA integrity_check;') || fail 'SQLite check failed'
    [[ "$result" = ok ]] || fail 'SQLite integrity check did not return ok'
}
offline() {
    local unit state line seen
    for unit in trueid-web.service trueid-engine.service; do
        state=$(systemctl show "$unit" --no-pager -p Id -p LoadState -p ActiveState -p SubState) || fail 'Service state unavailable'
        seen='|'
        while IFS= read -r line; do
            case "$line" in
                "Id=$unit"|LoadState=loaded|ActiveState=inactive|SubState=dead)
                    [[ "$seen" != *"|$line|"* ]] || fail 'Duplicate service state'
                    seen="$seen$line|";;
                *) fail 'Service must be loaded and inactive (dead)';;
            esac
        done <<< "$state"
        for line in "Id=$unit" LoadState=loaded ActiveState=inactive SubState=dead; do
            [[ "$seen" = *"|$line|"* ]] || fail 'Incomplete service state'
        done
    done
}
file_state() { stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$1"; }

BACKUP_FILE=$(resolve_path "$BACKUP_FILE")
DB_PATH=$(resolve_path "$DB_PATH")
regular_file "$BACKUP_FILE" && regular_file "$DB_PATH" || fail 'Input and target must be regular single-link files'
[[ "$BACKUP_FILE" != "$DB_PATH" && ! "$BACKUP_FILE" -ef "$DB_PATH" ]] || fail 'Input aliases target'
no_sidecars "$BACKUP_FILE"
no_sidecars "$DB_PATH"
PARENT=${DB_PATH%/*}
PARENT=${PARENT:-/}
PARENT_ID=$(stat -c '%d:%i:%u:%a' -- "$PARENT")
[[ $(stat -c '%u' -- "$PARENT") = "$UID" && -w "$PARENT" && -x "$PARENT" ]] || fail 'Target parent must be owned and writable'
PARENT_MODE=$(stat -c '%a' -- "$PARENT")
(( (8#$PARENT_MODE & 0022) == 0 )) || fail 'Target parent is writable by other users'

printf 'WARNING: This replaces the current database; both TrueID services must be stopped.\n'
read -p 'Continue? [y/N] ' -n 1 -r || fail 'Confirmation unavailable'
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then echo 'Aborted.'; exit 0; fi
offline
TARGET_STATE=$(file_state "$DB_PATH")
INPUT_STATE=$(file_state "$BACKUP_FILE")
TARGET_HASH=$(sha256sum < "$DB_PATH")
INPUT_HASH=$(sha256sum < "$BACKUP_FILE")
OWNER=$(stat -c '%u' -- "$DB_PATH")
GROUP=$(stat -c '%g' -- "$DB_PATH")
LOCK="$DB_PATH.restore.lock"
STAGE= LOCK_ID= STAGE_ID= KEEP_STAGE=0
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n "$STAGE" && "$KEEP_STAGE" = 0 ]]; then
        if [[ ! -L "$STAGE" && $(stat -c '%d:%i:%u:%a' -- "$STAGE") = "$STAGE_ID" ]]; then
            rm -rf -- "$STAGE" || status=1
        else status=1; fi
    fi
    if [[ -n "$LOCK_ID" ]]; then
        if [[ ! -L "$LOCK" && $(stat -c '%d:%i:%u:%a' -- "$LOCK") = "$LOCK_ID" ]]; then
            rmdir -- "$LOCK" || status=1
        else status=1; fi
    fi
    exit "$status"
}
mkdir -- "$LOCK" || fail 'Restore target is already locked'
LOCK_ID=$(stat -c '%d:%i:%u:%a' -- "$LOCK")
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
STAGE=$(mktemp -d "$PARENT/.trueid-restore.XXXXXXXX")
STAGE_ID=$(stat -c '%d:%i:%u:%a' -- "$STAGE")
[[ $(stat -c '%u:%a' -- "$STAGE") = "$UID:700" ]] || fail 'Unsafe private staging'
CANDIDATE="$STAGE/replacement.db"
ORIGINAL="$STAGE/original.db"
if [[ "$BACKUP_FILE" = *.gz ]]; then
    gzip -dc -- "$BACKUP_FILE" > "$CANDIDATE" || fail 'Complete gzip decode failed'
    gzip -t -- "$BACKUP_FILE" || fail 'Complete gzip verification failed'
else
    cp -- "$BACKUP_FILE" "$CANDIDATE" || fail 'Input staging failed'
fi
check_sqlite "$CANDIDATE"
[[ $(file_state "$BACKUP_FILE") = "$INPUT_STATE" && $(sha256sum < "$BACKUP_FILE") = "$INPUT_HASH" ]] || fail 'Input changed'
no_sidecars "$BACKUP_FILE"
[[ $(file_state "$DB_PATH") = "$TARGET_STATE" && $(sha256sum < "$DB_PATH") = "$TARGET_HASH" ]] || fail 'Target changed before preservation'
no_sidecars "$DB_PATH"
cp -- "$DB_PATH" "$ORIGINAL" || fail 'Original preservation failed'
[[ $(sha256sum < "$ORIGINAL") = "$TARGET_HASH" ]] || fail 'Original copy differs'
check_sqlite "$ORIGINAL"
chown "$OWNER:$GROUP" -- "$CANDIDATE" "$ORIGINAL" || fail 'Cannot preserve numeric ownership'
chmod 600 -- "$CANDIDATE" "$ORIGINAL"
for FILE in "$CANDIDATE" "$ORIGINAL"; do
    regular_file "$FILE" || fail 'Staged file is not single-link'
    [[ $(stat -c '%u:%g:%a' -- "$FILE") = "$OWNER:$GROUP:600" ]] || fail 'Staged ownership or mode differs'
    [[ $(stat -c '%d' -- "$FILE") = $(stat -c '%d' -- "$DB_PATH") ]] || fail 'Staging is on a different filesystem'
done

# This fresh read occurs after both real SQLite files have been staged.
offline
[[ $(resolve_path "$DB_PATH") = "$DB_PATH" && $(file_state "$DB_PATH") = "$TARGET_STATE" ]] || fail 'Live target identity changed'
[[ $(sha256sum < "$DB_PATH") = "$TARGET_HASH" ]] || fail 'Live target bytes changed'
no_sidecars "$DB_PATH"
[[ $(stat -c '%d:%i:%u:%a' -- "$PARENT") = "$PARENT_ID" && -w "$PARENT" && -x "$PARENT" ]] || fail 'Target parent changed'
# Preserve the verified old point even if activation fails or is interrupted.
KEEP_STAGE=1
mv -fT -- "$CANDIDATE" "$DB_PATH" || fail 'Atomic activation failed; old point retained'
printf 'Restore complete. Verified original retained: %s\n' "$ORIGINAL"
printf 'No service action was performed; validate before starting TrueID manually.\n'
