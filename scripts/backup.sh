#!/usr/bin/env bash
set -euo pipefail

# TrueID Database Backup Script
# Usage: ./scripts/backup.sh [backup_dir]
#
# Performs online SQLite backup using .backup command.
# Safe to run while TrueID is running (uses SQLite WAL mode).

BACKUP_DIR="${1:-./backups}"
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
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"
umask 077
export LC_ALL=C

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
case "$KEEP_DAYS" in ''|*[!0-9]*) fail 'Invalid BACKUP_KEEP_DAYS';; esac
find . -maxdepth 0 -mtime +"$KEEP_DAYS" -print >/dev/null || fail 'Invalid retention age'

# Resolve components without following a symlink, including an existing final name.
resolve_path() {
    local path=$1 part current=/
    local -a parts
    [[ "$path" = /* ]] || path="$PWD/$path"
    [[ ! "$path" =~ [[:cntrl:]] ]] || fail 'Control character in path'
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        case "$part" in ''|.) continue;; ..) current=${current%/*}; current=${current:-/};;
            *) current="${current%/}/$part";; esac
        [[ ! -L "$current" ]] || fail 'Symlink in path'
    done
    printf '%s\n' "$current"
}
private_dir() {
    [[ -d "$1" && ! -L "$1" && $(stat -c '%u:%a' -- "$1") = "$UID:700" ]]
}
regular_file() {
    [[ -f "$1" && ! -L "$1" && $(stat -c '%h' -- "$1") = 1 ]]
}

BACKUP_DIR=$(resolve_path "$BACKUP_DIR")
# SQLite dot-command filenames cannot safely contain these characters.
[[ "$BACKUP_DIR" != *"'"* && "$BACKUP_DIR" != *\\* ]] || fail 'Unsupported output quoting'
DB_PATH=$(resolve_path "$DB_PATH")
regular_file "$DB_PATH" || fail 'Source must be an existing regular file'
mkdir -p -- "$BACKUP_DIR"
private_dir "$BACKUP_DIR" || fail 'Backup directory must be owned and mode0700'
LOCK="$BACKUP_DIR/.trueid-backup.lock"
STAGE= LOCK_ID= STAGE_ID=
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n "$STAGE" ]]; then
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
mkdir -- "$LOCK" || fail 'Backup namespace is already locked'
LOCK_ID=$(stat -c '%d:%i:%u:%a' -- "$LOCK")
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
STAGE=$(mktemp -d "$BACKUP_DIR/.trueid-backup.XXXXXXXX")
STAGE_ID=$(stat -c '%d:%i:%u:%a' -- "$STAGE")
private_dir "$STAGE" || fail 'Unsafe staging directory'
RAW="$STAGE/snapshot.db"
COMPRESSED="$STAGE/snapshot.db.gz"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/trueid-$TIMESTAMP.db.gz"
[[ ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || fail 'Backup name already exists'

# Keep the online SQLite API: committed WAL data belongs in the snapshot.
sqlite3 -readonly "$DB_PATH" ".backup '$RAW'" || fail 'Online backup failed'
regular_file "$RAW" && [[ -s "$RAW" ]] || fail 'Empty or unsafe SQLite snapshot'
SQLITE_RAW=${RAW//%/%25}
SQLITE_RAW=${SQLITE_RAW//\?/%3F}
SQLITE_RAW=${SQLITE_RAW//#/%23}
INTEGRITY=$(sqlite3 -readonly "file:$SQLITE_RAW?immutable=1" 'PRAGMA integrity_check;') || fail 'SQLite check failed'
[[ "$INTEGRITY" = ok ]] || fail 'SQLite integrity check did not return ok'
[[ ! -e "$RAW-wal" && ! -L "$RAW-wal" && ! -e "$RAW-shm" && ! -L "$RAW-shm" ]] || fail 'Unexpected snapshot sidecar'
gzip -c -- "$RAW" > "$COMPRESSED" || fail 'Compression failed'
gzip -t -- "$COMPRESSED" || fail 'Compressed backup verification failed'
chmod 600 -- "$COMPRESSED"
regular_file "$COMPRESSED" || fail 'Unsafe compressed backup'
[[ $(stat -c '%u:%a' -- "$COMPRESSED") = "$UID:600" ]] || fail 'Backup is not private'

# A same-filesystem hardlink is atomic and fails if the final name exists.
ln -T -- "$COMPRESSED" "$BACKUP_FILE" || fail 'Exclusive publication failed'
NEW_ID=$(stat -c '%d:%i' -- "$COMPRESSED")
rm -- "$COMPRESSED"
regular_file "$BACKUP_FILE" || fail 'Published backup is not single-link'
[[ $(stat -c '%d:%i:%u:%a' -- "$BACKUP_FILE") = "$NEW_ID:$UID:600" ]] || fail 'Published identity changed'

# Never descend into foreign/public directories; unsafe objects stay untouched.
# Finish enumeration before deleting anything, and exclude the new inode and path.
find -P "$BACKUP_DIR" \
    \( -type d \( ! -uid "$UID" -o -perm /077 \) -prune \) -o \
    \( -type f -uid "$UID" -links 1 ! -perm /022 -name 'trueid-*.db.gz' \
       -mtime +"$KEEP_DAYS" ! -samefile "$BACKUP_FILE" \
       -printf '%D:%i:%U:%m:%n\0%p\0' \) > "$STAGE/retention" || fail 'Retention enumeration failed'
DELETED=0
while IFS= read -r -d '' OLD_ID && IFS= read -r -d '' OLD; do
    [[ "$OLD" != "$BACKUP_FILE" ]] || fail 'Retention selected the new point'
    regular_file "$OLD" || fail 'Retention candidate changed type or links'
    [[ $(stat -c '%d:%i:%u:%a:%h' -- "$OLD") = "$OLD_ID" ]] || fail 'Retention candidate changed identity'
    [[ $(stat -c '%d:%i' -- "$OLD") != "$NEW_ID" ]] || fail 'Retention selected the new inode'
    PARENT=${OLD%/*}
    while [[ "$PARENT" != "$BACKUP_DIR" ]]; do
        private_dir "$PARENT" || fail 'Retention containment changed'
        PARENT=${PARENT%/*}
    done
    private_dir "$BACKUP_DIR" || fail 'Backup directory changed'
    rm -- "$OLD" || fail 'Retention deletion failed; new point preserved'
    DELETED=$((DELETED + 1))
done < "$STAGE/retention"
printf 'Backup complete: %s\n' "$BACKUP_FILE"
printf 'Cleaned up %s backup(s) older than %s days.\n' "$DELETED" "$KEEP_DAYS"
echo 'Done.'
