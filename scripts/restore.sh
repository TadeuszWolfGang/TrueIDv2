#!/usr/bin/env bash
set -euo pipefail

# TrueID Database Restore Script
# Usage: ./scripts/restore.sh <backup_file>
#
# WARNING: Stops TrueID, replaces database, requires manual restart.

BACKUP_FILE="${1:?Usage: $0 <backup_file.db.gz>}"
DB_PATH="${DATABASE_URL:-net-identity.db}"
DB_PATH="${DB_PATH#sqlite://}"
DB_PATH="${DB_PATH%%\?*}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "=== TrueID Restore ==="
echo "Source: $BACKUP_FILE"
echo "Target: $DB_PATH"
echo ""
echo "WARNING: This will replace the current database."
echo "Make sure TrueID is stopped before proceeding."
read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Backup current DB (safety net)
if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "${DB_PATH}.pre-restore-$(date +%Y%m%d-%H%M%S)"
    echo "Current DB backed up."
fi

# Restore
if [[ "$BACKUP_FILE" == *.gz ]]; then
    gunzip -c "$BACKUP_FILE" > "$DB_PATH"
else
    cp "$BACKUP_FILE" "$DB_PATH"
fi

# Remove WAL/SHM (will be recreated)
rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"

echo "Restore complete. Start TrueID to apply any pending migrations."
