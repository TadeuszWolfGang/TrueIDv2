#!/usr/bin/env bash
set -euo pipefail

# TrueID Database Backup Script
# Usage: ./scripts/backup.sh [backup_dir]
#
# Performs online SQLite backup using .backup command.
# Safe to run while TrueID is running (uses SQLite WAL mode).

BACKUP_DIR="${1:-./backups}"
DB_PATH="${DATABASE_URL:-net-identity.db}"
DB_PATH="${DB_PATH#sqlite://}"
DB_PATH="${DB_PATH%%\?*}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/trueid-${TIMESTAMP}.db"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

echo "=== TrueID Backup ==="
echo "Source: $DB_PATH"
echo "Target: $BACKUP_FILE"

if [ ! -f "$DB_PATH" ]; then
    echo "ERROR: Database file not found: $DB_PATH"
    exit 1
fi

# Online backup (safe with WAL mode)
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

# Compress
gzip "$BACKUP_FILE"
BACKUP_FILE="${BACKUP_FILE}.gz"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup complete: $BACKUP_FILE ($SIZE)"

# Cleanup old backups
DELETED=$(find "$BACKUP_DIR" -name "trueid-*.db.gz" -mtime +"$KEEP_DAYS" -delete -print | wc -l)
if [ "$DELETED" -gt 0 ]; then
    echo "Cleaned up $DELETED backup(s) older than $KEEP_DAYS days."
fi

echo "Done."
