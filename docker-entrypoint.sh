#!/bin/sh
set -e

echo "TrueID container starting (uid=$(id -u), gid=$(id -g))"

# Pre-flight: verify /app/data is writable.
if ! touch /app/data/.write-test 2>/dev/null; then
    echo "FATAL: /app/data is not writable by uid=$(id -u) gid=$(id -g)"
    echo ""
    echo "  The mounted volume must be owned by UID $(id -u)."
    echo "  Fix on the host:"
    echo "    chown -R $(id -u):$(id -g) /path/to/host/data"
    echo "  Or use:  podman run --userns=keep-id ..."
    echo ""
    exit 1
fi
rm -f /app/data/.write-test

# OUI CSV auto-discovery.
if [ -z "${OUI_CSV_PATH:-}" ]; then
    if [ -f /app/data/oui.csv ]; then
        export OUI_CSV_PATH=/app/data/oui.csv
    elif [ -f /app/oui.csv ]; then
        export OUI_CSV_PATH=/app/oui.csv
    fi
fi

echo "  DATABASE_URL=${DATABASE_URL:-<default>}"
echo "  OUI_CSV_PATH=${OUI_CSV_PATH:-<not set, vendor lookup disabled>}"
echo "  Command: $*"

exec "$@"
