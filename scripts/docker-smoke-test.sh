#!/usr/bin/env bash
# docker-smoke-test.sh — Verifies container starts, DB initializes, health passes.
#
# Usage:
#   ./scripts/docker-smoke-test.sh [image_name]
#   Default image: sycope-trueid:latest

set -euo pipefail

IMAGE="${1:-sycope-trueid:latest}"
RUNTIME="${CONTAINER_RUNTIME:-podman}"  # or "docker"
CONTAINER="trueid-smoke-$$"
DATA_DIR=$(mktemp -d)

cleanup() {
    $RUNTIME rm -f "$CONTAINER" 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

PASS=0
FAIL=0
green() { printf "\033[32m%s %s\033[0m\n" "✓" "$1"; PASS=$((PASS+1)); }
red() { printf "\033[31m%s %s\033[0m\n" "✗" "$1"; FAIL=$((FAIL+1)); }

echo "=== TrueID Docker Smoke Test ==="
echo "Image:   $IMAGE"
echo "Runtime: $RUNTIME"
echo "Tmpdir:  $DATA_DIR"
echo

# Make data dir world-writable for non-root container user
chmod 777 "$DATA_DIR"

# Start container
$RUNTIME run -d \
    --name "$CONTAINER" \
    -v "$DATA_DIR:/app/data" \
    -e DATABASE_URL="sqlite:///app/data/net-identity.db?mode=rwc" \
    -e RUST_LOG=info \
    -e RADIUS_BIND="0.0.0.0:1813" \
    -e AD_SYSLOG_BIND="0.0.0.0:5514" \
    -e DHCP_SYSLOG_BIND="0.0.0.0:5516" \
    -e ADMIN_HTTP_BIND="0.0.0.0:9090" \
    "$IMAGE" trueid-engine

echo "Waiting 5s for startup..."
sleep 5

LOGS="$($RUNTIME logs "$CONTAINER" 2>&1 || true)"

# 1. Container is running
if $RUNTIME inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    green "Container is running"
else
    red "Container failed to start"
    echo "--- Container logs ---"
    $RUNTIME logs "$CONTAINER" 2>&1 | tail -30
    exit 1
fi

# 2. DB file created
if [ -f "$DATA_DIR/net-identity.db" ]; then
    green "Database file created"
else
    red "Database file not found"
fi

# 3. OUI loaded
if [[ "$LOGS" == *"Loaded OUI vendor database"* ]]; then
    green "OUI vendor database loaded"
else
    red "OUI vendor database NOT loaded"
fi

# 4. No fatal errors
if ! printf '%s' "$LOGS" | grep -Eqi "panic|FATAL"; then
    green "No panics or fatal errors"
else
    red "Panics or fatal errors found in logs"
    printf '%s\n' "$LOGS" | grep -Ei "panic|FATAL" | head -5
fi

# 5. Entrypoint printed startup info
if [[ "$LOGS" == *"TrueID container starting"* ]]; then
    green "Entrypoint pre-flight executed"
else
    red "Entrypoint did not run"
fi

# 6. Healthcheck via sqlite3
if $RUNTIME exec "$CONTAINER" sqlite3 /app/data/net-identity.db 'SELECT 1' 2>/dev/null | grep -q 1; then
    green "sqlite3 healthcheck passes inside container"
else
    red "sqlite3 healthcheck failed"
fi

# 7. Permission test — verify trueid user owns the DB file
DB_OWNER=$($RUNTIME exec "$CONTAINER" stat -c '%U' /app/data/net-identity.db 2>/dev/null || echo "unknown")
if [ "$DB_OWNER" = "trueid" ]; then
    green "DB file owned by trueid user"
else
    red "DB file owned by '$DB_OWNER' (expected 'trueid')"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
