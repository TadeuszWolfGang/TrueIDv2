#!/usr/bin/env bash
# smoke-test.sh — End-to-end smoke test for TrueID auth system.
#
# Usage:
#   ./scripts/smoke-test.sh [base_url]
#
# Default base_url: http://127.0.0.1:3000
# Requires TRUEID_SMOKE_ADMIN_PASS to be set for the bootstrap admin.

set -euo pipefail

BASE="${1:-http://127.0.0.1:3000}"
ADMIN_USER="${TRUEID_SMOKE_ADMIN_USER:-admin}"
ADMIN_PASS="${TRUEID_SMOKE_ADMIN_PASS:?Set TRUEID_SMOKE_ADMIN_PASS before running smoke-test.sh}"
PASS=0
FAIL=0

green()  { printf "\033[32m✓ %s\033[0m\n" "$1"; }
red()    { printf "\033[31m✗ %s\033[0m\n" "$1"; }

check() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        green "$desc (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        red "$desc — expected $expected, got $actual"
        FAIL=$((FAIL + 1))
    fi
}

COOKIES=$(mktemp)
trap "rm -f $COOKIES" EXIT

echo "=== TrueID Smoke Test ==="
echo "Target: $BASE"
echo

# 1. Health check
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
check "Health check" "200" "$STATUS"

# 2. Login
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
check "Login as admin" "200" "$STATUS"

# 3. /me with cookies
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/auth/me")
check "GET /api/auth/me" "200" "$STATUS"

# 4. GET mappings (authenticated)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v1/mappings")
check "GET /api/v1/mappings" "200" "$STATUS"

# 5. GET users (admin only)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v1/users")
check "GET /api/v1/users (admin)" "200" "$STATUS"

# 6. GET audit logs (admin only)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v1/audit-logs")
check "GET /api/v1/audit-logs (admin)" "200" "$STATUS"

# 7. Anonymous access → 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/mappings")
check "Anonymous GET /api/v1/mappings" "401" "$STATUS"

# 8. Wrong password → 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"wrongpassword\"}")
check "Login with wrong password" "401" "$STATUS"

# Extract CSRF token from cookie jar for mutating requests
CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')

# 9. Token refresh
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" -c "$COOKIES" \
    -X POST -H "X-CSRF-Token: $CSRF" "$BASE/api/auth/refresh")
check "Token refresh" "200" "$STATUS"

# Re-extract CSRF after refresh (may have rotated)
CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')

# 10. Logout
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" -c "$COOKIES" \
    -X POST -H "X-CSRF-Token: $CSRF" "$BASE/api/auth/logout")
check "Logout" "200" "$STATUS"

# 11. /me after logout → 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/auth/me")
check "GET /me after logout" "401" "$STATUS"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
