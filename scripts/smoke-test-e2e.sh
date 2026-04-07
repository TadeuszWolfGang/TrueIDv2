#!/usr/bin/env bash
# smoke-test-e2e.sh — Extended end-to-end smoke test for TrueID.
#
# Covers auth lifecycle, v2 API contracts, export formats, engine health,
# and basic conflict/alert pipeline. Run against a live Docker Compose stack.
#
# Usage:
#   ./scripts/smoke-test-e2e.sh [base_url]
#
# Default base_url: http://127.0.0.1:3000
# Requires TRUEID_SMOKE_ADMIN_PASS to be set for the bootstrap admin.

set -euo pipefail

BASE="${1:-http://127.0.0.1:3000}"
ADMIN_USER="${TRUEID_SMOKE_ADMIN_USER:-admin}"
ADMIN_PASS="${TRUEID_SMOKE_ADMIN_PASS:?Set TRUEID_SMOKE_ADMIN_PASS before running smoke-test-e2e.sh}"
PASS=0
FAIL=0
SKIP=0

green()  { printf "\033[32m✓ %s\033[0m\n" "$1"; }
red()    { printf "\033[31m✗ %s\033[0m\n" "$1"; }
yellow() { printf "\033[33m⊘ %s\033[0m\n" "$1"; }

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

check_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        green "$desc"
        PASS=$((PASS + 1))
    else
        red "$desc — response does not contain '$needle'"
        FAIL=$((FAIL + 1))
    fi
}

COOKIES=$(mktemp)
trap "rm -f $COOKIES" EXIT

echo "=== TrueID E2E Smoke Test ==="
echo "Target: $BASE"
echo

# ── Section 1: Health & Auth ──
echo "--- Health & Auth ---"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
check "Health check" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
check "Login as admin" "200" "$STATUS"

BODY=$(curl -s -b "$COOKIES" "$BASE/api/auth/me")
STATUS=$(echo "$BODY" | head -c 1)
check_contains "GET /me returns username" "$ADMIN_USER" "$BODY"

# Anonymous → 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v2/search?q=test")
check "Anonymous v2 search → 401" "401" "$STATUS"

CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')

# ── Section 2: V2 API Contracts ──
echo
echo "--- V2 API Contracts ---"

# Search response shape
BODY=$(curl -s -b "$COOKIES" "$BASE/api/v2/search?q=&limit=5")
check_contains "Search has page field" '"page"' "$BODY"
check_contains "Search has limit field" '"limit"' "$BODY"
check_contains "Search has query_time_ms" '"query_time_ms"' "$BODY"

# Conflicts endpoint
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/conflicts?limit=5")
check "GET /api/v2/conflicts" "200" "$STATUS"

BODY=$(curl -s -b "$COOKIES" "$BASE/api/v2/conflicts/stats")
check_contains "Conflicts stats has total_unresolved" '"total_unresolved"' "$BODY"
check_contains "Conflicts stats has by_type" '"by_type"' "$BODY"

# Alerts
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/alerts/history?limit=5")
check "GET /api/v2/alerts/history" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/alerts/stats")
check "GET /api/v2/alerts/stats" "200" "$STATUS"

# Timeline
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/timeline/ip/127.0.0.1")
check "GET /api/v2/timeline/ip (nonexistent)" "200" "$STATUS"

# Map
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/map/topology")
check "GET /api/v2/map/topology" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/map/flows")
check "GET /api/v2/map/flows" "200" "$STATUS"

# Analytics
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/analytics/sources")
check "GET /api/v2/analytics/sources" "200" "$STATUS"

# ── Section 3: Conflict & Alert Pipeline ──
echo
echo "--- Conflict & Alert Pipeline ---"

# Create an alert rule
CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')
BODY=$(curl -s -w "\n%{http_code}" -b "$COOKIES" \
    -X POST "$BASE/api/v2/alerts/rules" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF" \
    -d '{"name":"smoke-test-rule","rule_type":"ip_conflict","severity":"warning","action_log":true,"cooldown_seconds":60}')
RULE_STATUS=$(printf '%s\n' "$BODY" | awk 'END { print }')
RULE_BODY=$(printf '%s\n' "$BODY" | sed '$d')
check "Create alert rule" "201" "$RULE_STATUS"

# Extract rule ID
RULE_ID=$(echo "$RULE_BODY" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*' || true)
if [ -n "$RULE_ID" ]; then
    green "Alert rule created with id=$RULE_ID"
else
    yellow "Could not extract rule ID, skipping rule cleanup"
fi

# Create a source_down alert rule
BODY=$(curl -s -w "\n%{http_code}" -b "$COOKIES" \
    -X POST "$BASE/api/v2/alerts/rules" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF" \
    -d '{"name":"source-down-smoke","rule_type":"source_down","severity":"critical","conditions":"{\"source\":\"AD TLS\"}","action_log":true,"cooldown_seconds":300}')
SOURCE_RULE_STATUS=$(printf '%s\n' "$BODY" | awk 'END { print }')
SOURCE_RULE_BODY=$(printf '%s\n' "$BODY" | sed '$d')
check "Create source_down alert rule" "201" "$SOURCE_RULE_STATUS"
check_contains "source_down response includes AD TLS" "AD TLS" "$SOURCE_RULE_BODY"
check_contains "source_down response includes silence_seconds" "silence_seconds" "$SOURCE_RULE_BODY"

SOURCE_RULE_ID=$(echo "$SOURCE_RULE_BODY" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*' || true)
if [ -n "$SOURCE_RULE_ID" ]; then
    green "Source Down rule created with id=$SOURCE_RULE_ID"
else
    yellow "Could not extract source_down rule ID, skipping source_down cleanup"
fi

# List alert rules — should include our rule
BODY=$(curl -s -b "$COOKIES" "$BASE/api/v2/alerts/rules")
check_contains "Alert rules list contains smoke-test-rule" "smoke-test-rule" "$BODY"
check_contains "Alert rules list contains source-down-smoke" "source-down-smoke" "$BODY"
check_contains "Alert rules list shows AD TLS" "AD TLS" "$BODY"

# Update the source_down rule
if [ -n "$SOURCE_RULE_ID" ]; then
    BODY=$(curl -s -w "\n%{http_code}" -b "$COOKIES" \
        -X PUT "$BASE/api/v2/alerts/rules/$SOURCE_RULE_ID" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: $CSRF" \
        -d '{"conditions":"{\"source\":\"DHCP TLS\",\"silence_seconds\":600}"}')
    SOURCE_UPDATE_STATUS=$(printf '%s\n' "$BODY" | awk 'END { print }')
    SOURCE_UPDATE_BODY=$(printf '%s\n' "$BODY" | sed '$d')
    check "Update source_down alert rule" "200" "$SOURCE_UPDATE_STATUS"
    check_contains "source_down update includes DHCP TLS" "DHCP TLS" "$SOURCE_UPDATE_BODY"
    check_contains "source_down update includes 600 seconds" "600" "$SOURCE_UPDATE_BODY"
fi

# Check alert stats endpoint
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/alerts/stats")
check "GET /api/v2/alerts/stats" "200" "$STATUS"

# Verify conflict stats shape
BODY=$(curl -s -b "$COOKIES" "$BASE/api/v2/conflicts/stats")
check_contains "Conflict stats has total_unresolved" '"total_unresolved"' "$BODY"
check_contains "Conflict stats has by_type" '"by_type"' "$BODY"
check_contains "Conflict stats has by_severity" '"by_severity"' "$BODY"

# If there are conflicts, test resolve flow
CONFLICTS=$(curl -s -b "$COOKIES" "$BASE/api/v2/conflicts?limit=1")
CONFLICT_ID=$(echo "$CONFLICTS" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*' || true)
if [ -n "$CONFLICT_ID" ]; then
    CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" \
        -X POST "$BASE/api/v2/conflicts/$CONFLICT_ID/resolve" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: $CSRF" \
        -d '{"note":"resolved by smoke test"}')
    check "Resolve conflict $CONFLICT_ID" "200" "$STATUS"
else
    yellow "No conflicts to resolve (skip)"
    SKIP=$((SKIP + 1))
fi

# Cleanup: delete the smoke-test rule
if [ -n "$RULE_ID" ]; then
    CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" \
        -X DELETE "$BASE/api/v2/alerts/rules/$RULE_ID" \
        -H "X-CSRF-Token: $CSRF")
    check "Delete alert rule $RULE_ID" "204" "$STATUS"
fi
if [ -n "$SOURCE_RULE_ID" ]; then
    CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" \
        -X DELETE "$BASE/api/v2/alerts/rules/$SOURCE_RULE_ID" \
        -H "X-CSRF-Token: $CSRF")
    check "Delete source_down alert rule $SOURCE_RULE_ID" "204" "$STATUS"
fi

# ── Section 4: Export Compliance ──
echo
echo "--- Export Compliance ---"

# JSON export
HEADERS=$(curl -s -D - -o /dev/null -b "$COOKIES" "$BASE/api/v2/export/mappings?format=json")
check_contains "JSON export Content-Disposition" "attachment" "$HEADERS"
check_contains "JSON export filename .json" ".json" "$HEADERS"

# CSV export
BODY=$(curl -s -b "$COOKIES" "$BASE/api/v2/export/mappings?format=csv")
HEADER_LINE=$(echo "$BODY" | head -1)
check_contains "CSV header has ip column" "ip" "$HEADER_LINE"
check_contains "CSV header has source column" "source" "$HEADER_LINE"
check_contains "CSV header has current_users" "current_users" "$HEADER_LINE"

# Invalid format → 400
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/export/mappings?format=xml")
check "Export XML rejected" "400" "$STATUS"

# ── Section 4: Input Validation ──
echo
echo "--- Input Validation ---"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/search?scope=invalid")
check "Invalid scope rejected" "400" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/v2/search?from=not-a-date")
check "Invalid datetime rejected" "400" "$STATUS"

# ── Section 5: Auth Lifecycle ──
echo
echo "--- Auth Lifecycle ---"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" -c "$COOKIES" \
    -X POST -H "X-CSRF-Token: $CSRF" "$BASE/api/auth/refresh")
check "Token refresh" "200" "$STATUS"

CSRF=$(grep trueid_csrf_token "$COOKIES" 2>/dev/null | awk '{print $NF}')

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" -c "$COOKIES" \
    -X POST -H "X-CSRF-Token: $CSRF" "$BASE/api/auth/logout")
check "Logout" "200" "$STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE/api/auth/me")
check "GET /me after logout → 401" "401" "$STATUS"

# ── Results ──
echo
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
