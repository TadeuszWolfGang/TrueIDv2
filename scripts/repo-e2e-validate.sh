#!/usr/bin/env bash
# repo-e2e-validate.sh — validates the local TrueID data path through import → mapping → lookup → timeline.
#
# Usage:
#   TRUEID_VALIDATE_ADMIN_PASS=... ./scripts/repo-e2e-validate.sh [base_url]
#
# Default base_url: http://127.0.0.1:3000
#
# Required env:
#   TRUEID_VALIDATE_ADMIN_PASS
#
# Optional env:
#   TRUEID_VALIDATE_ADMIN_USER   default: admin
#   TRUEID_VALIDATE_PYTHON_BIN   default: python3
#   TRUEID_VALIDATE_IP           default: randomized TEST-NET-2 address
#   TRUEID_VALIDATE_USER         default: e2e.smoke
#   TRUEID_VALIDATE_MAC          default: randomized locally-administered MAC

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${ROOT_DIR}/validation-reports/repo-e2e-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${REPORT_DIR}"

BASE="${1:-${TRUEID_VALIDATE_BASE_URL:-http://127.0.0.1:3000}}"
ADMIN_USER="${TRUEID_VALIDATE_ADMIN_USER:-${TRUEID_SMOKE_ADMIN_USER:-admin}}"
ADMIN_PASS="${TRUEID_VALIDATE_ADMIN_PASS:-${TRUEID_SMOKE_ADMIN_PASS:-}}"
PYTHON_BIN="${TRUEID_VALIDATE_PYTHON_BIN:-python3}"
SAMPLE_USER="${TRUEID_VALIDATE_USER:-e2e.smoke}"
SAMPLE_IP="${TRUEID_VALIDATE_IP:-198.51.100.$(( (RANDOM % 200) + 10 ))}"
SAMPLE_MAC="${TRUEID_VALIDATE_MAC:-02:54:00:$(printf '%02x:%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))}"

if [ -z "${ADMIN_PASS}" ]; then
    echo "Set TRUEID_VALIDATE_ADMIN_PASS before running repo-e2e-validate.sh" >&2
    exit 1
fi

PASS=0
FAIL=0
COOKIES="$(mktemp)"
trap 'rm -f "${COOKIES}"' EXIT

green() { printf "\033[32m✓ %s\033[0m\n" "$1"; PASS=$((PASS + 1)); }
red() { printf "\033[31m✗ %s\033[0m\n" "$1"; FAIL=$((FAIL + 1)); }
info() { printf "\n\033[36m== %s ==\033[0m\n" "$1"; }

curl_status() {
    curl -sS -o /dev/null -w "%{http_code}" "$@"
}

csrf_from_cookie() {
    grep trueid_csrf_token "${COOKIES}" 2>/dev/null | awk '{print $NF}'
}

info "Health and authentication"
STATUS="$(curl_status "${BASE}/health")"
if [ "${STATUS}" = "200" ]; then
    green "Health endpoint responds"
else
    red "Health endpoint failed with HTTP ${STATUS}"
fi

STATUS="$(curl -sS -o /dev/null -w "%{http_code}" -c "${COOKIES}" \
    -X POST "${BASE}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")"
if [ "${STATUS}" = "200" ]; then
    green "Login as ${ADMIN_USER} succeeded"
else
    red "Login failed with HTTP ${STATUS}"
fi

STATUS="$(curl_status -b "${COOKIES}" "${BASE}/api/auth/me")"
if [ "${STATUS}" = "200" ]; then
    green "Authenticated /api/auth/me succeeded"
else
    red "Authenticated /api/auth/me failed with HTTP ${STATUS}"
fi

info "Synthetic import"
IMPORT_PAYLOAD="${REPORT_DIR}/import-events.json"
SAMPLE_USER="${SAMPLE_USER}" SAMPLE_IP="${SAMPLE_IP}" SAMPLE_MAC="${SAMPLE_MAC}" "${PYTHON_BIN}" - <<'PY' > "${IMPORT_PAYLOAD}"
import json
import os
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)
rows = []
for idx in range(3):
    rows.append({
        "ip": os.environ["SAMPLE_IP"],
        "user": os.environ["SAMPLE_USER"],
        "mac": os.environ["SAMPLE_MAC"],
        "source": "Manual" if idx < 2 else "AdLog",
        "timestamp": (now - timedelta(seconds=(30 - idx * 10))).isoformat(),
    })

print(json.dumps({"events": rows}))
PY

IMPORT_BODY="${REPORT_DIR}/import-response.json"
IMPORT_STATUS="$(curl -sS -w "%{http_code}" -o "${IMPORT_BODY}" \
    -b "${COOKIES}" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $(csrf_from_cookie)" \
    -X POST "${BASE}/api/v2/import/events" \
    --data-binary "@${IMPORT_PAYLOAD}")"
if [ "${IMPORT_STATUS}" = "200" ] && \
    IMPORT_BODY="${IMPORT_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["IMPORT_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

if body.get("imported") == 3 and body.get("skipped") == 0:
    sys.exit(0)

sys.exit(1)
PY
then
    green "Synthetic events imported successfully"
else
    red "Synthetic event import failed"
fi

info "Mapping and lookup validation"
MAPPINGS_BODY="${REPORT_DIR}/mappings.json"
MAPPINGS_STATUS="$(curl -sS -w "%{http_code}" -o "${MAPPINGS_BODY}" \
    -b "${COOKIES}" \
    "${BASE}/api/v1/mappings?search=${SAMPLE_IP}")"
if [ "${MAPPINGS_STATUS}" = "200" ] && \
    SAMPLE_IP="${SAMPLE_IP}" SAMPLE_USER="${SAMPLE_USER}" MAPPINGS_BODY="${MAPPINGS_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["MAPPINGS_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

rows = body.get("data", body if isinstance(body, list) else [])
for row in rows:
    if row.get("ip") != os.environ["SAMPLE_IP"]:
        continue
    users = row.get("current_users") or []
    if not isinstance(users, list):
        users = [users]
    if os.environ["SAMPLE_USER"] in {str(v).strip() for v in users if str(v).strip()}:
        sys.exit(0)

sys.exit(1)
PY
then
    green "Mappings API includes synthetic IP and user"
else
    red "Mappings API validation failed"
fi

LOOKUP_BODY="${REPORT_DIR}/lookup.json"
LOOKUP_STATUS="$(curl -sS -w "%{http_code}" -o "${LOOKUP_BODY}" \
    -b "${COOKIES}" \
    "${BASE}/lookup/${SAMPLE_IP}")"
if [ "${LOOKUP_STATUS}" = "200" ] && \
    SAMPLE_IP="${SAMPLE_IP}" SAMPLE_USER="${SAMPLE_USER}" LOOKUP_BODY="${LOOKUP_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["LOOKUP_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

mapping = body.get("mapping") or {}
recent = body.get("recent_events") or []

if mapping.get("ip") != os.environ["SAMPLE_IP"]:
    sys.exit(1)

users = mapping.get("current_users") or []
if not isinstance(users, list):
    users = [users]
normalized = {str(v).strip() for v in users if str(v).strip()}
if os.environ["SAMPLE_USER"] not in normalized:
    sys.exit(1)

if not any(event.get("user") == os.environ["SAMPLE_USER"] for event in recent):
    sys.exit(1)

sys.exit(0)
PY
then
    green "Lookup endpoint resolves the synthetic mapping"
else
    red "Lookup endpoint validation failed"
fi

info "Timeline validation"
TIMELINE_IP_BODY="${REPORT_DIR}/timeline-ip-page1.json"
TIMELINE_IP_STATUS="$(curl -sS -w "%{http_code}" -o "${TIMELINE_IP_BODY}" \
    -b "${COOKIES}" \
    "${BASE}/api/v2/timeline/ip/${SAMPLE_IP}?limit=2")"
if [ "${TIMELINE_IP_STATUS}" = "200" ] && \
    SAMPLE_USER="${SAMPLE_USER}" TIMELINE_IP_BODY="${TIMELINE_IP_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["TIMELINE_IP_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

events = body.get("events", {}).get("data", [])
user_changes = body.get("user_changes")
if len(events) < 2:
    sys.exit(1)
if not all(event.get("user") == os.environ["SAMPLE_USER"] for event in events):
    sys.exit(1)
if not body.get("events", {}).get("next_cursor"):
    sys.exit(1)
if user_changes != []:
    sys.exit(1)
sys.exit(0)
PY
then
    green "IP timeline page 1 returns events, next_cursor and no synthetic user_changes"
else
    red "IP timeline page 1 validation failed"
fi

TIMELINE_IP_PAGE2="${REPORT_DIR}/timeline-ip-page2.json"
if TIMELINE_IP_BODY="${TIMELINE_IP_BODY}" "${PYTHON_BIN}" - <<'PY' > "${REPORT_DIR}/timeline-ip-cursor.txt"
import json
import os

with open(os.environ["TIMELINE_IP_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

print(body.get("events", {}).get("next_cursor", ""))
PY
then
    NEXT_CURSOR="$(cat "${REPORT_DIR}/timeline-ip-cursor.txt")"
    if [ -n "${NEXT_CURSOR}" ]; then
        ENCODED_CURSOR="$(NEXT_CURSOR="${NEXT_CURSOR}" "${PYTHON_BIN}" - <<'PY'
import os
import urllib.parse
print(urllib.parse.quote(os.environ["NEXT_CURSOR"], safe=""))
PY
)"
        TIMELINE_IP_STATUS_2="$(curl -sS -w "%{http_code}" -o "${TIMELINE_IP_PAGE2}" \
            -b "${COOKIES}" \
            "${BASE}/api/v2/timeline/ip/${SAMPLE_IP}?limit=2&cursor=${ENCODED_CURSOR}")"
        if [ "${TIMELINE_IP_STATUS_2}" = "200" ] && \
            TIMELINE_IP_BODY="${TIMELINE_IP_BODY}" TIMELINE_IP_PAGE2="${TIMELINE_IP_PAGE2}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["TIMELINE_IP_BODY"], "r", encoding="utf-8") as fh:
    first = json.load(fh)
with open(os.environ["TIMELINE_IP_PAGE2"], "r", encoding="utf-8") as fh:
    second = json.load(fh)

first_ids = {row.get("id") for row in first.get("events", {}).get("data", [])}
second_ids = {row.get("id") for row in second.get("events", {}).get("data", [])}

if first_ids and second_ids and first_ids.isdisjoint(second_ids):
    sys.exit(0)
sys.exit(1)
PY
        then
            green "IP timeline cursor page 2 returns a disjoint page"
        else
            red "IP timeline cursor page 2 validation failed"
        fi
    else
        red "IP timeline did not expose a cursor for page 2"
    fi
else
    red "IP timeline cursor extraction failed"
fi

TIMELINE_USER_BODY="${REPORT_DIR}/timeline-user.json"
TIMELINE_USER_STATUS="$(curl -sS -w "%{http_code}" -o "${TIMELINE_USER_BODY}" \
    -b "${COOKIES}" \
    "${BASE}/api/v2/timeline/user/${SAMPLE_USER}?limit=2")"
if [ "${TIMELINE_USER_STATUS}" = "200" ] && \
    SAMPLE_IP="${SAMPLE_IP}" TIMELINE_USER_BODY="${TIMELINE_USER_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["TIMELINE_USER_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

events = body.get("events", {}).get("data", [])
ips = set(body.get("ip_addresses_used") or [])
active = body.get("active_mappings") or []
if len(events) < 2:
    sys.exit(1)
if ips != {os.environ["SAMPLE_IP"]}:
    sys.exit(1)
if not any(row.get("ip") == os.environ["SAMPLE_IP"] for row in active):
    sys.exit(1)
sys.exit(0)
PY
then
    green "User timeline exposes recent events, exact IP history and active mapping"
else
    red "User timeline validation failed"
fi

TIMELINE_MAC_BODY="${REPORT_DIR}/timeline-mac.json"
TIMELINE_MAC_STATUS="$(curl -sS -w "%{http_code}" -o "${TIMELINE_MAC_BODY}" \
    -b "${COOKIES}" \
    "${BASE}/api/v2/timeline/mac/${SAMPLE_MAC}?limit=1")"
if [ "${TIMELINE_MAC_STATUS}" = "200" ] && \
    SAMPLE_IP="${SAMPLE_IP}" TIMELINE_MAC_BODY="${TIMELINE_MAC_BODY}" "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["TIMELINE_MAC_BODY"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

rows = body.get("current_mappings") or []
history = set(body.get("ip_history") or [])

if not rows:
    sys.exit(1)
if rows[0].get("ip") != os.environ["SAMPLE_IP"]:
    sys.exit(1)
if os.environ["SAMPLE_IP"] not in history:
    sys.exit(1)
sys.exit(0)
PY
then
    green "MAC timeline resolves current mapping and IP history"
else
    red "MAC timeline validation failed"
fi

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
