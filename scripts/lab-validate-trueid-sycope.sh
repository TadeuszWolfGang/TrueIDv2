#!/usr/bin/env bash
# lab-validate-trueid-sycope.sh — validates the lab chain described in LAB_TEST_REPORT_2026-04-03.md
#
# Required env:
#   TRUEID_LAB_EXPECTED_IP
#   TRUEID_LAB_EXPECTED_USER
#   TRUEID_LAB_TRUEID_API_KEY
#
# Optional env:
#   TRUEID_LAB_TRUEID_URL       default: http://127.0.0.1:3000
#   TRUEID_LAB_DC_HOST          host alias for the Windows source (for SSH validation)
#   TRUEID_LAB_DC_SERVICE_NAME  default: TrueIDAgent
#   TRUEID_LAB_PYTHON_BIN       python interpreter with requests installed
#   TRUEID_LAB_TIMELINE_LIMIT    default: 10
#   TRUEID_LAB_SYCOPE_CONFIG    config.json path to reuse
#   TRUEID_LAB_SYCOPE_HOST
#   TRUEID_LAB_SYCOPE_LOGIN
#   TRUEID_LAB_SYCOPE_PASS
#   TRUEID_LAB_SYCOPE_LOOKUP    default: TrueID_Enrichment
#   TRUEID_LAB_SYCOPE_VALIDATE_QUERY  default: false
#   TRUEID_LAB_SYCOPE_QUERY_LOGIN     default: sycope_login
#   TRUEID_LAB_SYCOPE_QUERY_PASS      default: sycope_pass
#   TRUEID_LAB_SYCOPE_QUERY_STREAM    default: netflow
#   TRUEID_LAB_SYCOPE_QUERY_FROM      default: now-24h in UTC
#   TRUEID_LAB_SYCOPE_QUERY_TO        default: now in UTC

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${ROOT_DIR}/lab-reports"
mkdir -p "$REPORT_DIR"

EXPECTED_IP="${TRUEID_LAB_EXPECTED_IP:?Set TRUEID_LAB_EXPECTED_IP}"
EXPECTED_USER="${TRUEID_LAB_EXPECTED_USER:?Set TRUEID_LAB_EXPECTED_USER}"
TRUEID_URL="${TRUEID_LAB_TRUEID_URL:-http://127.0.0.1:3000}"
TRUEID_API_KEY="${TRUEID_LAB_TRUEID_API_KEY:?Set TRUEID_LAB_TRUEID_API_KEY}"
DC_HOST="${TRUEID_LAB_DC_HOST:-}"
DC_SERVICE_NAME="${TRUEID_LAB_DC_SERVICE_NAME:-TrueIDAgent}"
PYTHON_BIN="${TRUEID_LAB_PYTHON_BIN:-python3}"
TIMELINE_LIMIT="${TRUEID_LAB_TIMELINE_LIMIT:-10}"

PASS=0
FAIL=0

green() { printf "\033[32m✓ %s\033[0m\n" "$1"; PASS=$((PASS + 1)); }
red() { printf "\033[31m✗ %s\033[0m\n" "$1"; FAIL=$((FAIL + 1)); }
info() { printf "\n\033[36m== %s ==\033[0m\n" "$1"; }

info "TrueID mapping validation"
curl -sS \
  -H "X-API-Key: ${TRUEID_API_KEY}" \
  "${TRUEID_URL}/api/v1/mappings" > "${REPORT_DIR}/trueid-mappings.json"

if EXPECTED_IP="${EXPECTED_IP}" EXPECTED_USER="${EXPECTED_USER}" REPORT_FILE="${REPORT_DIR}/trueid-mappings.json" \
  "${PYTHON_BIN}" - <<'PY'
import ipaddress
import json
import os
import sys

with open(os.environ["REPORT_FILE"], "r", encoding="utf-8") as fh:
    payload = json.load(fh)

rows = payload.get("data", payload) if isinstance(payload, dict) else payload
expected_ip = os.environ["EXPECTED_IP"]
expected_user = os.environ["EXPECTED_USER"]

for row in rows:
    if row.get("ip") != expected_ip:
        continue
    users = row.get("current_users") or []
    if not isinstance(users, list):
        users = [users]
    fallback = row.get("user")
    if fallback:
        users.append(fallback)
    normalized = {str(user).strip() for user in users if str(user or "").strip()}
    if expected_user in normalized:
        sys.exit(0)

sys.exit(1)
PY
then
  green "TrueID mappings include ${EXPECTED_IP} -> ${EXPECTED_USER}"
else
  red "TrueID mappings do not include ${EXPECTED_IP} -> ${EXPECTED_USER}"
fi

info "TrueID lookup endpoint validation"
curl -sS \
  -H "X-API-Key: ${TRUEID_API_KEY}" \
  "${TRUEID_URL}/lookup/${EXPECTED_IP}" > "${REPORT_DIR}/trueid-lookup.json"

if EXPECTED_IP="${EXPECTED_IP}" EXPECTED_USER="${EXPECTED_USER}" REPORT_FILE="${REPORT_DIR}/trueid-lookup.json" \
  "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["REPORT_FILE"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

mapping = body.get("mapping") or {}
recent_events = body.get("recent_events") or []
expected_ip = os.environ["EXPECTED_IP"]
expected_user = os.environ["EXPECTED_USER"]

if mapping.get("ip") != expected_ip:
    sys.exit(1)

users = mapping.get("current_users") or []
if not isinstance(users, list):
    users = [users]
users.append(mapping.get("user"))
normalized = {str(user).strip() for user in users if str(user or "").strip()}
if expected_user not in normalized:
    sys.exit(1)

if not any(event.get("user") == expected_user for event in recent_events):
    sys.exit(1)

sys.exit(0)
PY
then
  green "TrueID lookup endpoint resolves ${EXPECTED_IP} -> ${EXPECTED_USER}"
else
  red "TrueID lookup endpoint does not resolve ${EXPECTED_IP} -> ${EXPECTED_USER}"
fi

info "TrueID timeline validation"
curl -sS \
  -H "X-API-Key: ${TRUEID_API_KEY}" \
  "${TRUEID_URL}/api/v2/timeline/ip/${EXPECTED_IP}?limit=${TIMELINE_LIMIT}" \
  > "${REPORT_DIR}/trueid-timeline-ip.json"

if EXPECTED_IP="${EXPECTED_IP}" EXPECTED_USER="${EXPECTED_USER}" REPORT_FILE="${REPORT_DIR}/trueid-timeline-ip.json" \
  "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys

with open(os.environ["REPORT_FILE"], "r", encoding="utf-8") as fh:
    body = json.load(fh)

expected_ip = os.environ["EXPECTED_IP"]
expected_user = os.environ["EXPECTED_USER"]

if body.get("ip") != expected_ip:
    sys.exit(1)

events = body.get("events", {}).get("data", [])
if not events:
    sys.exit(1)

if not any(event.get("user") == expected_user for event in events):
    sys.exit(1)

sys.exit(0)
PY
then
  green "TrueID IP timeline contains events for ${EXPECTED_USER}"
else
  red "TrueID IP timeline does not contain events for ${EXPECTED_USER}"
fi

if [ -n "${DC_HOST}" ]; then
  info "Windows service validation on ${DC_HOST}"
  if ssh "${DC_HOST}" "powershell -NoProfile -Command \"\$svc = Get-CimInstance Win32_Service -Filter \\\"Name='${DC_SERVICE_NAME}'\\\"; if (-not \$svc) { exit 1 }; \$svc | Select-Object Name,State,StartMode,PathName | ConvertTo-Json -Compress; \$conn = Get-NetTCPConnection -State Established | Where-Object { \$_.RemotePort -eq 5615 -or \$_.RemotePort -eq 5617 } | Select-Object -First 1 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess; if (\$conn) { \$conn | ConvertTo-Json -Compress } else { exit 2 }\"" \
    > "${REPORT_DIR}/windows-agent-status.jsonl"; then
    green "Windows service is running and has an established TLS session"
  else
    red "Windows service validation failed on ${DC_HOST}"
  fi
fi

if [ -n "${TRUEID_LAB_SYCOPE_CONFIG:-}" ] || [ -n "${TRUEID_LAB_SYCOPE_HOST:-}" ]; then
  info "Sycope lookup validation"
  if ROOT_DIR="${ROOT_DIR}" \
    EXPECTED_IP="${EXPECTED_IP}" \
    EXPECTED_USER="${EXPECTED_USER}" \
    TRUEID_LAB_SYCOPE_CONFIG="${TRUEID_LAB_SYCOPE_CONFIG:-}" \
    TRUEID_LAB_SYCOPE_HOST="${TRUEID_LAB_SYCOPE_HOST:-}" \
    TRUEID_LAB_SYCOPE_LOGIN="${TRUEID_LAB_SYCOPE_LOGIN:-}" \
    TRUEID_LAB_SYCOPE_PASS="${TRUEID_LAB_SYCOPE_PASS:-}" \
    TRUEID_LAB_SYCOPE_LOOKUP="${TRUEID_LAB_SYCOPE_LOOKUP:-TrueID_Enrichment}" \
    "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys
from pathlib import Path

try:
    import requests
except ImportError as exc:
    raise SystemExit(f"requests is required for Sycope lookup validation: {exc}")

repo_root = Path(os.environ["ROOT_DIR"])
sys.path.insert(0, str(repo_root))

from sycope.api import SycopeApi

cfg = {}
cfg_path = os.environ.get("TRUEID_LAB_SYCOPE_CONFIG")
if cfg_path:
    with open(cfg_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

host = os.environ.get("TRUEID_LAB_SYCOPE_HOST") or cfg.get("sycope_host")
login = os.environ.get("TRUEID_LAB_SYCOPE_LOGIN") or cfg.get("sycope_login")
password = os.environ.get("TRUEID_LAB_SYCOPE_PASS") or cfg.get("sycope_pass")
lookup_name = os.environ.get("TRUEID_LAB_SYCOPE_LOOKUP") or cfg.get("lookup_name") or "TrueID_Enrichment"
api_base = cfg.get("api_base", "/npm/api/v1/")

if not all([host, login, password]):
    raise SystemExit("Sycope host/login/pass are required")

with requests.Session() as session:
    api = SycopeApi(
        session=session,
        host=host,
        login=login,
        password=password,
        api_endpoint=api_base,
        api_endpoint_lookup="config-element-lookup/csvFile",
    )
    lookup_id, lookup = api.get_lookup(lookup_name, lookup_type="csvFile")
    if lookup_id == "0":
        raise SystemExit("Lookup not found")

rows = lookup.get("file", {}).get("rows", [])
expected_ip = os.environ["EXPECTED_IP"]
expected_user = os.environ["EXPECTED_USER"]

for row in rows:
    if len(row) >= 3 and row[0] == expected_ip and row[2] == expected_user:
        raise SystemExit(0)

raise SystemExit(1)
PY
  then
    green "Sycope lookup includes ${EXPECTED_IP} -> ${EXPECTED_USER}"
  else
    red "Sycope lookup does not include ${EXPECTED_IP} -> ${EXPECTED_USER}"
  fi

  if [ "${TRUEID_LAB_SYCOPE_VALIDATE_QUERY:-false}" = "true" ]; then
    info "Sycope query validation"
    if ROOT_DIR="${ROOT_DIR}" \
      EXPECTED_IP="${EXPECTED_IP}" \
      EXPECTED_USER="${EXPECTED_USER}" \
      TRUEID_LAB_SYCOPE_CONFIG="${TRUEID_LAB_SYCOPE_CONFIG:-}" \
      TRUEID_LAB_SYCOPE_HOST="${TRUEID_LAB_SYCOPE_HOST:-}" \
      TRUEID_LAB_SYCOPE_LOGIN="${TRUEID_LAB_SYCOPE_LOGIN:-}" \
      TRUEID_LAB_SYCOPE_PASS="${TRUEID_LAB_SYCOPE_PASS:-}" \
      TRUEID_LAB_SYCOPE_QUERY_LOGIN="${TRUEID_LAB_SYCOPE_QUERY_LOGIN:-}" \
      TRUEID_LAB_SYCOPE_QUERY_PASS="${TRUEID_LAB_SYCOPE_QUERY_PASS:-}" \
      TRUEID_LAB_SYCOPE_QUERY_STREAM="${TRUEID_LAB_SYCOPE_QUERY_STREAM:-netflow}" \
      TRUEID_LAB_SYCOPE_LOOKUP="${TRUEID_LAB_SYCOPE_LOOKUP:-TrueID_Enrichment}" \
      TRUEID_LAB_SYCOPE_QUERY_FROM="${TRUEID_LAB_SYCOPE_QUERY_FROM:-}" \
      TRUEID_LAB_SYCOPE_QUERY_TO="${TRUEID_LAB_SYCOPE_QUERY_TO:-}" \
      "${PYTHON_BIN}" - <<'PY'
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError as exc:
    raise SystemExit(f"requests is required for Sycope query validation: {exc}")

repo_root = Path(os.environ["ROOT_DIR"])
sys.path.insert(0, str(repo_root))

from sycope.api import SycopeApi

cfg = {}
cfg_path = os.environ.get("TRUEID_LAB_SYCOPE_CONFIG")
if cfg_path:
    with open(cfg_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

host = os.environ.get("TRUEID_LAB_SYCOPE_HOST") or cfg.get("sycope_host")
login = os.environ.get("TRUEID_LAB_SYCOPE_QUERY_LOGIN") or os.environ.get("TRUEID_LAB_SYCOPE_LOGIN") or cfg.get("sycope_login")
password = os.environ.get("TRUEID_LAB_SYCOPE_QUERY_PASS") or os.environ.get("TRUEID_LAB_SYCOPE_PASS") or cfg.get("sycope_pass")
lookup_name = os.environ.get("TRUEID_LAB_SYCOPE_LOOKUP") or cfg.get("lookup_name") or "TrueID_Enrichment"
stream_name = os.environ.get("TRUEID_LAB_SYCOPE_QUERY_STREAM") or "netflow"
api_base = cfg.get("api_base", "/npm/api/v1/")

if not all([host, login, password]):
    raise SystemExit("Sycope host/query login/query pass are required")

start_time = os.environ.get("TRUEID_LAB_SYCOPE_QUERY_FROM")
end_time = os.environ.get("TRUEID_LAB_SYCOPE_QUERY_TO")
if not start_time or not end_time:
    now = datetime.now(timezone.utc)
    start_time = f"@{(now - timedelta(hours=24)).isoformat()}"
    end_time = f"@{now.isoformat()}"

expected_ip = os.environ["EXPECTED_IP"]
expected_user = os.environ["EXPECTED_USER"]

try:
    ipaddress.ip_address(expected_ip)
except ValueError as exc:
    raise SystemExit(f"EXPECTED_IP is not a valid IP address: {exc}")

def nql_quote(value: str) -> str:
    if any(ord(ch) < 32 for ch in value):
        raise SystemExit("NQL validation values must not contain control characters")
    return value.replace("\\", "\\\\").replace("\"", "\\\"")

nql = (
    f'src stream="{nql_quote(stream_name)}" '
    f'| set clientUser=lookup("{nql_quote(lookup_name)}", "user", {{"ip": clientIp}}, default="") '
    f'| where clientIp = "{nql_quote(expected_ip)}" and clientUser = "{nql_quote(expected_user)}" '
    f'| sort timestamp desc'
)

with requests.Session() as session:
    api = SycopeApi(
        session=session,
        host=host,
        login=login,
        password=password,
        api_endpoint=api_base,
        api_endpoint_lookup="config-element-lookup/csvFile",
    )
    rows = api.query_all_results(nql, start_time, end_time, page_size=1000)

if rows:
    raise SystemExit(0)

raise SystemExit(1)
PY
    then
      green "Sycope NQL resolves ${EXPECTED_IP} -> ${EXPECTED_USER} in stream data"
    else
      red "Sycope NQL did not resolve ${EXPECTED_IP} -> ${EXPECTED_USER}"
    fi
  fi
fi

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
