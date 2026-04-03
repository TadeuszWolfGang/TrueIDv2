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
#   TRUEID_LAB_SYCOPE_CONFIG    config.json path to reuse
#   TRUEID_LAB_SYCOPE_HOST
#   TRUEID_LAB_SYCOPE_LOGIN
#   TRUEID_LAB_SYCOPE_PASS
#   TRUEID_LAB_SYCOPE_LOOKUP    default: TrueID_Enrichment

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
fi

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
