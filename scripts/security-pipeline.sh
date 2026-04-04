#!/usr/bin/env bash
# security-pipeline.sh — 3-layer security pipeline for TrueID.
#
# Layers:
# 1) SAST/SCA (cargo audit + cargo deny advisories)
# 2) Container scan (Trivy for engine + web images)
# 3) DAST (ZAP baseline + Nuclei + TrueID-specific runtime checks)
#
# Usage:
#   ./scripts/security-pipeline.sh
#
# Optional env:
#   TRUEID_GITLEAKS_HISTORY_SCAN=true  Scan full git history locally (CI-equivalent).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0
FAIL=0
WARN=0
REPORT_DIR="${ROOT_DIR}/security-reports"
VENV_DIR="${ROOT_DIR}/.venv-security"
SCHEMATHESIS_BIN=""
rm -rf "$REPORT_DIR" "${ROOT_DIR}/.hypothesis"
mkdir -p "$REPORT_DIR"

green() { printf "\033[32m✓ %s\033[0m\n" "$1"; PASS=$((PASS + 1)); }
red() { printf "\033[31m✗ %s\033[0m\n" "$1"; FAIL=$((FAIL + 1)); }
yellow() { printf "\033[33m! %s\033[0m\n" "$1"; WARN=$((WARN + 1)); }
info() { printf "\n\033[36m== %s ==\033[0m\n" "$1"; }

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd"
        exit 1
    fi
}

run_and_check() {
    local desc="$1"
    shift
    if "$@"; then
        green "$desc"
    else
        red "$desc"
    fi
}

run_advisory_check() {
    local desc="$1"
    shift
    if "$@"; then
        green "$desc"
    else
        yellow "$desc (advisory)"
    fi
}

cleanup() {
    docker compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

gen_hex_secret() {
    openssl rand -hex 32
}

gen_password() {
    python3 - <<'PY'
import secrets
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*_-+="
print("".join(secrets.choice(alphabet) for _ in range(24)))
PY
}

run_schemathesis_targeted() {
    local output_path="$1"
    "$SCHEMATHESIS_BIN" run docs/openapi.yaml \
      --url http://127.0.0.1:3000 \
      -H "X-API-Key: ${schemathesis_api_key}" \
      --phases examples,coverage,fuzzing \
      --checks not_a_server_error,status_code_conformance \
      --include-path /lookup/{ip} \
      --include-path /api/v1/mappings \
      --include-path /api/v2/timeline/ip/{ip} \
      --include-path /api/v2/timeline/user/{user} \
      --include-path /api/v2/timeline/mac/{mac} \
      --max-examples 25 \
      --report-junit-path "${REPORT_DIR}/schemathesis-junit.xml" \
      2>&1 | tee "${output_path}"
    grep -Eq 'Operations:[[:space:]]+5 selected /' "${output_path}"
}

info "Dependency setup"
require_cmd docker
require_cmd cargo
require_cmd python3
docker pull ghcr.io/zaproxy/zaproxy:stable >/dev/null
docker pull aquasec/trivy:0.57.1 >/dev/null
docker pull projectdiscovery/nuclei:latest >/dev/null
docker pull instrumentisto/nmap:latest >/dev/null
docker pull ghcr.io/gitleaks/gitleaks:v8.30.0 >/dev/null
python3 -m venv "$VENV_DIR"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/python" -m pip install schemathesis >/dev/null
SCHEMATHESIS_BIN="${VENV_DIR}/bin/schemathesis"
green "Security tooling images pulled"

info "SAST + SCA"
cargo install cargo-audit --locked >/dev/null
cargo install cargo-deny --locked >/dev/null
GITLEAKS_ARGS=()
if [ "${TRUEID_GITLEAKS_HISTORY_SCAN:-false}" != "true" ]; then
    GITLEAKS_ARGS+=(--no-git)
    echo "Note: local Gitleaks defaults to working-tree scan only; set TRUEID_GITLEAKS_HISTORY_SCAN=true to scan full git history like CI."
fi
run_and_check "gitleaks secret scan" \
  docker run --rm -v "${ROOT_DIR}:/repo" ghcr.io/gitleaks/gitleaks:v8.30.0 detect \
  "${GITLEAKS_ARGS[@]}" \
  --source /repo \
  --report-format sarif \
  --report-path /repo/security-reports/gitleaks.sarif \
  --redact \
  --exit-code 1
run_and_check "cargo fmt check" cargo fmt --all -- --check
run_and_check "cargo clippy (security-focused lints)" \
  cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
run_and_check "cargo audit" cargo audit --ignore RUSTSEC-2023-0071
run_and_check "cargo deny advisories" cargo deny check advisories

info "Start application (prod-like)"
export TRUEID_DEV_MODE=false
export JWT_SECRET="${JWT_SECRET:-$(gen_hex_secret)}"
export ENGINE_SERVICE_TOKEN="${ENGINE_SERVICE_TOKEN:-$(gen_hex_secret)}"
export CONFIG_ENCRYPTION_KEY="${CONFIG_ENCRYPTION_KEY:-$(gen_hex_secret)}"
export RADIUS_SECRET="${RADIUS_SECRET:-$(gen_hex_secret)}"
export TRUEID_ADMIN_USER="${TRUEID_ADMIN_USER:-admin}"
export TRUEID_ADMIN_PASS="${TRUEID_ADMIN_PASS:-$(gen_password)}"
export METRICS_TOKEN="${METRICS_TOKEN:-$(gen_hex_secret)}"
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build

ready=0
for _ in $(seq 1 20); do
    if docker compose ps | grep -q "engine.*healthy" && docker compose ps | grep -q "web.*healthy"; then
        ready=1
        break
    fi
    sleep 3
done
if [ "$ready" -eq 1 ]; then
    green "engine healthy"
    green "web healthy"
else
    red "services did not become healthy in time"
    docker compose ps || true
fi

info "Container scan (Trivy)"
run_and_check "trivy engine image (HIGH/CRITICAL)" \
  docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${ROOT_DIR}/.trivyignore:/work/.trivyignore:ro" \
  aquasec/trivy:0.57.1 image \
  --severity HIGH,CRITICAL --ignorefile /work/.trivyignore --exit-code 1 trueidv2-engine:latest
run_and_check "trivy web image (HIGH/CRITICAL)" \
  docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${ROOT_DIR}/.trivyignore:/work/.trivyignore:ro" \
  aquasec/trivy:0.57.1 image \
  --severity HIGH,CRITICAL --ignorefile /work/.trivyignore --exit-code 1 trueidv2-web:latest

info "DAST + service checks"
if curl -sS --max-time 1 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    red "engine admin port 8080 must not be published"
else
    green "engine admin port 8080 is not publicly published"
fi

if docker compose port engine 8080 >/dev/null 2>&1; then
    red "engine admin port 8080 is published by Docker Compose"
else
    green "engine admin port 8080 is not published by Docker Compose"
fi

web_cid="$(docker compose ps -q web)"
if [ -n "${web_cid}" ] && docker inspect "${web_cid}" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -qx 'TRUEID_DEV_MODE=false'; then
    green "TRUEID_DEV_MODE is false in web container"
else
    red "TRUEID_DEV_MODE is not false in web container"
fi

run_and_check "unauthenticated /api/v1/mappings returns 401" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/v1/mappings)" = "401" ]'
run_and_check "unauthenticated /api/v1/users returns 401" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/v1/users)" = "401" ]'
run_and_check "unauthenticated /metrics returns 401" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/metrics)" = "401" ]'
run_and_check "metrics token returns 200" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/metrics?token='"${METRICS_TOKEN}"'")" = "200" ]'
run_and_check "repo-e2e-validate.sh" \
  env TRUEID_VALIDATE_ADMIN_USER="${TRUEID_ADMIN_USER}" \
      TRUEID_VALIDATE_ADMIN_PASS="${TRUEID_ADMIN_PASS}" \
      TRUEID_VALIDATE_PYTHON_BIN=python3 \
      ./scripts/repo-e2e-validate.sh http://127.0.0.1:3000

rate_limit_seen=0
login_attack_ip="198.51.100.240"
login_attack_user="rate-limit-probe"
for _ in $(seq 1 15); do
    code="$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST http://localhost:3000/api/auth/login \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: ${login_attack_ip}" \
      -d "{\"username\":\"${login_attack_user}\",\"password\":\"wrong-password\"}")"
    if [ "$code" = "429" ]; then
        rate_limit_seen=1
        break
    fi
done
if [ "$rate_limit_seen" -eq 1 ]; then
    green "login brute-force protection produced HTTP 429"
else
    red "login brute-force protection did not produce HTTP 429"
fi

run_advisory_check "ZAP baseline scan" \
  docker run --rm --network host -v "${REPORT_DIR}:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -I -t http://127.0.0.1:3000 -r zap-report.html -J zap-report.json -m 5

rm -f "${REPORT_DIR}/nuclei-report.jsonl"
if docker run --rm --network host -v "${REPORT_DIR}:/reports:rw" projectdiscovery/nuclei:latest \
  -u http://127.0.0.1:3000 \
  -severity high,critical \
  -jsonl \
  -silent \
  -o /reports/nuclei-report.jsonl; then
    if [ -s "${REPORT_DIR}/nuclei-report.jsonl" ]; then
        red "Nuclei reported HIGH/CRITICAL findings"
    else
        green "Nuclei reported no HIGH/CRITICAL findings"
    fi
else
    red "Nuclei scan execution failed"
fi

run_and_check "open ports probe (3000)" \
  docker run --rm --network host instrumentisto/nmap:latest \
  -sV -sC -p 3000 127.0.0.1

curl -sSI http://localhost:3000 > "${REPORT_DIR}/headers.txt"
green "saved HTTP headers report to security-reports/headers.txt"

info "Create admin API key for Schemathesis"
rm -f /tmp/trueid-cookies.txt /tmp/trueid-login.json /tmp/trueid-api-key.json
schemathesis_login_ip="198.51.100.241"
login_status="$(curl -sS \
  -c /tmp/trueid-cookies.txt \
  -X POST http://127.0.0.1:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: ${schemathesis_login_ip}" \
  -d "{\"username\":\"${TRUEID_ADMIN_USER}\",\"password\":\"${TRUEID_ADMIN_PASS}\"}" \
  -o /tmp/trueid-login.json \
  -w "%{http_code}")"
if [ "${login_status}" != "200" ]; then
  red "Schemathesis login failed with HTTP ${login_status}"
  cat /tmp/trueid-login.json || true
  exit 1
fi

csrf_token="$(awk '$6 == "trueid_csrf_token" { print $7 }' /tmp/trueid-cookies.txt | tail -n 1)"
if [ -z "${csrf_token}" ]; then
  red "Schemathesis CSRF token was not issued"
  exit 1
fi

api_key_status="$(curl -sS \
  -b /tmp/trueid-cookies.txt \
  -X POST http://127.0.0.1:3000/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${csrf_token}" \
  -o /tmp/trueid-api-key.json \
  -w "%{http_code}" \
  -d '{"description":"schemathesis-local","role":"Admin","rate_limit_rpm":5000,"rate_limit_burst":1000}')"
if [ "${api_key_status}" != "201" ]; then
  red "Schemathesis API key creation failed with HTTP ${api_key_status}"
  cat /tmp/trueid-api-key.json || true
  exit 1
fi

schemathesis_api_key="$("${VENV_DIR}/bin/python" -c 'import json; print(json.load(open("/tmp/trueid-api-key.json"))["key"])')"
[ -n "${schemathesis_api_key}" ]
green "Schemathesis API key created"

run_and_check "Schemathesis API property fuzzing" \
  run_schemathesis_targeted "${REPORT_DIR}/schemathesis.txt"

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${WARN} warnings, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
