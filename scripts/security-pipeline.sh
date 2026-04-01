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

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0
FAIL=0
WARN=0
REPORT_DIR="${ROOT_DIR}/security-reports"
VENV_DIR="${ROOT_DIR}/.venv-security"
SCHEMATHESIS_BIN=""
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
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

info "Dependency setup"
require_cmd docker
require_cmd cargo
require_cmd python3
docker pull ghcr.io/zaproxy/zaproxy:stable >/dev/null
docker pull aquasec/trivy:0.57.1 >/dev/null
docker pull projectdiscovery/nuclei:latest >/dev/null
docker pull instrumentisto/nmap:latest >/dev/null
python3 -m venv "$VENV_DIR"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/python" -m pip install schemathesis >/dev/null
SCHEMATHESIS_BIN="${VENV_DIR}/bin/schemathesis"
green "Security tooling images pulled"

info "SAST + SCA"
cargo install cargo-audit --locked >/dev/null
cargo install cargo-deny --locked >/dev/null
run_advisory_check "cargo fmt check" cargo fmt --all -- --check
run_advisory_check "cargo clippy (security-focused lints)" \
  cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
run_advisory_check "cargo audit" cargo audit
run_advisory_check "cargo deny advisories" cargo deny check advisories

info "Start application (prod-like)"
export TRUEID_DEV_MODE=false
export JWT_SECRET="${JWT_SECRET:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export ENGINE_SERVICE_TOKEN="${ENGINE_SERVICE_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export CONFIG_ENCRYPTION_KEY="${CONFIG_ENCRYPTION_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export RADIUS_SECRET="${RADIUS_SECRET:-ci-radius-shared-secret}"
export TRUEID_ADMIN_PASS="${TRUEID_ADMIN_PASS:-integration12345}"
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
run_advisory_check "trivy engine image (HIGH/CRITICAL)" \
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 \
  image --severity HIGH,CRITICAL --ignorefile .trivyignore --exit-code 1 trueidv2-engine:latest
run_advisory_check "trivy web image (HIGH/CRITICAL)" \
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 \
  image --severity HIGH,CRITICAL --ignorefile .trivyignore --exit-code 1 trueidv2-web:latest

info "DAST + service checks"
if curl -sS --max-time 1 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    red "engine admin port 8080 must not be published"
else
    green "engine admin port 8080 is not publicly published"
fi

if [ "$(docker compose exec -T web printenv TRUEID_DEV_MODE)" = "false" ]; then
    green "TRUEID_DEV_MODE is false in web container"
else
    red "TRUEID_DEV_MODE is not false in web container"
fi

run_and_check "unauthenticated /api/v1/mappings returns 401" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/v1/mappings)" = "401" ]'
run_and_check "unauthenticated /api/v1/users returns 401" \
  bash -c '[ "$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/v1/users)" = "401" ]'

rate_limit_seen=0
for _ in $(seq 1 15); do
    code="$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST http://localhost:3000/api/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"wrong-password"}')"
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

run_and_check "Nuclei scan (low+ severities)" \
  docker run --rm --network host projectdiscovery/nuclei:latest \
  -u http://127.0.0.1:3000 -severity low,medium,high,critical \
  -o /tmp/nuclei-report.txt

run_and_check "open ports probe (3000,8080)" \
  docker run --rm --network host instrumentisto/nmap:latest \
  -sV -sC -p 3000,8080 localhost

curl -sSI http://localhost:3000 > "${REPORT_DIR}/headers.txt"
green "saved HTTP headers report to security-reports/headers.txt"

run_advisory_check "Schemathesis API property fuzzing" \
  "$SCHEMATHESIS_BIN" run docs/openapi.yaml \
  --url http://127.0.0.1:3000 \
  --max-examples 25 \
  --checks all \
  --report-junit-path "${REPORT_DIR}/schemathesis-junit.xml"

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${WARN} warnings, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
