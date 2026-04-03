#!/usr/bin/env bash
# compose-e2e-validate.sh — builds and validates the Docker Compose stack end-to-end.
#
# Usage:
#   ./scripts/compose-e2e-validate.sh
#
# Optional env:
#   TRUEID_E2E_WEB_PORT        default: 3000
#   TRUEID_E2E_ADMIN_USER      default: admin
#   TRUEID_E2E_ADMIN_PASS      default: generated per run
#   TRUEID_E2E_METRICS_TOKEN   default: generated per run
#   TRUEID_E2E_KEEP_STACK      default: false
#   TRUEID_E2E_BUILD           default: true
#   DOCKER_COMPOSE_CMD         default: docker compose

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${ROOT_DIR}/validation-reports/compose-e2e-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${REPORT_DIR}"

COMPOSE_CMD="${DOCKER_COMPOSE_CMD:-docker compose}"
WEB_PORT="${TRUEID_E2E_WEB_PORT:-3000}"
BASE_URL="http://127.0.0.1:${WEB_PORT}"
ADMIN_USER="${TRUEID_E2E_ADMIN_USER:-admin}"
PYTHON_BIN="${TRUEID_E2E_PYTHON_BIN:-python3}"
KEEP_STACK="${TRUEID_E2E_KEEP_STACK:-false}"
BUILD_STACK="${TRUEID_E2E_BUILD:-true}"

random_secret() {
    "${PYTHON_BIN}" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

export JWT_SECRET="${JWT_SECRET:-$(random_secret)}"
export ENGINE_SERVICE_TOKEN="${ENGINE_SERVICE_TOKEN:-$(random_secret)}"
export CONFIG_ENCRYPTION_KEY="${CONFIG_ENCRYPTION_KEY:-$(random_secret)}"
export RADIUS_SECRET="${RADIUS_SECRET:-$(random_secret)}"
export TRUEID_ADMIN_USER="${TRUEID_ADMIN_USER:-${ADMIN_USER}}"
export TRUEID_ADMIN_PASS="${TRUEID_ADMIN_PASS:-${TRUEID_E2E_ADMIN_PASS:-$(random_secret)}}"
export TRUEID_DEV_MODE="${TRUEID_DEV_MODE:-false}"
export METRICS_TOKEN="${METRICS_TOKEN:-${TRUEID_E2E_METRICS_TOKEN:-$(random_secret)}}"
export WEB_PORT

cleanup() {
    if [ "${KEEP_STACK}" != "true" ]; then
        ${COMPOSE_CMD} down -v > "${REPORT_DIR}/docker-compose-down.log" 2>&1 || true
    fi
}
trap cleanup EXIT

PASS=0
FAIL=0
BOOTSTRAP_OK=1
green() { printf "\033[32m✓ %s\033[0m\n" "$1"; PASS=$((PASS + 1)); }
red() { printf "\033[31m✗ %s\033[0m\n" "$1"; FAIL=$((FAIL + 1)); }
info() { printf "\n\033[36m== %s ==\033[0m\n" "$1"; }

info "Docker Compose bootstrap"
if [ "${BUILD_STACK}" = "true" ]; then
    if ${COMPOSE_CMD} up -d --build > "${REPORT_DIR}/docker-compose-up.log" 2>&1; then
        green "Docker Compose stack started"
    else
        BOOTSTRAP_OK=0
        red "Docker Compose bootstrap failed"
    fi
else
    if ${COMPOSE_CMD} up -d > "${REPORT_DIR}/docker-compose-up.log" 2>&1; then
        green "Docker Compose stack started"
    else
        BOOTSTRAP_OK=0
        red "Docker Compose bootstrap failed"
    fi
fi

if [ "${BOOTSTRAP_OK}" = "1" ]; then
    info "Wait for web health"
    HEALTH_OK=0
    for _ in $(seq 1 60); do
        if curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/health" 2>/dev/null | grep -q '^200$'; then
            HEALTH_OK=1
            break
        fi
        sleep 2
    done

    if [ "${HEALTH_OK}" = "1" ]; then
        green "Web health endpoint is ready"
    else
        red "Web health endpoint did not become ready"
    fi

    if [ "${HEALTH_OK}" = "1" ]; then
        info "Basic smoke"
        if TRUEID_SMOKE_ADMIN_USER="${TRUEID_ADMIN_USER}" \
           TRUEID_SMOKE_ADMIN_PASS="${TRUEID_ADMIN_PASS}" \
           ./scripts/smoke-test.sh "${BASE_URL}" \
           > "${REPORT_DIR}/smoke-test.log" 2>&1; then
            green "Basic smoke-test.sh passed"
        else
            red "Basic smoke-test.sh failed"
        fi

        info "Data-path validation"
        if TRUEID_VALIDATE_ADMIN_USER="${TRUEID_ADMIN_USER}" \
           TRUEID_VALIDATE_ADMIN_PASS="${TRUEID_ADMIN_PASS}" \
           TRUEID_VALIDATE_PYTHON_BIN="${PYTHON_BIN}" \
           ./scripts/repo-e2e-validate.sh "${BASE_URL}" \
           > "${REPORT_DIR}/repo-e2e-validate.log" 2>&1; then
            green "repo-e2e-validate.sh passed"
        else
            red "repo-e2e-validate.sh failed"
        fi

        info "Metrics access"
        METRICS_ANON="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/metrics" || true)"
        if [ "${METRICS_ANON}" = "401" ]; then
            green "/metrics rejects anonymous access"
        else
            red "/metrics anonymous access returned HTTP ${METRICS_ANON}"
        fi

        METRICS_AUTH="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/metrics?token=${METRICS_TOKEN}" || true)"
        if [ "${METRICS_AUTH}" = "200" ]; then
            green "/metrics accepts static token"
        else
            red "/metrics token access returned HTTP ${METRICS_AUTH}"
        fi
    fi
fi

${COMPOSE_CMD} ps > "${REPORT_DIR}/docker-compose-ps.txt" 2>&1 || true
${COMPOSE_CMD} logs > "${REPORT_DIR}/docker-compose-logs.txt" 2>&1 || true

echo
echo "Reports saved in: ${REPORT_DIR}"
echo "Result: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
