# HANDOFF — browser login compatibility

## Phase
POST-REALIZATION — native web deployed and browser acceptance passed. Full
local/live suites passed; hosted checks are running on draft PR #42.

## Last action
Codex reproduced a second login defect in the real Axum router: separate HTTP/2
Cookie fields caused `/api/auth/me` to return 401 with `Refresh token missing`.
The shared extractor now reads all fields consistently across authentication,
CSRF, rate limiting, session management and OIDC. Independent code review found
no blocking issue. The earlier dashboard startup fix remains in place.

## Current state
Branch: `fix/dashboard-startup-order`.
Base: `c28480cb4896a67d10f8094171e5b07202e65661` (merged PR #39).
Previous checkpoint: `040ed0ef4cc3f174f967eb7181189822086af06c` (dashboard bootstrap).

Triage: P1 / high availability impact and CSRF compatibility, small effort.
HTTP/2 permits separate Cookie fields; reading only HeaderMap::get(COOKIE)
recognized the access JWT but missed refresh and CSRF cookies in later fields.
An independent deployed TLS probe confirmed HTTP/1 combined=200, HTTP/2
combined=200 and HTTP/2 split=401. See
`../trueid-lab/http2-cookie-before.json`.

Protocol reference: [RFC 9113 section 8.2.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3).

The internal `pub(crate)` helper preserves the first exact named cookie,
including an empty or invalid value. It never retries a later duplicate after
JWT or session validation fails. Any nontext Cookie field rejects extraction,
even after an earlier match. Existing JWT, database, IP, User-Agent, CSRF and
current-session checks remain active. The public API, schema, dependencies and
Cargo.lock are unchanged.

Validation:
- RED: the real router returned 401 `Refresh token missing` for three Cookie
  fields on an HTTP/2 request where 200 was expected.
- GREEN: 5 HTTP/2 router regressions passed. They cover `/me` with reordered
  fields and rate-limit headers, CSRF rejection and acceptance, refresh rotation,
  logout revocation, current-session protection, invalid/empty duplicates, and
  OIDC state/nonce parsing before the disabled-provider check.
- Two helper unit tests cover exact names, values containing `=`, empty first
  values, commas, and nontext fields before or after a valid match.
- `cargo test --workspace --locked`: 421 passed, 0 failed, 16 intentionally
  ignored live auth/RBAC tests. These ignored tests require a disposable server;
  this run did not execute them against the deployed instance.
- Rustfmt, security-focused web Clippy, 3 Node bootstrap regressions, CSP asset
  policy and `git diff --check`: passed. Clippy warnings concern unchanged files.
- `cargo build --locked -p trueid-web --bin trueid-web`: passed; the current
  local debug web binary is available for the disposable validation lane.
- Logs: `../validation-full-20261025/http2-cookie-{red,green,workspace,clippy,web-build}.log`.

## Deployed acceptance and remaining checks
Draft PR: [#42](https://github.com/TadeuszWolfGang/TrueIDv2/pull/42).
The native web binary was built in its own Cargo invocation and atomically
activated in CT104; engine/CLI/probe binaries and private runtime material were
preserved. Application files at the Docker checkpoint 81de703 are identical to
c964583; the later certifi commit changes only the Python lock and this handoff.
The previous web binary and static bootstrap are retained under /root for
recovery; the deployed web SHA256 is
5443954c38b8d23ed3e5951511ae840ff35c6af4c08f2a16363699f9f10dfecf.

- Real TLS/ALPN transport: 9/9 checks passed, including split Cookie fields,
  refresh rotation, old-session rejection, logout and revoked-session rejection.
- Real browser: login, mappings, search, timeline, conflicts, alerts and retained
  authentication after reload passed; no console warning/error was captured.
- The updated debug web binary passed all 16 previously ignored auth/RBAC tests
  on a disposable loopback fixture, plus 10 repository E2E, 11 basic and 44
  extended smoke checks (0 skipped). Fixture processes were stopped afterward;
  destructive test cases did not use the deployed database.
- The refreshed Python environment passed all 20 connector tests, including
  both live TrueID reads with the lab CA verified. No Sycope appliance writes
  or actual Hermes profile changes were made.
- OSV querybatch reported no findings for all five registry packages in the
  updated Python lock. Rust audit/deny passed the existing policy with exactly
  the two documented RSA/crypto-bigint exceptions; raw audit is not clean.
- Evidence: ../trueid-lab/{http2-cookie-after,disposable-validation,
  sycope-live-validation,python-dependency-audit}.json and
  ../../outputs/trueid-dashboard-tested.png.

Hosted Windows, container/native HTTPS, DAST, CodeQL and security checks remain
pending until verified for the final PR head. Real domain-controller forwarding
and end-to-end delivery into the Sycope appliance are not established by these
tests. The operator has a one-event Windows AD smoke script; wait for its
TestCorrelation before claiming a real DC event was received.

## Next action
Inspect final-head CI on draft PR #42 and review the ready changes. Do not merge
without operator authorization for this PR. Preserve all older guests and the
existing CT104 credentials. Do not run a fresh installer over this deployment.

## Container build reproducibility
The former Docker build selected engine and web together, unifying the engine's
Rustls ring feature with web's aws-lc provider. Native HTTPS could then panic
before serving requests because Rustls could not choose a CryptoProvider.

The Dockerfile now builds engine/CLI/probe first, then explicitly selects only
`trueid-web` in a separate release/locked invocation before copying artifacts.
Application sources and Cargo.lock remain identical to checkpoint
`c964583bf6de1d7d140748001b9262646a957586`.

The existing glibc workflow retains its engine checks and adds a native HTTPS
web startup smoke. It generates an ephemeral EC CA and an IP-SAN server
certificate, supplies production secrets via a mode-0600 temporary env file,
uses the image's default nonroot UID 65532, and checks CA-verified `/health`
returns exactly 200. TLS material is mounted read-only. Cleanup removes the
container, temporary credentials and keys, including on failure.

Local validation passed: workflow YAML parsing, Bash syntax for all 7 run steps,
POSIX shell syntax for all 6 Docker RUN commands, actual OpenSSL certificate
chain/IP verification, 3 Node tests, CSP policy and `git diff --check`.
Independent read-only review found no blocker. No local Docker daemon is
available, so image build and container runtime results remain pending CI.
The HTTPS smoke establishes startup/TLS compatibility; it does not claim
engine connectivity or a complete login flow.

## Python CA-bundle security update
Triage: critical advisory, small effort. Dependabot alert #13 identifies
[GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2):
certifi before 2026.10.19 trusts an emSign root with compromised intermediate
keys, allowing an on-path attacker with such a key to impersonate TLS hosts.

`uv lock --project integrations/sycope --upgrade-package certifi --no-python-downloads`
updated only certifi from 2026.7.22 to 2026.10.23. This is the latest compatible
[PyPI release](https://pypi.org/project/certifi/2026.10.23/), supporting Python
>=3.7. Wheel and sdist URLs, SHA256 hashes and sizes match the PyPI JSON API.
All other packages, lock revision 3, project metadata and Rust sources are
unchanged. No new dependency or advisory exception was added.

Existing [Dependabot PR #40](https://github.com/TadeuszWolfGang/TrueIDv2/pull/40)
addresses the same advisory with 2026.10.19; this checkpoint uses the newer fixed
release. PR #40 was inspected without modifying, merging or closing it.

Validation passed: `uv lock --check --offline`, 18 offline connector tests, and
an import check confirming certifi 2026.10.23 with the affected emSign ECC G3
root absent from its bundle. Discovery found 20 tests; the 2 live TrueID tests
were initially skipped; the coordinator subsequently ran all 20 successfully,
including both live reads with CA verification. Independent review found no blocker. Logs and PyPI
metadata proof are in `../validation-full-20261025/certifi-*`.

The connector Dockerfile already uses frozen uv sync, so the lock update is
sufficient for future builds. Existing environments/images require refresh;
the local disposable test environment was synced. This checkpoint does not
claim the default-branch Dependabot alert is closed before merge.

## Open questions / risks
- HTTP_2 + oneshot tests exercise HeaderMap/router behavior; the separate
  deployed TLS/ALPN and browser acceptance now provide transport proof.
- The OIDC fixture validates cookie/state handling with the provider disabled;
  it does not claim a live identity-provider exchange.
- The startup fix assumes the existing parser-blocking script tags. Re-evaluate
  bootstrap if modules become async or dynamically injected after DOM readiness.
- The documented public-key-only exceptions remain RUSTSEC-2023-0071 and
  RUSTSEC-2026-0387; this patch does not alter dependency policy.

## READY-TO-RUN COMMAND
Prerequisites:
- [x] Rust 1.95.0, Node.js with node:test, and Python 3 are available.
- [x] The operator authorized the login compatibility fixes and local tests.
- [x] Commands run from the repository root; workspace tests need local loopback.
- [x] No concurrent Cargo build/test uses this target directory.

```bash
cargo test --locked -p trueid-web --test api_v2_tests test_http2_split_cookie_headers -- --test-threads=1
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --locked -p trueid-web --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
node --test scripts/test-dashboard-bootstrap.cjs
python3 scripts/check-csp-assets.py
cargo build --locked -p trueid-web --bin trueid-web
git diff --check
```

Container CI reproduction (not executed locally): requires a Linux Docker
Buildx daemon, OpenSSL, curl, Ruby/YAML and passwordless sudo, as on the hosted
runner. The extraction below runs the exact smoke body maintained in CI.

```bash
set -euo pipefail
docker buildx build --platform linux/amd64 --target runtime --load -t trueid-runtime:glibc236 .
ruby -ryaml -e 'puts YAML.load_file(ARGV[0]).fetch("jobs").fetch("glibc-compat").fetch("steps").find { |step| step["name"] == "Smoke test native HTTPS web" }.fetch("run")' \
  .github/workflows/glibc-compat.yml | bash
```

Connector reproduction (Python 3.11 is selected from `.python-version`; this
creates a separate test environment and skips live tests explicitly):

```bash
UV_PROJECT_ENVIRONMENT="$(pwd)/../validation-full-20261025/sycope-python-env" \
  uv sync --frozen --project integrations/sycope --no-python-downloads
uv lock --check --offline --project integrations/sycope --no-python-downloads
env -u TRUEID_TEST_URL -u TRUEID_TEST_API_KEY \
  UV_PROJECT_ENVIRONMENT="$(pwd)/../validation-full-20261025/sycope-python-env" \
  uv run --offline --frozen --no-env-file --project integrations/sycope \
  python -m unittest discover -s integrations/sycope/tests -p 'test_*.py' -v
```
