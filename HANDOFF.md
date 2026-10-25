# HANDOFF — browser login compatibility

## Phase
POST-REALIZATION — both defects fixed and independently reviewed; deployment
acceptance in the real HTTPS browser is pending.

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

## Next action
Review this checkpoint, rebuild only the native web binary, then verify actual
HTTP/2 split cookies and a fresh browser login. Confirm mappings load, the
browser remains on the dashboard, refresh/logout work, and CSRF still rejects
missing or incorrect tokens. Run the live auth/RBAC suite against a disposable
instance using the updated binary. Deployment and GitHub publication remain
owned by the operator's coordinating session.

## Open questions / risks
- HTTP_2 + oneshot tests exercise HeaderMap/router behavior; deployed TLS/ALPN
  and browser acceptance provide the transport proof after deployment.
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
