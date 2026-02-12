# Changelog

## Unreleased

### Changed
- Refactored web route organization: extracted legacy handlers to `apps/web/src/routes_v1.rs` and engine proxy handlers to `apps/web/src/routes_proxy.rs`, leaving `apps/web/src/lib.rs` as a router orchestrator.
- Updated `build_router()` to use module-qualified handler wiring and kept lookup route behavior for existing clients/tests.
- Refactored `trueid-web` into library + binary split: moved router/app state/handlers to `apps/web/src/lib.rs`, kept startup/bootstrap/server bind in `apps/web/src/main.rs`.
- Added explicit Cargo targets for web crate (`[lib] trueid_web`, `[[bin]] trueid-web`) and kept static assets fallback only in binary startup.
- Reworked API v2 in-process tests to import `trueid_web` directly (removed `#[path]` include hack) and run against in-memory SQLite.
- Marked external integration tests in `tests/auth_integration.rs` and `tests/rbac_matrix.rs` as opt-in (`#[ignore]`) with explicit run instructions.

### Fixed
- **Route authorization hardening** — moved `DELETE /api/auth/sessions/{id}` back to `operator_routes` (Operator+), removed accidental exposure from `viewer_routes`.
- **CSRF on token refresh** — dashboard refresh timer (10 min) now sends `X-CSRF-Token` header, preventing 403 and forced logout.
- **CSRF in smoke-test.sh** — refresh and logout curl calls now extract CSRF token from cookie jar and send header.
- **request_id in login/refresh** — handlers read `RequestId` from Axum extensions (not request headers), fixing empty `request_id` in audit logs and error responses.
- **Session revoke accessible to Viewer** — `DELETE /api/auth/sessions/{id}` moved from `operator_routes` to `viewer_routes` so all logged-in users can manage their own sessions.
- **locked_until in 423 response** — login now returns `locked_until` (ISO 8601) in the JSON body so the frontend can display a countdown.
- **Deduplicated `extract_cookie`** — single `pub fn` in `auth.rs`, removed duplicates from `middleware.rs` and `routes_auth.rs`.
- **Removed unused `cookie` crate** dependency from `apps/web/Cargo.toml`.

### Added
- **Dashboard v1.5 refresh (frontend):**
  - Reworked `index.html` tabs and navigation: Mappings, Search, Conflicts, Alerts, Status, Sycope, Audit.
  - Upgraded Mappings tab to `/api/v2/search` with filters, paging, exports, and 30s refresh cadence.
  - Added Search tab (unified v2 search), Conflicts tab (stats/filter/resolve), and Alerts tab (stats/history + admin rule CRUD UI).
  - Added timeline slide-in panel with cross-navigation from clickable IP/user links.
- **Alerts & webhooks (v2):**
  - Added migration `0012_add_alerts_tables.sql` with `alert_rules` and `alert_history`.
  - Added engine alert module (`apps/engine/src/alerts.rs`) with rule loading, event evaluation, cooldown checks, and async webhook delivery.
  - Integrated alert processing into engine event loop with rule cache reload every 60 seconds.
  - Added web alert API (`apps/web/src/routes_alerts.rs`) for admin rule CRUD and viewer alert history/stats.
  - Wired alert routes in `apps/web/src/main.rs` (viewer + admin groups).
- **Timeline API (v2):**
  - Added `routes_timeline.rs` with investigation endpoints:
    - `GET /api/v2/timeline/ip/{ip}` (current mapping, paginated events, user transitions, unresolved conflicts count).
    - `GET /api/v2/timeline/user/{user}` (active mappings, paginated events, distinct IP list).
    - `GET /api/v2/timeline/mac/{mac}` (current mappings and mapping-based IP history).
  - Wired timeline routes in `viewer_routes` for authenticated read access.
- **Conflict detection foundation (v2):**
  - Added migration `0011_add_conflicts_table.sql` with `conflicts` table and indexes.
  - Added engine conflict detection module (`apps/engine/src/conflicts.rs`) for `ip_user_change`, `mac_ip_conflict`, and `duplicate_mac` with 5-minute dedup.
  - Added web conflict API (`apps/web/src/routes_conflicts.rs`): list, stats, and resolve endpoints.
  - Wired routes in `apps/web/src/main.rs` for Viewer+ read and Operator+ resolve actions.
- **API v2 search foundation**:
  - New module `apps/web/src/routes_search.rs` with:
    - `GET /api/v2/search` (unified mappings + events query, filters, pagination, sorting, scope, timing).
    - `GET /api/v2/export/mappings` (JSON/CSV export with filters).
    - `GET /api/v2/export/events` (JSON/CSV export, 100k safety cap, truncation header).
  - New migration `0010_add_search_indexes.sql` adding search/time indexes for `events` and `mappings`.
  - Router wiring in `viewer_routes` for new v2 endpoints.
- **RBAC & Authentication system** (17-step plan fully implemented):
  - Database migration `0009_add_auth_tables.sql`: `users`, `sessions`, `api_keys`, `audit_log` tables with indexes and triggers.
  - Domain models: `UserRole` (Admin/Operator/Viewer), `User`, `UserPublic`, `Session`, `ApiKeyRecord`, `AuditEntry`.
  - DB layer (`db_auth.rs`): full CRUD for users, sessions, API keys, audit log with Argon2id password hashing, SHA-256 token hashing, account lockout (5 attempts → 30 min lock).
  - JWT auth (`auth.rs`): HS256 tokens in HttpOnly/Secure/SameSite=Strict cookies, CSRF double-submit cookie, refresh token rotation with replay detection.
  - Unified error format (`error.rs`): `ApiError` with status, code, message, request_id.
  - Auth middleware (`middleware.rs`): `AuthUser`/`OptionalAuthUser` extractors (cookie JWT + X-API-Key), CSRF guard, role-based route layers (Viewer/Operator/Admin).
  - Auth endpoints (`routes_auth.rs`): login, logout, logout-all, refresh, /me, change-password, session listing/revocation.
  - User management (`routes_users.rs`): Admin-only CRUD — create, list, get, change role, reset password, unlock, delete (with last-admin protection).
  - API key management (`routes_api_keys.rs`): Admin-only create/list/revoke, raw key shown only at creation.
  - Engine service token (`admin_api.rs`): `X-Service-Token` middleware on engine admin API, web proxy sends token automatically.
  - Config encryption (`db.rs`): AES-256-GCM encryption for sensitive config values (`sycope_pass`, `sycope_login`), auto-migration of plaintext on startup.
  - Login page (`login.html`): matching dashboard style, force-password-change flow.
  - Dashboard auth integration (`index.html`): auth check → redirect, CSRF in fetch, token refresh every 10 min, role-based tab visibility, user bar + logout.
  - Security headers middleware: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  - Rate limiting (`rate_limit.rs`): DashMap-based sliding window — login (10/60s per IP), API keys (100/60s per prefix).
  - AuthProvider trait (`auth_provider.rs`): `LocalAuthProvider`, `LdapAuthProvider` stub, `AuthProviderChain` — login/change-password routed by `auth_source`.
  - Audit log endpoints (`routes_audit.rs`): paginated list with filters (action, username, since, until), stats (total, 24h, 7d, top actions). Append-only by design.
  - Audit Log tab in dashboard: Admin-only, filterable, paginated, auto-refresh 30s.
  - Native TLS support: optional `TLS_CERT`/`TLS_KEY` env vars → HTTPS via axum-server + rustls.
  - Production startup validation: fail-fast on missing `JWT_SECRET`, `ENGINE_SERVICE_TOKEN`, `CONFIG_ENCRYPTION_KEY` (bypass with `TRUEID_DEV_MODE=true`).
  - Admin bootstrap: auto-create admin user from `TRUEID_ADMIN_USER`/`TRUEID_ADMIN_PASS` on first run with `force_password_change=true`.
  - Background tasks: session cleanup (hourly), rate limiter cleanup (5 min).
  - Integration tests (`tests/`): auth flows (12 tests), RBAC matrix (role × endpoint), API key auth, CSRF protection.
  - Smoke test script (`scripts/smoke-test.sh`): 11 curl-based checks.
  - `docker-compose.tls.yml`: Traefik + Let's Encrypt example overlay.
- **Documentation:** Security section in README (TLS, env vars, roles, secret generation), API key auth section in INTEGRATION_GUIDE.md.

### Changed
- `docker-compose.yml`: added auth-related env vars (`ENGINE_SERVICE_TOKEN`, `JWT_SECRET`, `CONFIG_ENCRYPTION_KEY`, `ARGON2_PEPPER`, `TRUEID_ADMIN_*`, `TRUEID_DEV_MODE`).
- Router refactored into role-grouped layers: public, viewer, operator, admin routes.
- `Db` struct extended with `pepper` and `encryption_key` fields.
- `Makefile`: added `test-integration` and `smoke-test` targets.

### Dependencies
- `crates/common`: +aes-gcm, argon2, async-trait, base64, rand, sha2.
- `apps/web`: +async-trait, axum-server (tls-rustls), cookie, dashmap, jsonwebtoken, rand, uuid.
- `apps/engine`: +sqlx (workspace dependency) for conflict detection queries.

### Previous
- **net-identity-agent:** New Rust-based Windows Event Log agent (`crates/agent/`) with TCP+TLS transport (mTLS), ring buffer, exponential-backoff reconnect, heartbeat, and `--dry-run` mode.
- **TLS listeners on engine:** Dual-protocol support — existing UDP (NXLog) preserved, new TCP+TLS listeners (AD:5615, DHCP:5617) activated when cert files are present.
- **PKI tooling:** `scripts/gen-certs.sh` generates CA + server + agent certificates for mTLS.
- **Unit tests:** 8 tests for XML event parsers (4768, 4624, DHCP 10) and syslog octet-counting framing.
- **Sycope connector:** Python integration (`integrations/sycope/`) — CSV Lookup enrichment (Pattern A) and Custom Index event injection (Pattern B) following official SycopeSolutions/Integrations SDK patterns.
- **Sycope SDK:** Vendored `sycope/` package from SycopeSolutions/Integrations for API auth, lookups, indexes.
- **Web API v1:** `GET /api/v1/mappings` (active only) and `GET /api/v1/events?since=<ts>` endpoints on `trueid-web`.
- **Migration:** `0005_add_vendor_to_mappings.sql` — ensures `vendor` column exists on fresh deployments.

### Changed
- **Architectural Overhaul:** Split monolithic `net-identity-server` into two separate applications:
  - `trueid-engine`: Headless service for passive ingestion (UDP/Syslog) and DB writing.
  - `trueid-web`: HTTP service for API and Dashboard visualization.
- **Refactor:** Extracted shared logic (models, DB pool, migrations) to `trueid-common`.
- **Removed:** Legacy `crates/core` and `crates/db` (merged into common).
- **Docs:** Updated README with ASCII architecture diagram and Engine/Web split.
- **Feature:** `is_active` TTL flag on mappings — janitor task deactivates stale entries every 60s (5 min TTL).
- **UI:** Dashboard shows online/offline status (green/grey dot, dimmed rows, relative time in Last Seen).
- **Docker:** Multi-stage Dockerfile + docker-compose.yml (engine + web services with shared SQLite volume).
- **Feature:** OUI vendor lookup — engine loads IEEE `oui.csv` at startup for MAC-to-vendor resolution.
- **Feature:** Vendor name persisted to DB (`vendor` column) and exposed via API.
- Set up Rust workspace and crate structure.
- Add core domain models and ingestion trait.
- Scaffold Axum server and data/access crates.
- Add SQLite db layer with migrations and mapping queries.
- Add RADIUS adapter with UDP listener and event parsing.
- Add AD syslog adapter for event 4768/4624.
- Integrate adapters, DB, and HTTP server in main app.
- Add events history table and source-priority mapping logic.
- Debug endpoint `POST /api/debug/event` for manual ingest.
- Public API `GET /api/recent` for dashboard data.
- Verified End-to-End data flow (API -> DB -> API).
- Minimalist HTML/JS Dashboard served from `/`.
- Static file serving via `tower-http`.
- Auto-refresh logic for realtime-like experience.
- Verified End-to-End flow with UI visualization.
- Include `source` in mapping responses (PascalCase).
- Add RADIUS accounting test client utility.
- `dotenvy` support: Server now automatically loads `.env` file on startup.
- `ad_client` utility: Verified payload format to match server parser regex.
- Verified End-to-End AD Syslog ingestion (User -> Syslog -> DB -> API).
- Fixed port binding issue on macOS (respecting `AD_SYSLOG_BIND` from env).
- DHCP Syslog Adapter: listening for `DHCPACK` logs to map non-802.1x devices.
- Hostname extraction: DHCP adapter now parses hostnames (e.g., `(Printer-HP)`) into the User field.
- `dhcp_client` utility: Tool for simulating DHCP syslog traffic.
- Full multi-protocol ingest support (RADIUS + AD + DHCP).
