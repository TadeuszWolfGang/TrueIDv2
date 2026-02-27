# Changelog

All notable changes to TrueID are documented here.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [0.8.0] — 2026-02-08

### Added
- Phase 6 E2E coverage: map topology/flows, report schedule lifecycle/validation/send-now, rate-limit headers/usage/429, OIDC status+admin CRUD+disabled login, static JS serving, Matrix-theme HTML smoke checks
- New unit tests: token-bucket burst/refill, scheduler cron daily match, OIDC authorization URL format
- OIDC admin aliases: `GET/PUT /api/v2/admin/oidc/config`, `POST /api/v2/admin/oidc/test`
- Shared pagination primitives in common crate: `PaginationParams`, `PaginatedResponse<T>`

### Changed
- Report schedule routes now use consolidated DB helper methods from `trueid-common::db` (reduced inline SQL in web handlers)
- Unified pagination logic in selected routes (`v1`, `search`, `alerts`, `audit`) via shared pagination helper
- Package versions bumped to `0.8.0` across workspace crates/apps
- OpenAPI metadata version bumped and extended with Phase 6 endpoint groups
- HA docs extended with OIDC SSO failover/runtime notes
- Dashboard navigation refactored from top tabs to a fixed left sidebar with grouped sections and Matrix-styled active state
- Status/Admin UI extended with Users table, Add User modal, and Reset Password actions wired to `/api/v2/admin/users*`
- Dashboard UI/UX refresh: global Matrix background layering, collapsible sidebar groups with active-tab auto-expand, and semi-transparent content panels
- Added global sortable table headers (`sort`/`order`) across Mappings/Search/Conflicts/Alerts/Audit/Subnets/Switches/DNS/Fingerprints views
- Docker runtime image now includes `sqlite3` and `curl`, ships a container entrypoint pre-flight, and sets default `ENTRYPOINT/CMD` for standalone engine/web runs
- Docker compose services now rely on image-bundled OUI CSV path and no longer require external `/app/oui.csv` bind mount hacks

### Fixed
- Audit filters switched to substring matching (`LIKE '%...%'`) for `action` and `username` in DB audit queries (minimal Rust fix)
- Dashboard sidebar group toggles now work via global `toggleGroup`, and Matrix rain defaults to enabled when no preference exists (`trueid_matrix_rain=on/off`).
- Dashboard Matrix rain visibility increased (`opacity` + softer fade), sidebar groups switched to `display`-based collapse, and group headers now use `data-toggle` with delegated click handling.
- SQLite startup now auto-creates parent directories for file-backed `DATABASE_URL` paths, preventing `(code: 14) unable to open database file` on fresh mounts
- OUI lookup logging switched from `info` to `trace` to avoid high-volume vendor lookup noise in production logs

## [0.6.0] — 2026-02-13

### Added
- **API Rate Limiting Per-Key**: token-bucket limiter with per-key RPM/burst overrides (`api_keys.rate_limit_rpm`, `api_keys.rate_limit_burst`)
- **Rate Limit Response Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` on authenticated API responses (API key + session)
- **API Key Usage Rollups**: hourly usage/error aggregates in new `api_usage_hourly` table with non-blocking request tracking
- **API Key Admin API v2**: usage endpoint (`GET /api/v2/api-keys/{id}/usage`) and limits update endpoint (`PUT /api/v2/api-keys/{id}/limits`)
- Dashboard **Status** tab extension: API keys panel with RPM/error visibility, 7-day inline SVG usage chart, and limit editing
- 3 new E2E tests: `test_api_key_rate_limit_headers`, `test_api_key_usage_tracking`, `test_api_key_rate_limit_429`
- **Scheduled Reports & Delivery**: `report_schedules` model and engine scheduler loop for cron-based report execution with duplicate-window protection
- **Scheduled Report Channels**: report delivery via existing notification channels (email/slack/teams/webhook), including Matrix-themed HTML email format
- **Report Schedules API**: admin CRUD + send-now endpoints under `/api/v2/reports/schedules*`
- Analytics tab extension with **Scheduled Reports** management UI (schedule form, sections/channels selection, send-now action, list table)
- 2 new E2E tests: `test_report_schedule_crud` and `test_report_schedule_send_now_no_channels`
- **Network Map Visualization**: new dashboard tab with Matrix-themed SVG topology (adapters, managed/discovered subnets, integrations), animated flow paths, hover tooltips, and auto-refresh
- **Map API v2**: `GET /api/v2/map/topology` and `GET /api/v2/map/flows` for Viewer+ role
- New E2E test: `test_map_topology` validating map topology endpoint contract
- Dashboard JS modularization under `apps/web/assets/js/` with real domain extraction (`mappings`, `conflicts`, `alerts`, `analytics`, `network`, `integrations`, `admin`) plus shared `utils` and `api` helpers
- Matrix/Cyber UI redesign for dashboard and login pages: neon-green palette variables, glow/scan-line effects, custom scrollbars, and security modal visual refresh
- Subtle Matrix rain canvas background for dashboard and login, with dashboard toggle persisted via `localStorage` (`trueid_matrix_rain`)
- Phase 5 test expansion: +14 web E2E tests (SSE, notification channels, retention run/stats/validation, import batch/partial failure, password history reuse, absolute session timeout, duplicate tags, geo field presence)
- 3 new unit tests: Geo resolver private IP path, retention executor empty tables, password policy validator behavior
- New shared runtime config model: `crates/common/src/app_config.rs` with in-memory reload support in web state
- **Notification Channels**: email (SMTP), Slack, Teams, webhook channels with encrypted config storage and per-channel delivery logs
- **Notifications API**: `/api/v2/notifications/channels*` CRUD + test endpoint + deliveries history
- **Engine Notification Dispatcher**: channel-based alert fan-out with delivery tracking (`notification_deliveries`)
- 4 new E2E tests for notification channels CRUD/types/validation/deliveries
- **SSE Live Feed**: engine `/engine/events/stream` + web `/api/v2/events/stream` for real-time mapping/conflict/alert/firewall/heartbeat events
- Dashboard live updates via native `EventSource` (toast indicator + Live/Polling connection status)
- **Reporting & Analytics**: `/api/v2/analytics/*` endpoints, compliance summary, daily `report_snapshots` generator, dashboard Analytics tab (SVG charts + report history)
- **Production Operations**: backup/restore/install scripts, Nginx/Caddy reverse-proxy templates, systemd services + backup timer, HA architecture guide (`docs/HA.md`)
- **VPN Adapters**: AnyConnect, GlobalProtect, Fortinet syslog parsing (UDP :5518 + TLS)
- **Firewall User-ID Push**: PAN-OS (XML API, batch 1000) and FortiGate (REST API) integration
- **SIEM Forwarding**: CEF, LEEF, JSON syslog event forwarding over UDP/TCP
- **LDAP Group Sync**: Active Directory group membership sync with user enrichment
- **Prometheus Metrics**: `/metrics` endpoint with 8 metric families
- **Multi-user Sessions**: Terminal server support with concurrent session tracking per IP
- **IPv6 Foundation**: Dual-stack subnet matching (v4+v6 CIDR), IPv6-safe alert formatting
- **Dashboard Extensions**: Firewall, SIEM, LDAP, Subnets, Switches, Fingerprints, DNS, Status tabs
- **Docker Production**: Dependency-cached Dockerfile, healthchecks, non-root runtime
- **OpenAPI 3.1**: Complete API specification (`docs/openapi.yaml`)
- `helpers::audit()` — reduced audit log boilerplate
- `helpers::audit_system()` and `helpers::audit_principal()` for non-auth/system audit flows
- `EventLoopCtx` struct — cleaner event loop parameter passing
- 34 new tests (21 E2E + 13 unit) covering Phase 3 handlers and parsers
- Phase 4 test coverage: +10 analytics E2E tests and +2 report generator unit tests (totals: 93 E2E, 15 unit)
- SSE test coverage: +2 E2E tests (`test_sse_endpoint_requires_auth`, `test_sse_endpoint_returns_stream`)
- **Data Retention Policies**: `retention_policies` table with seeded defaults for events/conflicts/alerts/audit/deliveries/firewall/reports/dns
- **Retention Executor + Scheduler**: batched cleanup (1000 rows), configurable interval (`retention_interval_hours`), optional post-cleanup `VACUUM`
- **Retention Admin API**: `/api/v2/admin/retention*` list/update/run/stats endpoints
- Dashboard **Status** tab now includes **Data Retention** controls and DB/table stats
- 3 new E2E tests for retention list/update/audit-minimum validation
- **CLI Tool (`trueid`)**: new API-driven command-line client (`apps/cli`) with commands for lookup/search/mappings/conflicts/alerts/status/stats/users/export/import/retention/health
- **Bulk Import API**: `POST /api/v2/import/events` for JSON batch ingestion with per-row validation and error reporting
- 3 new E2E tests for import endpoint (success/invalid IP/max limit)
- **Enhanced Security**: configurable password policy, password history enforcement, TOTP 2FA (setup/verify/disable/status/backup codes), and session hardening (idle/absolute timeout + IP/UA binding)
- New admin security APIs: `/api/v2/admin/security/password-policy`, `/api/v2/admin/security/sessions*`, `/api/v2/admin/security/totp-requirement`
- New user/admin TOTP APIs: `/api/auth/totp/*` and `DELETE /api/v1/users/{id}/totp`
- 5 new E2E tests for password policy, TOTP flow, and session IP metadata
- **Network Context Enrichment**: GeoIP cache, passive discovered subnets, and manual IP tags with API support
- New Geo API: `/api/v2/geo/{ip}`, `/api/v2/geo/stats`, `/api/v2/geo/refresh` (private-IP safe fallback)
- New Tags API: `/api/v2/tags*` for create/list/search/delete and per-IP tag lookup
- New discovered-subnets flows: `/api/v2/subnets/discovered`, `/api/v2/subnets/promote`, dismiss endpoint for admin
- Dashboard updates: mappings `Location` + `Tags`, discovered subnets section, timeline IP tags, status quick tag management
- 4 new E2E tests for tags/discovered-subnets/geo-private lookup

### Fixed
- `group_names` subquery missing in routes_v1, routes_search, routes_subnets (groups always null)
- CSV export missing `groups` column
- VPN dispatcher not matching `Username = ..., IP = ...` format

### Changed
- `index.html` now loads ordered external scripts (`js/*.js`) instead of a single inline JS monolith; `app.js` reduced to app orchestration/state responsibilities
- Analytics SVG styling updated to cyber theme colors (bars/donut/labels) and live SSE toasts switched to neon flash style
- Web routing refactor: extracted grouped routers to `apps/web/src/routes.rs`, reduced `build_router()` complexity in `apps/web/src/lib.rs`
- Session hardening reads idle/absolute timeout from shared runtime config and supports immediate expiry (`session_absolute_max_hours <= 0`) for tests/ops
- SSE proxy errors now return unified `ApiError` format (instead of raw status codes)
- Alert rule create/update payload now supports `channel_ids`; rule list now includes linked channels
- Dashboard adds admin-only **Notifications** tab and alert-rule channel selector
- Polling for mappings/conflicts/alerts reduced to 120s when SSE is connected (fallback to 30s on disconnect)
- Graceful shutdown flow for engine/web (drain window, controlled loop stop, graceful server termination)
- `parse_vpn_syslog` now public for testability
- 6 call sites migrated from inline `ok_or_else` to `helpers::require_db()`
- 10 audit calls in Phase 3 routes migrated to `helpers::audit()`
- Mapping SQL projection unified via `MAPPING_SELECT` constant across API and DB queries (removed 7 duplicates)
- Analytics/report SQL extracted from `db.rs` to new `db_analytics.rs` module (`db.rs` reduced to ~754 LOC)
- Remaining direct web audit writes migrated to helpers; direct `.write_audit_log(...)` calls now centralized in `helpers.rs`

## [0.5.0] — 2026-02-08

### Added
- **Alert Engine**: 5 rule types (new_mac, ip_conflict, user_change, new_subnet, source_down), webhook + cooldown
- **Subnet Management**: CIDR definitions, auto-tagging, VLAN + location metadata
- **DNS Reverse Lookup**: Background PTR resolution with configurable cache
- **DHCP Fingerprinting**: Option 55 parsing, device type classification, OUI vendor database
- **SNMP Switch Polling**: MAC-to-port mapping via SNMP v2c/v3
- **Conflict Detection**: ip_user_change, mac_ip_conflict, duplicate_mac with severity levels
- **Timeline API**: IP/User/MAC history with user transitions
- **Search API v2**: Universal search across mappings + events, CSV/JSON export
- **TLS/mTLS Listeners**: Agent certificate authentication
- Dashboard: Conflicts tab, Alerts tab (rules + history), Search tab, Timeline panel
- 56 E2E integration tests

## [0.4.0] — 2026-01-25

### Added
- **Core Engine**: RADIUS, AD Syslog, DHCP Syslog adapters
- **Web Dashboard**: Login, mappings table, basic search, Sycope integration tab
- **Auth System**: JWT sessions, API keys, RBAC (Admin/Operator/Viewer), CSRF protection
- **Audit Logging**: All admin actions recorded with request correlation
- Source priority scoring with configurable weights
- Rate limiting and account lockout
- 24 E2E tests
