# Changelog

All notable changes to TrueID are documented here.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [0.6.0] — 2026-02-13

### Added
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

### Fixed
- `group_names` subquery missing in routes_v1, routes_search, routes_subnets (groups always null)
- CSV export missing `groups` column
- VPN dispatcher not matching `Username = ..., IP = ...` format

### Changed
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
