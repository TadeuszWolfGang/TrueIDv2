# Changelog

## Unreleased

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
