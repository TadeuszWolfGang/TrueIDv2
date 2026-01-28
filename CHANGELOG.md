# Changelog

## Unreleased
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
