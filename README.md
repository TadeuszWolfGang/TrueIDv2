# TrueID v0.3.0

**Real-time Identity Correlation Engine** written in Rust.
Maps IP addresses to user identities using RADIUS (802.1x), Active Directory
(Kerberos/Syslog) and DHCP — with source-priority scoring and a live dashboard.

## Architecture

```
 ┌──────────┐  ┌──────────┐  ┌──────────┐
 │  RADIUS  │  │ AD Syslog│  │DHCP Syslog│
 └────┬─────┘  └────┬─────┘  └────┬──────┘
      │  UDP :1813   │ UDP :5514   │ UDP :5516
      └──────────────┼─────────────┘
                     ▼
            ┌────────────────┐
            │ TrueID Engine  │   (trueid-engine)
            │  adapters +    │
            │  event loop    │
            └───────┬────────┘
                    │ write
                    ▼
              ┌──────────┐
              │  SQLite   │
              └─────┬────┘
                    │ read
                    ▼
            ┌────────────────┐
            │  TrueID Web    │   (trueid-web)
            │  API + static  │
            └───────┬────────┘
                    │ HTTP :3000
                    ▼
            ┌────────────────┐
            │ Admin Dashboard│
            └────────────────┘
```

## Components

| Crate | Path | Role |
|-------|------|------|
| **trueid-common** | `crates/common` | Shared models (`IdentityEvent`, `DeviceMapping`, `SourceType`), DB pool, migrations, helpers. |
| **trueid-engine** | `apps/engine` | Passive UDP/Syslog listener. Writes to DB. No HTTP. Graceful shutdown on Ctrl+C. |
| **trueid-web** | `apps/web` | Read-only Axum HTTP server. API (`/api/recent`, `/lookup/{ip}`) and static dashboard. Decoupled from ingestion. |

## Quick Start

### Requirements

- Rust 1.75+ & Cargo
- SQLite (bundled via `libsqlite3-sys`)

### Configuration

Both services share the same `.env` file:

```bash
cp .env.example .env
```

```env
DATABASE_URL=sqlite://trueid.db?mode=rwc
RADIUS_BIND=0.0.0.0:1813
AD_SYSLOG_BIND=0.0.0.0:5514
DHCP_SYSLOG_BIND=0.0.0.0:5516
RADIUS_SECRET=secret
HTTP_BIND=0.0.0.0:3000
```

### Build

```bash
cargo build --release
```

### Run

Start the engine (data collection) and web (dashboard) in separate terminals:

```bash
# Terminal 1 — ingestion
cargo run -p trueid-engine

# Terminal 2 — dashboard
cargo run -p trueid-web
```

## Integration

See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for step-by-step configuration
of Active Directory (NXLog), RADIUS (FreeRADIUS / NPS) and DHCP (rsyslog)
to forward data to TrueID.
