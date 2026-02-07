# TrueID

**Real-time Identity Correlation Engine** written in Rust.
Maps IP addresses to user identities using RADIUS (802.1x), Active Directory
(Kerberos/Syslog) and DHCP — with source-priority scoring and a live dashboard.

## Requirements

- Rust (stable, >= 1.75) — install: https://rustup.rs
- macOS / Linux (Windows: WSL2)

## Quick Start

```bash
git clone <repo-url> && cd TrueID

# 1. Setup (first time only)
make setup

# 2. Run engine (Terminal 1)
make engine

# 3. Run web dashboard (Terminal 2)
make web
# Dashboard: http://127.0.0.1:3000
```

## Commands

| Command       | Description                              |
|---------------|------------------------------------------|
| `make setup`  | First-time setup: .env, build, init DB   |
| `make engine` | Run engine (ingestion + admin API)       |
| `make web`    | Start web dashboard (port 3000)          |
| `make run`    | Run engine + web together                |
| `make check`  | Health check: .env, DB, server status    |
| `make clean`  | Remove local database                    |
| `make help`   | Show all available commands              |

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
            │  admin API     │   :8080 (internal)
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
            │  API + proxy   │
            │  + static UI   │   :3000
            └────────────────┘
```

## Components

| Crate | Path | Role |
|-------|------|------|
| **trueid-common** | `crates/common` | Shared models, DB pool, migrations, helpers |
| **trueid-engine** | `apps/engine` | Passive UDP/TLS listener + Admin API (:8080). Writes to DB |
| **trueid-web** | `apps/web` | HTTP API gateway + dashboard. Reads from DB, proxies writes to engine |

## Configuration

Copy `.env.example` to `.env` (done automatically by `make setup`):

```env
DATABASE_URL=sqlite://net-identity.db?mode=rwc
RADIUS_BIND=0.0.0.0:1813
AD_SYSLOG_BIND=0.0.0.0:5514
DHCP_SYSLOG_BIND=0.0.0.0:5516
HTTP_BIND=0.0.0.0:3000
RUST_LOG=info
```

All defaults work out of the box — no changes needed for local development.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| White screen on port 3000 | Run `make engine` first, then `make web` |
| "unable to open database" | Check `DATABASE_URL` in `.env`, run `make setup` |
| DB exists but tables missing | Run `make engine` to apply migrations |
| Need full reset | `make clean && make setup` |

## Integration

See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for step-by-step configuration
of Active Directory (NXLog), RADIUS (FreeRADIUS / NPS) and DHCP (rsyslog)
to forward data to TrueID.
