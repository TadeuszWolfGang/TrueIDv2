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

## Security

### TLS (REQUIRED for production)

TrueID uses HttpOnly Secure cookies. The browser will only send Secure cookies over HTTPS.
Without TLS, authentication will not work (unless `TRUEID_DEV_MODE=true`).

**Option A: Reverse proxy (recommended)**

```nginx
server {
    listen 443 ssl;
    server_name trueid.example.com;
    ssl_certificate /etc/ssl/trueid.pem;
    ssl_certificate_key /etc/ssl/trueid-key.pem;

    location / {
        proxy_pass http://trueid-web:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Option B: Native TLS**

Set `TLS_CERT` and `TLS_KEY` env vars pointing to PEM files. `trueid-web` will use HTTPS directly.

### Required environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Prod | Random 64+ char secret for JWT signing |
| `ENGINE_SERVICE_TOKEN` | Prod | Shared secret between web↔engine (≥32 chars) |
| `CONFIG_ENCRYPTION_KEY` | Prod | 64 hex chars (32-byte AES key) for config encryption |
| `ARGON2_PEPPER` | Recommended | Extra secret prepended to passwords before hashing |
| `TRUEID_ADMIN_USER` | First run | Initial admin username |
| `TRUEID_ADMIN_PASS` | First run | Initial admin password (≥12 chars) |
| `TLS_CERT` | If native TLS | Path to certificate PEM |
| `TLS_KEY` | If native TLS | Path to private key PEM |
| `TRUEID_DEV_MODE` | Dev only | Set `"true"` to relax security for local development |

### Secret generation

```bash
JWT_SECRET=$(openssl rand -hex 32)
ENGINE_SERVICE_TOKEN=$(openssl rand -hex 32)
CONFIG_ENCRYPTION_KEY=$(openssl rand -hex 32)
ARGON2_PEPPER=$(openssl rand -hex 16)
```

### Network architecture

- Engine `:8080` must **NEVER** be exposed outside the Docker network.
- All external access goes through `trueid-web` `:3000` which enforces authentication.
- Web→Engine communication is secured by `ENGINE_SERVICE_TOKEN` header.

### Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: user management, API keys, config, audit logs |
| **Operator** | Read + write mappings, manage own sessions |
| **Viewer** | Read-only access to mappings, events, stats |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| White screen on port 3000 | Run `make engine` first, then `make web` |
| "unable to open database" | Check `DATABASE_URL` in `.env`, run `make setup` |
| DB exists but tables missing | Run `make engine` to apply migrations |
| Need full reset | `make clean && make setup` |

## Integration

See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for step-by-step configuration
of all supported data sources: TrueID Agent (Windows, TLS), NXLog CE,
FreeRADIUS, Microsoft NPS, ISC DHCP + rsyslog, Kea DHCP, and Windows DHCP Server.
