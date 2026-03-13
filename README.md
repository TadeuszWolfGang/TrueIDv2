# TrueID

[![CI](../../actions/workflows/glibc-compat.yml/badge.svg)](../../actions/workflows/glibc-compat.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.82%2B-orange.svg)](https://rustup.rs)

**Real-time identity correlation platform**
TrueID maps IP addresses to users and devices from multiple telemetry sources and exposes
RBAC-protected APIs, dashboard workflows, and integration outputs for SOC operations.

## Requirements

- Rust (stable, >= 1.82) - install: https://rustup.rs
- Docker + Docker Compose (recommended for deployment)
- macOS / Linux (Windows via WSL2)

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

| Command | Description |
|---|---|
| `make setup` | First-time setup: `.env`, build, init DB |
| `make engine` | Run engine (ingestion + admin API) |
| `make web` | Start web dashboard (port 3000) |
| `make run` | Run engine + web together |
| `make check` | Health check: `.env`, DB, server status |
| `make smoke-test` | Run basic API smoke checks |
| `make test` | Run full test suite |
| `make lint` | Run `fmt` + `clippy -D warnings` |
| `make docker-build` | Build Docker images |
| `make docker-up` | Start Docker stack |
| `make docker-down` | Stop Docker stack |
| `make docker-status` | Show container status + health |
| `make docker-logs` | Follow container logs |
| `make docker-backup` | Backup SQLite DB from container |
| `make help` | Show all available targets |

## Architecture

```
 ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
 │  RADIUS  │  │ AD Syslog│  │DHCP Syslog│  │VPN Syslog│
 └────┬─────┘  └────┬─────┘  └────┬──────┘  └────┬─────┘
      │ :1813       │ :5514       │ :5516        │ :5518
      └─────────────┼─────────────┼──────────────┘
                    ▼             ▼
           ┌─────────────────────────────┐
           │       TrueID Engine         │
           │  Adapters │ Event Loop      │
           │  Conflict │ Alert Engine    │──► Firewall Push (PAN-OS/FortiGate)
           │  SNMP     │ DNS Resolver    │──► SIEM Forward (CEF/LEEF/JSON)
           │  LDAP     │ Prometheus      │──► Webhook Alerts
           └────────────┬────────────────┘
                        │ SQLite
                        ▼
           ┌─────────────────────────────┐
           │       TrueID Web            │
           │  REST API │ Auth (JWT)      │
           │  Dashboard│ Audit Log       │
           │  CSV/JSON │ Role-based ACL  │
           └─────────────────────────────┘
                     :3000
```

## Components

| Crate | Path | Role |
|---|---|---|
| `trueid-common` | `crates/common` | Shared models, DB, migrations, crypto/config helpers |
| `trueid-engine` | `apps/engine` | UDP/TLS ingestion, correlation, push/forward pipelines |
| `trueid-web` | `apps/web` | REST API + dashboard + auth/RBAC + reporting/export |

## Features

| Category | Feature | Status |
|---|---|---|
| **Ingestion** | RADIUS (802.1x) | ✅ |
|  | Active Directory Syslog | ✅ |
|  | DHCP Syslog | ✅ |
|  | VPN Syslog (AnyConnect, GlobalProtect, Fortinet) | ✅ |
|  | TLS/mTLS agent support | ✅ |
| **Correlation** | IP<->User<->MAC mapping | ✅ |
|  | Source priority scoring | ✅ |
|  | Multi-user session tracking | ✅ |
|  | IPv4 + IPv6 dual-stack | ✅ |
| **Network** | Subnet management + auto-tagging | ✅ |
|  | SNMP switch polling (MAC->port) | ✅ |
|  | DHCP fingerprinting (device type) | ✅ |
|  | DNS reverse lookup cache | ✅ |
|  | OUI vendor resolution | ✅ |
| **Security** | Conflict detection (3 types) | ✅ |
|  | Alert rules + webhook | ✅ |
|  | Firewall User-ID push (PAN-OS, FortiGate) | ✅ |
|  | SIEM event forwarding (CEF, LEEF, JSON) | ✅ |
| **Identity** | LDAP/AD group sync | ✅ |
|  | User group enrichment in API | ✅ |
| **API** | REST API v1 + v2 | ✅ |
|  | API key authentication | ✅ |
|  | JWT session auth + CSRF | ✅ |
|  | Role-based access (Admin/Operator/Viewer) | ✅ |
|  | CSV + JSON export | ✅ |
|  | Timeline (IP/User/MAC) | ✅ |
|  | Audit log | ✅ |
| **Monitoring** | Prometheus metrics (`/metrics`) | ✅ |
|  | Adapter health status | ✅ |
| **Dashboard** | Live mappings + search | ✅ |
|  | Conflict management | ✅ |
|  | Alert rules + history | ✅ |
|  | Integration management (Firewall/SIEM/LDAP) | ✅ |
|  | Network management (Subnets/Switches/Fingerprints) | ✅ |

## Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
make secrets
```

Then copy generated secret values into `.env` and set:

- `TRUEID_ADMIN_PASS`
- listener/port overrides (if needed)
- optional TLS/OUI paths

### Required Secrets

| Variable | Description |
|---|---|
| `JWT_SECRET` | JWT signing key for web sessions/API auth |
| `ENGINE_SERVICE_TOKEN` | Shared secret for web-to-engine internal calls |
| `CONFIG_ENCRYPTION_KEY` | AES key for sensitive config at rest |

### Security Notes

- Do not expose engine port `8080` outside internal network.
- Keep `TRUEID_DEV_MODE=false` in production.
- Use TLS termination (reverse proxy or native certs) for secure cookies/session flow.

## Docker Deployment

### Quick Start (Docker)

```bash
# Clone and configure
git clone <repo> && cd TrueID
cp .env.example .env

# Generate secrets
make secrets
# Copy output to .env

# Set initial admin password in .env
# TRUEID_ADMIN_PASS=YourSecurePassword123

# Build and start
make docker-build
make docker-up

# Check status
make docker-status

# View logs
make docker-logs
```

Dashboard: http://localhost:3000

### Ports

| Port | Protocol | Service |
|---|---|---|
| 3000 | TCP | Web dashboard + API |
| 1813 | UDP | RADIUS accounting |
| 5514 | UDP | AD syslog |
| 5516 | UDP | DHCP syslog |
| 5518 | UDP | VPN syslog |

### Backup & Restore

```bash
# Backup
make docker-backup

# Restore (stop services first)
docker compose down
cp backups/backup-YYYYMMDD-HHMMSS.db data/net-identity.db
docker compose up -d
```

## API Reference (summary)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | Public | Login |
| POST | `/api/auth/logout` | Session | Logout |
| GET | `/api/auth/me` | Session | Current user |
| GET | `/api/v1/mappings` | Session/Key | List mappings |
| GET | `/api/v1/stats` | Session/Key | Global stats |
| GET | `/api/v2/search` | Session/Key | Universal search |
| GET | `/api/v2/conflicts` | Session/Key | List conflicts |
| GET | `/api/v2/alerts/rules` | Admin | Alert rules |
| GET | `/api/v2/subnets` | Session/Key | Subnets |
| GET | `/api/v2/switches` | Session/Key | SNMP switches |
| GET | `/api/v2/firewall/targets` | Admin | Firewall targets |
| GET | `/api/v2/siem/targets` | Admin | SIEM targets |
| GET | `/api/v2/ldap/config` | Admin | LDAP config |
| GET | `/api/v2/timeline/ip/{ip}` | Session/Key | IP timeline |
| GET | `/api/v1/audit-logs` | Admin | Audit log |
| GET | `/metrics` | Public | Prometheus metrics |
| GET | `/health` | Public | Health check |

Full API details: inline route documentation (OpenAPI planned).

## Prometheus Monitoring

TrueID exposes Prometheus metrics at `/metrics` (no auth required).

### `prometheus.yml`

```yaml
scrape_configs:
  - job_name: trueid
    scrape_interval: 15s
    static_configs:
      - targets: ['trueid-web:3000']
```

### Available Metrics

| Metric | Type | Description |
|---|---|---|
| `trueid_events_total` | counter | Events by source |
| `trueid_active_mappings` | gauge | Current active mappings |
| `trueid_conflicts_total` | counter | Total conflicts |
| `trueid_alerts_fired_total` | counter | Alerts fired |
| `trueid_firewall_push_total` | counter | Firewall pushes by target |
| `trueid_siem_events_forwarded_total` | counter | SIEM events forwarded |
| `trueid_ldap_sync_users` | gauge | Users synced from LDAP |
| `trueid_uptime_seconds` | gauge | Engine uptime |

## Roles

| Role | Permissions |
|---|---|
| **Admin** | Full access: users, API keys, integrations, audit, settings |
| **Operator** | Operational write paths, mapping/session management |
| **Viewer** | Read-only data exploration and reporting |

## Troubleshooting

| Problem | Solution |
|---|---|
| Web not responding | Check `make docker-status`, then `make docker-logs` |
| DB open/migration errors | Verify `DATABASE_URL` and mounted volume permissions |
| Healthcheck fails | Confirm engine on `:8080`, web on `:3000`, and required secrets |
| Auth/session issues | Ensure HTTPS/TLS config and correct `JWT_SECRET` |

## Integration Guide

See [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) for source-specific integration steps
(TrueID Agent, NXLog, FreeRADIUS, NPS, DHCP variants, VPN syslog inputs, and more).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

TrueID is licensed under the [MIT License](LICENSE).
