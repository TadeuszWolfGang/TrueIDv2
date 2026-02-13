# Deployment Guide

## Docker Quick Start

```bash
cp .env.example .env
make secrets
# Fill generated values in .env (plus TRUEID_ADMIN_PASS)

docker compose build
docker compose up -d
docker compose ps
```

Dashboard: `http://localhost:3000`

## Exposed Ports

| Port | Protocol | Purpose |
|---|---|---|
| 3000 | TCP | Web dashboard + API |
| 1813 | UDP | RADIUS accounting |
| 5514 | UDP | AD syslog |
| 5516 | UDP | DHCP syslog |
| 5518 | UDP | VPN syslog |

## Health Checks

- Engine health check validates SQLite accessibility.
- Web health check calls `GET /health`.
- `web` waits for `engine` healthy via `depends_on.condition: service_healthy`.

## Data Persistence

- Database uses named volume: `trueid-data`.
- Main file inside container: `/app/data/net-identity.db`.

## Backup and Restore

```bash
# Backup
make docker-backup

# Restore
docker compose down
cp backups/<backup-file>.db data/net-identity.db
docker compose up -d
```

## TLS

### Agent mTLS (engine listeners)

Mount certificate directory:

```yaml
volumes:
  - ${TLS_CERT_DIR:-./tls}:/app/tls:ro
```

Optional environment variables:

- `TLS_CA_CERT`
- `TLS_SERVER_CERT`
- `TLS_SERVER_KEY`

### Web HTTPS (optional)

- `WEB_TLS_CERT`
- `WEB_TLS_KEY`

Use reverse proxy termination in production when possible.
