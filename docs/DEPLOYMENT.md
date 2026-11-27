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

### Reverse proxy (nginx)

A sample config is in [`deploy/nginx/trueid.conf`](../deploy/nginx/trueid.conf). It terminates TLS and enables HTTP/2 (`listen 443 ssl http2`).

If you use that sample, or any nginx front end with HTTP/2, run **nginx 1.30.7 or later (stable) or 1.31.9 or later (mainline)**. Official releases 1.9.5-1.31.8 are affected by [CVE-2026-123007](https://www.cve.org/CVERecord?id=CVE-2026-123007) (HTTP/2 flow-control memory corruption, nicknamed nginx2root). The fixes shipped in 1.30.7 and 1.31.9 on 18 November 2026.

See the [nginx security advisories](https://nginx.org/en/security_advisories.html), the [1.30 CHANGES](https://nginx.org/en/CHANGES-1.30) and [mainline CHANGES](https://nginx.org/en/CHANGES), and [CERT Polska advisory 217/2026](https://moje.cert.pl/komunikaty/2026/217/krytyczne-podatnosci-w-serwerze-nginx-umozliwiajace-zdalne-wykonanie-kodu-nginx2root/). After upgrading, fully restart nginx or the container (`reload` is not enough). For distribution packages, compare the full package version with the distro advisory; `nginx -v` may not reflect a backport.
