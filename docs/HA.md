# TrueID High Availability

## Architecture Options

### Option A: Active-Standby with Litestream (Recommended)

TrueID uses SQLite, which does not natively support multi-writer replication.
The recommended HA approach is **Litestream** for continuous SQLite replication.

```
                    ┌─────────────┐
                    │   Primary   │
  UDP ──────────►   │   Engine    │──► SQLite ──► Litestream ──► S3/MinIO
  TCP ──────────►   │   + Web     │
                    └─────────────┘
                          │
                          │ replicate
                          ▼
                    ┌─────────────┐
                    │  Standby    │
                    │  (cold)     │◄── Litestream restore
                    └─────────────┘
```

**Setup:**
1. Install Litestream on primary: https://litestream.io
2. Configure continuous replication to S3-compatible storage
3. On failover: restore DB on standby, start services
4. RTO: ~2 minutes (restore + start)
5. RPO: ~1 second (Litestream lag)

**litestream.yml:**
```yaml
dbs:
  - path: /opt/trueid/data/net-identity.db
    replicas:
      - url: s3://trueid-backups/litestream
        retention: 168h  # 7 days
```

### Option B: Load-Balanced Web + Single Engine

For read-heavy workloads, scale the web tier horizontally:

```
                    ┌─────────────┐
  UDP ──────────►   │   Engine    │──► SQLite (single writer)
                    └──────┬──────┘
                           │ read
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐ ┌──────────┐
              │  Web #1  │ │  Web #2  │
              └──────────┘ └──────────┘
                    ▲             ▲
                    └──────┬──────┘
                           │
                    ┌──────────────┐
                    │ Load Balancer│
                    └──────────────┘
```

SQLite WAL mode supports concurrent readers. Multiple web instances
can read from the same database file via shared volume mount.

**Limitations:**
- Engine is still single-instance (single writer)
- Web instances share JWT secret for session portability
- Failover requires manual intervention for engine

### Option C: PostgreSQL Migration (Future)

For true multi-writer HA, migrate from SQLite to PostgreSQL.
This would require:
- Replacing `sqlx::Sqlite` with `sqlx::Postgres` throughout
- Updating migrations to PostgreSQL dialect
- Using PgBouncer for connection pooling
- Standard PostgreSQL HA (streaming replication, Patroni, etc.)

**Estimated effort:** 2-3 weeks for migration + testing.

## Current Limitations

- SQLite is single-writer: only one engine instance can write at a time
- UDP listeners bind to specific ports: only one engine per host
- No built-in leader election or consensus
- Session state is in SQLite: web instances must share the same DB file

## Recommendations

| Deployment Size | Approach | RTO | RPO |
|----------------|----------|-----|-----|
| < 5,000 IPs | Single instance + daily backup | Hours | 24h |
| 5,000-50,000 IPs | Litestream + warm standby | ~2 min | ~1 sec |
| > 50,000 IPs | Consider PostgreSQL migration | Depends | Depends |
