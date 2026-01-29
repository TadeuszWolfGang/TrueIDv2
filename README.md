# IDsense (net-identity)

## About
IDsense is a real-time Identity Correlation Engine written in Rust. It correlates user
identity across the network using three sources: RADIUS (802.1x), Active Directory
(Kerberos/Syslog), and DHCP.

## Architecture
- UDP Listener: RADIUS (Accounting), Syslog (AD & DHCP)
- Core: Priority logic (RADIUS > AD > DHCP) and confidence scoring
- Storage: SQLite + SQLx
- UI: Vanilla JS real-time dashboard

## Quick Start
### Requirements
- Rust
- Cargo

### Build
```bash
cargo build --release
```

### Run
```bash
cargo run -p net-identity-server
```

## Configuration (.env)
```env
RADIUS_BIND=0.0.0.0:1813
AD_SYSLOG_BIND=0.0.0.0:5514
DHCP_SYSLOG_BIND=0.0.0.0:5516
HTTP_BIND=0.0.0.0:3000
```
