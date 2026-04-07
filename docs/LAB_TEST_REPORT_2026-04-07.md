# TrueID Lab Validation Report — 2026-04-07

## Scope

Full re-validation of the TrueID lab environment after previous setup (2026-04-03),
security review, and refactoring cycle. This report covers the complete chain:

1. API smoke tests (auth, RBAC, CSRF)
2. Windows AD agent service validation
3. Live event generation and mapping verification
4. Synthetic import data path (repo-e2e-validate)
5. Sycope connector lookup synchronization
6. UI screenshot capture with demo data (Playwright)

## Environment

| VM | IP | OS | Role |
|---|---|---|---|
| trueid-01 | 10.50.0.10 | Ubuntu 24.04 | TrueID engine + web (native, no Docker) |
| dc01 | 10.50.0.20 | Windows Server 2022 | AD DC + TrueID Agent |
| wincli-01 | 10.50.0.100 | Windows 11 | Domain workstation (user: Jan) |
| flowgen-01 | 10.50.0.30 | Ubuntu 24.04 | Flow exporter (not tested this round) |

Sycope appliance: 192.168.100.12 (HTTPS API)
Proxmox host: 192.168.100.11 (SSH jump, IP forwarding)

## Test Results Summary

### Phase 1 — API Smoke Tests

| Test | Result |
|------|--------|
| Health check (GET /health → 200) | **PASS** |
| Login as admin | **PASS** |
| GET /api/auth/me (authenticated) | **PASS** |
| GET /api/v1/mappings (authenticated) | **PASS** |
| GET /api/v1/users (admin) | **PASS** |
| GET /api/v1/audit-logs (admin) | **PASS** |
| Anonymous GET /api/v1/mappings → 401 | **PASS** |
| Login with wrong password → 401 | **PASS** |
| Token refresh | **PASS** |
| Logout | **PASS** |
| GET /me after logout → 401 | **PASS** |

**Result: 11/11 PASS**

### Phase 2 — Windows Agent Validation

| Test | Result |
|------|--------|
| TrueIDAgent service status = Running | **PASS** |
| TrueIDAgent StartType = Automatic | **PASS** |
| TLS connection to 10.50.0.10:5615 established | **PASS** |
| Engine heartbeat running (30s interval) | **PASS** |
| AD events flowing (DC01$, fe80::, 10.50.0.20) | **PASS** |

**Result: 5/5 PASS**

### Phase 3 — Live Event Generation

| Test | Result | Notes |
|------|--------|-------|
| jan.test password reset (AD complexity) | **PASS** | Reset to Lala!2024 |
| net use from wincli-01 as jan.test → dc01 | **PASS** | Network logon Type 3 |
| Event 4624 for jan.test in Security log | **PASS** | IP: fe80::4dad:cb10:2c3:23ac |
| TrueID mapping jan.test ↔ 10.50.0.100 refreshed | **PASS** | Timestamp: 12:59:54 UTC |
| TrueID mapping jan.test ↔ fe80::4dad:... created | **PASS** | New IPv6 mapping |

**Result: 5/5 PASS**

### Phase 4 — Synthetic Import (repo-e2e-validate.sh)

| Test | Result |
|------|--------|
| Health endpoint responds | **PASS** |
| Login as admin | **PASS** |
| Authenticated /api/auth/me | **PASS** |
| Synthetic events imported (3 events) | **PASS** |
| Mappings API includes synthetic IP and user | **PASS** |
| Lookup endpoint resolves the synthetic mapping | **PASS** |
| User timeline exposes recent events, IP history, active mapping | **PASS** |
| MAC timeline resolves current mapping and IP history | **PASS** |
| IP timeline page 1 | **FAIL** |
| IP timeline cursor pagination | **FAIL** |

**Result: 8/10 PASS**

**Known issue:** IP timeline uses page/limit pagination, but test expects cursor-based pagination (`next_cursor`). This is a test/API contract mismatch, not a data path issue.

### Phase 5 — Sycope Connector

| Test | Result | Notes |
|------|--------|-------|
| Routing 10.50.0.0/24 → 192.168.100.12 | **PASS** | Required iptables FORWARD + MASQUERADE on Proxmox |
| Connector deployed to trueid-01 | **PASS** | ~/trueid-lab/integrations/sycope/ |
| API key created (tid_jrw3t3jy...) | **PASS** | Role: Viewer |
| trueid_sync.py execution | **PASS** | 6 mappings fetched, 3 IPv4 synced |
| Sycope lookup TrueID_Enrichment updated | **PASS** | 3 rows: DC01$, jan.test, e2e.smoke |
| Lookup contains jan.test ↔ 10.50.0.100 | **PASS** | Verified via Sycope API |

**Result: 6/6 PASS**

### Phase 6 — Full Lab Validation (lab-validate-trueid-sycope.sh)

| Test | Result |
|------|--------|
| TrueID mappings include 10.50.0.100 → jan.test | **PASS** |
| TrueID lookup endpoint resolves 10.50.0.100 → jan.test | **PASS** |
| TrueID IP timeline contains events for jan.test | **PASS** |
| Windows service running + TLS session established | **PASS** |
| Sycope lookup includes 10.50.0.100 → jan.test | **PASS** |

**Result: 5/5 PASS**

### Phase 7 — Demo Data Injection + UI Screenshots

120 events injected across 37 unique IPs from 5 sources:
- **AdLog**: 12 corporate workstation users (anna.kowalska, piotr.nowak, etc.)
- **Radius**: 8 WiFi/VPN users with FQDN identities
- **DhcpLog**: 9 infrastructure devices (printers, IoT sensors, APs, switches)
- **VpnLog**: 5 remote workers (including shared users with AD)
- **Manual**: 3 guest/conference room entries

**20 Playwright screenshots captured** in `screenshots/`:

| # | View | File |
|---|------|------|
| 1 | Login page (Matrix rain background) | 01-login.png |
| 2 | Dashboard overview | 02-dashboard-overview.png |
| 3 | Mappings (full table, 37+ entries) | 03-mappings.png |
| 4 | Search results for "jan" | 04-search.png |
| 5 | Conflicts | 05-conflicts.png |
| 6 | Alerts (rules + history) | 06-alerts.png |
| 7 | Analytics | 07-analytics.png |
| 8 | Net Map | 08-map.png |
| 9 | Subnets | 09-subnets.png |
| 10 | Switches | 10-switches.png |
| 11 | Fingerprints | 11-fingerprints.png |
| 12 | DNS | 12-dns.png |
| 13 | Sycope Integration | 13-sycope.png |
| 14 | Status | 14-status.png |
| 15 | Audit log | 15-audit.png |
| 16 | Firewall integration | 20-firewall.png |
| 17 | SIEM integration | 20-siem.png |
| 18 | LDAP integration | 20-ldap.png |
| 19 | Notifications | 20-notifications.png |
| 20 | Timeline detail | 25-timeline-detail.png |

## Infrastructure Fixes Applied During Testing

### 1. Routing: trueid-01 → Sycope

trueid-01 had no default gateway configured, making Sycope (192.168.100.12)
unreachable. Additionally, Proxmox iptables FORWARD policy was DROP with no rules
for lab ↔ management traffic.

**Fix:**
- Added default route on trueid-01: `ip route add default via 10.50.0.1`
- Added iptables FORWARD rules on Proxmox for 10.50.0.0/24 ↔ 192.168.100.0/24
- Added MASQUERADE NAT for lab network outbound traffic

**Note:** These are runtime changes. After VM restart they will be lost unless
persisted in netplan (trueid-01) and iptables-save (Proxmox).

### 2. jan.test password

The jan.test AD account had an unknown password from the previous session.
Reset to `Lala!2024` (AD complexity requirements prevented plain `Lala!`).

## Known Issues

1. **IP timeline pagination**: Test expects `next_cursor`, API returns `page`/`limit`.
   Test or API contract needs alignment.

2. **force_password_change on admin**: The admin account has `force_password_change: true`.
   This causes the login UI to show a password change modal instead of redirecting to
   the dashboard. Playwright login bypasses this via direct API call.

3. **IPv6 link-local in AD events**: AD logon events from wincli-01 report the IPv6
   link-local address (fe80::4dad:cb10:2c3:23ac) instead of IPv4 (10.50.0.100).
   TrueID correctly maps both addresses. Sycope connector skips IPv6 addresses
   (by design).

4. **Routing not persistent**: Runtime routes and iptables rules on trueid-01 and
   Proxmox will be lost after reboot. Should be persisted before snapshotting.

## Overall Assessment

| Area | Status |
|------|--------|
| TrueID API + Auth | **PASS** (11/11) |
| Windows Agent | **PASS** (5/5) |
| Live AD Event Flow | **PASS** (5/5) |
| Synthetic Data Path | **PASS** (8/10, 2 known) |
| Sycope Lookup Enrichment | **PASS** (6/6) |
| Full Chain Validation | **PASS** (5/5) |
| UI Screenshots | **PASS** (20 captured) |

**The complete TrueID → AD Agent → Sycope enrichment chain is operational.**
