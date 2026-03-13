# TrueID Integration Guide

> **Note:** Configuration examples are based on source code analysis and vendor documentation. Always verify ports, paths, field names, and Event IDs against your actual infrastructure before deploying. If you find errors or missing steps, please [open an issue](../../issues) or submit a PR.

Step-by-step configuration of upstream data sources — Active Directory, RADIUS and DHCP — to forward identity events to the TrueID engine.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [TrueID Agent (Recommended for Windows)](#3-trueid-agent-recommended-for-windows)
4. [Active Directory — NXLog CE](#4-active-directory--nxlog-ce)
5. [RADIUS — FreeRADIUS](#5-radius--freeradius)
6. [RADIUS — Microsoft NPS](#6-radius--microsoft-nps)
7. [DHCP — ISC DHCP + rsyslog (Linux)](#7-dhcp--isc-dhcp--rsyslog-linux)
8. [DHCP — Kea DHCP + rsyslog](#8-dhcp--kea-dhcp--rsyslog)
9. [DHCP — Windows DHCP Server + NXLog](#9-dhcp--windows-dhcp-server--nxlog)
10. [Verification & Troubleshooting](#10-verification--troubleshooting)
11. [Security: TLS Transport (Optional)](#11-security-tls-transport-optional)

---

## 1. Architecture Overview

```
  Data Sources                      TrueID Engine Adapters
  ────────────                      ──────────────────────

  Domain Controller (AD)
  ┌─ Option A: TrueID Agent  ──►   AD TLS Listener    TCP :5615 (TLS)
  └─ Option B: NXLog CE      ──►   AD Syslog Adapter  UDP/TCP :5514

  RADIUS Server
     FreeRADIUS / NPS         ──►   RADIUS Adapter     UDP :1813

  DHCP Server
  ┌─ Option A: TrueID Agent  ──►   DHCP TLS Listener  TCP :5617 (TLS)
  ├─ Option B: rsyslog        ──►   DHCP Syslog Adapter UDP :5516
  └─ Option C: NXLog CE      ──►   DHCP Syslog Adapter UDP :5516
```

TrueID engine exposes five listeners — three legacy (UDP/TCP) and two TLS:

| Listener | Default Port | Protocol | Expected Input |
|----------|-------------|----------|----------------|
| AD Syslog | UDP/TCP **5514** | Syslog (JSON or text) | Windows Security events **4624** (Logon) and **4768** (Kerberos TGT) containing `TargetUserName` and `IpAddress` fields |
| AD TLS | TCP **5615** | TLS + RFC 5425 | `TrueID-Agent: AD_LOGON user=... ip=... event_id=... status=...` (from TrueID Agent) |
| RADIUS | UDP **1813** | Native RADIUS | Standard **Accounting-Request** packets (RFC 2866) with `User-Name` and `Framed-IP-Address` attributes |
| DHCP Syslog | UDP **5516** | Syslog (text) | ISC dhcpd–style `DHCPACK on <ip> to <mac>` messages |
| DHCP TLS | TCP **5617** | TLS + RFC 5425 | `TrueID-Agent: DHCP_LEASE ip=... mac=... hostname=... lease=...` (from TrueID Agent) |

All ports are configurable via `.env`:

```env
# Legacy syslog adapters (NXLog / rsyslog)
AD_SYSLOG_BIND=0.0.0.0:5514
DHCP_SYSLOG_BIND=0.0.0.0:5516
RADIUS_BIND=0.0.0.0:1813
RADIUS_SECRET=YourSharedSecret

# TLS listeners (TrueID Agent) — enabled automatically when cert files exist
AD_TLS_BIND=0.0.0.0:5615
DHCP_TLS_BIND=0.0.0.0:5617
TLS_CA_CERT=./certs/ca.pem
TLS_SERVER_CERT=./certs/server.pem
TLS_SERVER_KEY=./certs/server-key.pem
```

---

## 2. Prerequisites

Before configuring any data source, make sure:

1. TrueID engine is running and reachable from the source host:

```bash
# On TrueID server
cargo run -p trueid-engine
# or
./target/release/trueid-engine
```

2. Firewall rules allow the relevant ports (see table above) from source hosts to TrueID.

3. For RADIUS: you have a shared secret string ready (same on NAS/proxy and TrueID).

4. For TLS transport (optional): TLS certificates are in place (see [Section 11](#11-security-tls-transport-optional)).

---

## 3. TrueID Agent (Recommended for Windows)

The **TrueID Agent** (`net-identity-agent`) is a native Rust binary that runs directly on Windows Domain Controllers and/or Windows DHCP Servers. It replaces the need for NXLog, rsyslog, or any other third-party log forwarder on Windows hosts.

### 3.1 Why Use the Agent Instead of NXLog

| Feature | TrueID Agent | NXLog CE + syslog |
|---------|-------------|-------------------|
| Install complexity | Single binary + `config.toml` | MSI + XML config, syslog formatting |
| Transport | **TCP + mutual TLS** (encrypted, authenticated) | UDP syslog (plaintext by default) |
| Offline buffering | Built-in **ring buffer** — events queued when server is down, flushed on reconnect | Lost on UDP; TCP blocks on disconnect |
| Reconnect | Automatic **exponential backoff** (5s → 60s max) | Depends on module; UDP has no reconnect |
| Heartbeats | Sends health status every 60s (hostname, uptime, events sent/dropped) | Not available |
| Event parsing | Native Windows Event Log API (`EvtSubscribe`) — real-time, zero-copy XML | NXLog `im_msvistalog` — similar, but extra serialization step |
| Windows Service | Built-in `install` / `uninstall` subcommands | Separate MSI service |
| Covers | AD **and** DHCP in one binary (mode: `ad`, `dhcp`, `both`) | Separate configs per source |
| RADIUS | Not applicable — RADIUS uses native UDP protocol, not syslog | Not applicable |

**Use the Agent** when the source host is Windows and you want encrypted transport with zero third-party dependencies.

**Use NXLog/rsyslog** when you need a proven, widely-deployed tool, when the source is Linux, or when corporate policy mandates a specific log shipper.

> **Note:** RADIUS integration does not use the agent — RADIUS devices (switches, APs, VPN concentrators) send native RADIUS Accounting-Request packets directly to TrueID on port 1813. See [Section 5](#5-radius--freeradius) and [Section 6](#6-radius--microsoft-nps).

### 3.2 Architecture with Agent

```
  Windows DC / DHCP Server              TrueID Engine
  ────────────────────────              ──────────────

  ┌──────────────────────┐              ┌──────────────────────┐
  │  Windows Event Log   │              │                      │
  │  (Security / DHCP)   │              │  AD TLS Listener     │
  │         │            │     TLS      │  TCP :5615           │
  │    EvtSubscribe      │────────────► │                      │
  │         │            │              ├──────────────────────┤
  │  ┌──────────────┐   │              │                      │
  │  │ TrueID Agent │   │     TLS      │  DHCP TLS Listener   │
  │  │ (service)    │───│────────────► │  TCP :5617           │
  │  └──────────────┘   │              │                      │
  │    Ring buffer       │              │  Heartbeat handler   │
  │    Heartbeat 60s     │              │  Agent status in DB  │
  └──────────────────────┘              └──────────────────────┘
```

The agent subscribes to the Windows Event Log in real time, parses XML events, formats them as structured syslog messages prefixed with `TrueID-Agent:`, wraps them in RFC 5425 octet-counted frames, and sends them over mutual TLS to the engine.

### 3.3 Build the Agent

The agent is part of the TrueID monorepo. Build it with:

```bash
# From the TrueID project root
cargo build --release -p net-identity-agent
```

The resulting binary is at `target/release/net-identity-agent.exe` (Windows) or `target/release/net-identity-agent` (cross-compile target).

> **Cross-compilation for Windows** (from a Linux build host):
> ```bash
> rustup target add x86_64-pc-windows-gnu
> cargo build --release -p net-identity-agent --target x86_64-pc-windows-gnu
> ```

### 3.4 Generate TLS Certificates

The agent requires mutual TLS — both the server and the agent authenticate each other with certificates signed by the same CA.

**On the TrueID server** (or any PKI workstation):

```bash
cd certs/

# 1. Create a CA (one-time, shared by server + all agents)
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout ca-key.pem -out ca.pem \
    -subj "/CN=TrueID CA"

# 2. Server certificate (for the TrueID engine)
openssl req -newkey rsa:4096 -nodes \
    -keyout server-key.pem -out server.csr \
    -subj "/CN=trueid-server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365

# 3. Agent certificate (one per Windows host)
openssl req -newkey rsa:4096 -nodes \
    -keyout agent-dc01-key.pem -out agent-dc01.csr \
    -subj "/CN=DC01"
openssl x509 -req -in agent-dc01.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out agent-dc01.pem -days 365
```

Copy to the Windows host:
- `ca.pem` → `C:\TrueID\certs\ca.pem`
- `agent-dc01.pem` → `C:\TrueID\certs\agent.pem`
- `agent-dc01-key.pem` → `C:\TrueID\certs\agent-key.pem`

Copy to the TrueID server:
- `ca.pem` → `./certs/ca.pem`
- `server.pem` → `./certs/server.pem`
- `server-key.pem` → `./certs/server-key.pem`

### 3.5 Enable TLS Listeners on the Engine

In TrueID's `.env` (server side):

```env
TLS_CA_CERT=./certs/ca.pem
TLS_SERVER_CERT=./certs/server.pem
TLS_SERVER_KEY=./certs/server-key.pem
AD_TLS_BIND=0.0.0.0:5615
DHCP_TLS_BIND=0.0.0.0:5617
```

Restart the engine. When all three cert files exist, TLS listeners start automatically:

```
INFO TLS syslog listener started bind_addr=0.0.0.0:5615 label="AD-TLS"
INFO TLS syslog listener started bind_addr=0.0.0.0:5617 label="DHCP-TLS"
```

### 3.6 Configure the Agent (`config.toml`)

Create `C:\TrueID\config.toml` on the Windows host:

```toml
# ─── TrueID Agent Configuration ───

[target]
# TrueID engine hostname or IP
server = "trueid.example.com"
# Ports must match engine's AD_TLS_BIND / DHCP_TLS_BIND
ad_port = 5615
dhcp_port = 5617

[tls]
ca_cert     = "C:\\TrueID\\certs\\ca.pem"
client_cert = "C:\\TrueID\\certs\\agent.pem"
client_key  = "C:\\TrueID\\certs\\agent-key.pem"

[agent]
# Mode: "ad", "dhcp", or "both"
#   ad   — collect AD Security events (4624, 4625, 4768, 4769, 4770)
#   dhcp — collect Windows DHCP Server events (10, 11, 12, 15)
#   both — collect both AD and DHCP events
mode = "ad"

# Optional: override system hostname (used in syslog headers and heartbeats)
# hostname = "DC01"

# Ring buffer capacity — events buffered when TrueID is unreachable
buffer_size = 1000

[connection]
# Seconds between reconnect attempts (exponential backoff, max 60s)
reconnect_interval_secs = 5
# TCP keepalive interval
keepalive_secs = 30
```

**Mode selection guide:**

| Host Role | Set `mode` to |
|-----------|---------------|
| Domain Controller only | `"ad"` |
| Windows DHCP Server only | `"dhcp"` |
| DC that also runs DHCP Server | `"both"` |

### 3.7 Collected Event IDs

**AD mode** subscribes to the Security event log:

| Event ID | Name | Extracted Fields |
|----------|------|-----------------|
| **4624** | Successful logon | `TargetUserName`, `IpAddress`, `IpPort`, `Status` |
| **4625** | Failed logon | `TargetUserName`, `IpAddress`, `IpPort`, `Status` |
| **4768** | Kerberos TGT requested | `TargetUserName`, `IpAddress`, `IpPort`, `Status` |
| **4769** | Kerberos service ticket requested | `TargetUserName`, `IpAddress`, `IpPort`, `Status` |
| **4770** | Kerberos service ticket renewed | `TargetUserName`, `IpAddress`, `IpPort`, `Status` |

The agent uses the Windows `EvtSubscribe` API with `EvtSubscribeToFutureEvents` — it subscribes in real time and processes only new events (no backlog on startup).

IPv4-mapped IPv6 addresses (e.g., `::ffff:10.0.1.42`) are automatically stripped to `10.0.1.42`.

**DHCP mode** subscribes to `Microsoft-Windows-DHCP-Server/Operational`:

| Event ID | Name | Extracted Fields |
|----------|------|-----------------|
| **10** | New lease | `IPAddress`, `MACAddress`, `HostName`, `LeaseDuration` |
| **11** | Lease renewed | `IPAddress`, `MACAddress`, `HostName`, `LeaseDuration` |
| **12** | Lease released | `IPAddress`, `MACAddress`, `HostName`, `LeaseDuration` |
| **15** | Lease denied (NACK) | `IPAddress`, `MACAddress`, `HostName`, `LeaseDuration` |

### 3.8 Syslog Wire Format

The agent formats events as syslog messages and wraps them in RFC 5425 octet-counted frames for reliable TCP transport:

**AD event:**
```
<13>Feb  7 14:22:05 DC01 TrueID-Agent: AD_LOGON user=jan.kowalski ip=10.0.1.42 port=52431 event_id=4768 status=0x0
```

**DHCP event:**
```
<13>Feb  7 14:22:05 DHCP01 TrueID-Agent: DHCP_LEASE ip=10.0.1.42 mac=00:1A:2B:3C:4D:5E hostname=LAPTOP-JAN lease=86400
```

**Heartbeat (every 60 seconds):**
```
<13>Feb  7 14:23:05 DC01 TrueID-Agent: HEARTBEAT hostname=DC01 uptime=3600 events_sent=142 events_dropped=0 transport=tls
```

Each message is framed as: `<length> <payload>\n` (e.g., `128 <13>Feb  7 ...`).

The engine parses these on the TLS listeners (ports 5615/5617), extracts identity data, and processes heartbeats to track agent health in the database.

### 3.9 Test in Dry-Run Mode

Before deploying with TLS, test event parsing locally on the Windows host:

```powershell
cd C:\TrueID
.\net-identity-agent.exe -c config.toml run --dry-run
```

Dry-run mode does **not** connect to the server — it prints sample formatted syslog messages to the console so you can verify parsing works:

```
INFO Sample AD syslog:   <13>Feb  7 14:22:05 DC01 TrueID-Agent: AD_LOGON user=jan.kowalski ip=10.0.1.50 port=52431 event_id=4768 status=0x0
INFO Sample DHCP syslog: <13>Feb  7 14:22:05 DC01 TrueID-Agent: DHCP_LEASE ip=10.0.1.50 mac=AA:BB:CC:DD:EE:FF hostname=WORKSTATION01 lease=86400
INFO Dry-run complete. Press Ctrl+C to exit.
```

### 3.10 Run Interactively (Console Mode)

For testing with a live TLS connection:

```powershell
cd C:\TrueID
.\net-identity-agent.exe -c config.toml run
```

The agent will:
1. Load `config.toml`
2. Connect to the TrueID engine via TLS
3. Subscribe to Windows Event Log in real time
4. Forward events as they occur
5. Send heartbeats every 60 seconds
6. Buffer events if the connection drops, flush on reconnect

Check the console for:
```
INFO Starting agent hostname="DC01" mode=Ad
INFO TLS connection established server="trueid.example.com" port=5615
INFO Subscribed to event log channel="Security"
INFO Agent running — press Ctrl+C to stop
INFO Sending heartbeat uptime=60 sent=3 dropped=0
```

### 3.11 Install as a Windows Service

For production, register the agent as an auto-starting Windows Service:

```powershell
# Install (registers "TrueIDAgent" service with AutoStart)
.\net-identity-agent.exe -c C:\TrueID\config.toml install

# Start the service
Start-Service TrueIDAgent

# Verify it's running
Get-Service TrueIDAgent
```

The service name is **TrueIDAgent**, display name **TrueID Identity Agent**. It starts automatically on boot.

**Manage the service:**

```powershell
# Stop
Stop-Service TrueIDAgent

# Restart
Restart-Service TrueIDAgent

# View service status
Get-Service TrueIDAgent | Format-List *

# Uninstall (remove the service)
Stop-Service TrueIDAgent
.\net-identity-agent.exe -c C:\TrueID\config.toml uninstall
```

### 3.12 Enable Audit Policies (Same as NXLog)

The agent reads the same Windows Event Log as NXLog — the same audit policies must be enabled on the Domain Controller. See [Section 4.2](#42-enable-audit-policies-on-the-domain-controller) for full instructions.

Quick version:

```
# Group Policy → Domain Controllers OU:
Computer Configuration → Policies → Windows Settings → Security Settings
  → Advanced Audit Policy Configuration → Audit Policies:
    Logon/Logoff → Audit Logon: Success
    Account Logon → Audit Kerberos Authentication Service: Success
```

### 3.13 Multi-Host Deployment

Install the agent on **every Windows host** that is a data source:

| Host | `mode` | Cert CN | Connects to |
|------|--------|---------|-------------|
| DC01 | `ad` | `DC01` | `:5615` |
| DC02 | `ad` | `DC02` | `:5615` |
| DHCP01 | `dhcp` | `DHCP01` | `:5617` |
| DC03 (also runs DHCP) | `both` | `DC03` | `:5615` + `:5617` |

Each host gets its own client certificate (signed by the same CA). The engine accepts unlimited concurrent TLS connections.

Agent health is visible on the TrueID dashboard — the engine stores heartbeat data (hostname, uptime, events sent/dropped, last seen) in the database for each connected agent.

### 3.14 Troubleshooting the Agent

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `TLS connect failed` | Cert files missing or wrong path | Verify paths in `config.toml` `[tls]` section |
| `TLS handshake` error | CA mismatch — agent cert not signed by engine's CA | Re-sign agent cert with same `ca.pem` |
| `EvtSubscribe failed` | Agent not running as Administrator / SYSTEM | Run as admin or install as service (runs as SYSTEM) |
| Events parsed but `IpAddress` is empty | Local/service logons (LogonType 5) have no IP | Expected behavior — TrueID ignores events without valid IP |
| `events_dropped > 0` in heartbeat | Buffer overflow — TrueID was unreachable longer than buffer allows | Increase `buffer_size` in `config.toml` |
| Service won't start | `config.toml` path wrong in service registration | Uninstall and re-install with correct `-c` path |
| No heartbeats on dashboard | Firewall blocking port 5615/5617 | Open TCP ports on firewall between agent and engine |

**Enable debug logging** on the agent:

```powershell
$env:RUST_LOG = "debug"
.\net-identity-agent.exe -c config.toml run
```

---

## 4. Active Directory — NXLog CE

> **Alternative:** If you prefer encrypted transport without third-party software, use the [TrueID Agent](#3-trueid-agent-recommended-for-windows) instead of NXLog. The agent covers both AD and DHCP from a single binary with built-in TLS, buffering, and heartbeats.

NXLog Community Edition runs on the Domain Controller (or a Windows Event Collector) and forwards Security event log entries to TrueID's AD syslog adapter on port **5514**.

### 4.1 Which Events TrueID Needs

TrueID parses two Windows Security Event IDs:

| Event ID | Name | What TrueID extracts |
|----------|------|----------------------|
| **4624** | An account was successfully logged on | `TargetUserName`, `IpAddress` (from `EventData`) |
| **4768** | A Kerberos authentication ticket (TGT) was requested | `TargetUserName`, `IpAddress` (from `EventData`) |

Both events are generated by the **Microsoft-Windows-Security-Auditing** provider on Domain Controllers.

### 4.2 Enable Audit Policies on the Domain Controller

Before NXLog can forward these events, the audit policies must be enabled on every DC.

**Option A — Group Policy (recommended for multiple DCs):**

1. Open **Group Policy Management** → edit the GPO linked to the **Domain Controllers** OU.
2. Navigate to: `Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`
3. Enable:
   - `Logon/Logoff → Audit Logon` → **Success**
   - `Account Logon → Audit Kerberos Authentication Service` → **Success**
4. Run `gpupdate /force` on each DC, or wait for replication.

**Option B — Local Security Policy (single DC / lab):**

```
secpol.msc → Local Policies → Audit Policy
  → Audit logon events: Success
  → Audit account logon events: Success
```

**Verify events are being generated:**

```powershell
# Should return recent 4624/4768 events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4768} -MaxEvents 5
```

> **Windows Server version notes:**
> - **Windows Server 2016/2019/2022/2025** — Use `Advanced Audit Policy Configuration` (granular sub-categories). The `im_msvistalog` NXLog module is the correct choice.
> - **Windows Server 2012 R2** — Same approach works, but NXLog CE ≥ 2.10 is required for full `im_msvistalog` support. Older NXLog versions should use `im_msvistalog` (not the deprecated `im_mseventlog`).
> - **Windows Server 2008 R2** — Supported but end-of-life. Use `im_msvistalog`. The Event IDs are the same (4624, 4768). Consider upgrading.

### 4.3 Install NXLog Community Edition

1. Download NXLog CE from [https://nxlog.co/products/nxlog-community-edition/download](https://nxlog.co/products/nxlog-community-edition/download)
2. Run the MSI installer with defaults (installs to `C:\Program Files\nxlog\`).
3. The configuration file lives at: `C:\Program Files\nxlog\conf\nxlog.conf`

### 4.4 NXLog Configuration — JSON Format (Recommended)

This configuration forwards events 4624 and 4768 in **JSON format** via UDP syslog to TrueID. JSON is the preferred format because it preserves all `EventData` fields with their names.

Edit `C:\Program Files\nxlog\conf\nxlog.conf`:

```xml
## TrueID — Forward AD logon events as JSON syslog
## Destination: TrueID engine AD adapter (UDP 5514)

define ROOT     C:\Program Files\nxlog
define CERTDIR  %ROOT%\cert
define CONFDIR  %ROOT%\conf
define LOGDIR   %ROOT%\data
define LOGFILE  %LOGDIR%\nxlog.log
LogFile %LOGFILE%

Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data

<Extension _syslog>
    Module  xm_syslog
</Extension>

<Extension _json>
    Module  xm_json
</Extension>

<Input eventlog_security>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">
                    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing']
                    and (EventID=4624 or EventID=4768)]]
                </Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output trueid_udp>
    Module  om_udp
    Host    TRUEID_SERVER_IP
    Port    5514
    Exec    delete($Message); to_json();
</Output>

<Route trueid_route>
    Path    eventlog_security => trueid_udp
</Route>
```

> **Replace `TRUEID_SERVER_IP`** with the actual IP address or hostname of your TrueID server.

**What this does:**
- `im_msvistalog` reads the Windows Security log, pre-filtered to only events 4624 and 4768.
- `delete($Message)` removes the verbose human-readable description (saves bandwidth).
- `to_json()` serializes the event as a flat JSON object containing fields like `EventID`, `TargetUserName`, `IpAddress`, etc.
- `om_udp` sends each event as a UDP datagram to TrueID port 5514.

**Example JSON payload TrueID receives:**

```json
{
  "EventTime": "2026-02-07T14:22:05.439877+01:00",
  "Hostname": "DC01",
  "EventID": 4624,
  "SourceName": "Microsoft-Windows-Security-Auditing",
  "TargetUserName": "jan.kowalski",
  "TargetDomainName": "FIRMA",
  "IpAddress": "10.0.1.42",
  "LogonType": 3,
  "Channel": "Security"
}
```

### 4.5 NXLog Configuration — TCP Transport (Reliable Delivery)

If you need guaranteed delivery (no dropped events over UDP), use TCP instead:

```xml
<Output trueid_tcp>
    Module  om_tcp
    Host    TRUEID_SERVER_IP
    Port    5514
    Exec    delete($Message); to_json();
</Output>

<Route trueid_route>
    Path    eventlog_security => trueid_tcp
</Route>
```

TrueID's AD adapter listens on both UDP and TCP on the same port (5514).

### 4.6 NXLog Configuration — Text/Syslog Format (Alternative)

If JSON is not suitable, TrueID also parses plain-text syslog containing key-value pairs:

```xml
<Output trueid_udp_text>
    Module  om_udp
    Host    TRUEID_SERVER_IP
    Port    5514
    Exec    to_syslog_bsd();
</Output>
```

TrueID's parser extracts `EventID=...`, `TargetUserName=...`, and `IpAddress=...` from the text payload using key-value scanning. JSON is preferred because it handles edge cases (spaces, special characters) more reliably.

### 4.7 Restart NXLog and Verify

```powershell
# Restart the service
Restart-Service nxlog

# Check NXLog log for errors
Get-Content "C:\Program Files\nxlog\data\nxlog.log" -Tail 20

# Verify events are flowing (on TrueID server)
# Look for "AD syslog" entries in the engine log output
```

### 4.8 Multi-DC Deployment

Install and configure NXLog on **every Domain Controller**. All DCs can point to the same TrueID server. TrueID deduplicates by IP address — if the same user logs on to multiple DCs, the most recent mapping wins.

For centralized collection, you can alternatively use **Windows Event Forwarding (WEF)** to aggregate all Security events on a single Windows Event Collector, and install NXLog only on that collector:

```
DC01 ─┐                    ┌───────────────┐
DC02 ─┤──► WEF Collector ──┤  NXLog CE     ├──► TrueID :5514
DC03 ─┘   (ForwardedEvents)│               │
                            └───────────────┘
```

In that case, change the NXLog `<Input>` to read from `ForwardedEvents`:

```xml
<Input eventlog_forwarded>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="ForwardedEvents">
                    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing']
                    and (EventID=4624 or EventID=4768)]]
                </Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>
```

---

## 5. RADIUS — FreeRADIUS

Configure FreeRADIUS to forward (proxy) RADIUS Accounting-Request packets to TrueID on port **1813**. This is the most common setup for Linux-based RADIUS servers used with 802.1X, VPN, or Wi-Fi authentication.

TrueID acts as a RADIUS accounting server — it receives standard `Accounting-Request` packets and extracts `User-Name` + `Framed-IP-Address`.

### 5.1 FreeRADIUS 3.x Configuration

FreeRADIUS 3.x is the most widely deployed version (default on Ubuntu 22.04/24.04, RHEL 8/9, Debian 11/12).

**Step 1 — Define TrueID as a home server**

Edit `/etc/freeradius/3.0/proxy.conf` (or `/etc/raddb/proxy.conf` on RHEL):

```
home_server trueid {
    type       = acct
    ipaddr     = TRUEID_SERVER_IP
    port       = 1813
    secret     = YourSharedSecret
    response_window = 10
    zombie_period   = 30
    revive_interval = 60
}

home_server_pool trueid_pool {
    type            = fail-over
    home_server     = trueid
}

realm trueid_acct {
    acct_pool = trueid_pool
}
```

**Step 2 — Forward accounting to TrueID**

Edit `/etc/freeradius/3.0/sites-enabled/default`, in the `accounting` section add:

```
accounting {
    # ... existing accounting handlers ...

    # Forward a copy to TrueID
    update control {
        &Proxy-To-Realm := "trueid_acct"
    }
}
```

Alternatively, for **replication** (fire-and-forget, no response expected), add to `proxy.conf`:

```
home_server trueid {
    type       = acct
    ipaddr     = TRUEID_SERVER_IP
    port       = 1813
    secret     = YourSharedSecret
    response_window = 10
}

# In the virtual server, use the replicate section:
# accounting {
#     linelog          # local logging
#     replicate        # send copy to TrueID
# }
```

**Step 3 — Set the shared secret on TrueID**

In TrueID's `.env` file:

```env
RADIUS_BIND=0.0.0.0:1813
RADIUS_SECRET=YourSharedSecret
```

The shared secret **must match** on both FreeRADIUS and TrueID.

**Step 4 — Restart and test**

```bash
# Restart FreeRADIUS
sudo systemctl restart freeradius

# Check for errors
sudo journalctl -u freeradius --since "1 minute ago"

# Send a test accounting packet (from a machine with radclient installed)
echo "User-Name = testuser
Framed-IP-Address = 10.0.1.100
Acct-Status-Type = Start
Acct-Session-Id = test-session-001" | radclient -x TRUEID_SERVER_IP:1813 acct YourSharedSecret
```

If TrueID receives it, you'll see in the engine log:

```
INFO: Vendor lookup result mac=None vendor=None ip=10.0.1.100
```

### 5.2 FreeRADIUS 4.x Differences

FreeRADIUS 4.x (currently in release candidate stage) has a significantly different configuration syntax.

**Key changes from 3.x:**

| Aspect | FreeRADIUS 3.x | FreeRADIUS 4.x |
|--------|---------------|---------------|
| Config syntax | `home_server` + `proxy.conf` | `radius` module in `mods-enabled/` |
| Proxying | Single destination only | Multiple destinations natively |
| Replication | Special `replicate` section | `replicate = yes` in module config |
| Attribute syntax | `User-Name` | `&User-Name` (ampersand prefix) |

**FreeRADIUS 4.x configuration:**

Create `/etc/freeradius/mods-enabled/trueid`:

```
radius trueid_acct {
    transport = udp

    type = Accounting-Request

    udp {
        ipaddr    = TRUEID_SERVER_IP
        port      = 1813
        secret    = YourSharedSecret
    }

    # Fire-and-forget: don't wait for TrueID's response
    replicate = yes
}
```

Then in your virtual server's `accounting` section:

```
recv Accounting-Request {
    # ... existing processing ...

    trueid_acct
}
```

### 5.3 RADIUS Attributes Used by TrueID

TrueID extracts exactly two RADIUS attributes from Accounting-Request packets:

| Attribute | RFC | Description |
|-----------|-----|-------------|
| `User-Name` (1) | RFC 2865 | The authenticated user identity (e.g., `jan.kowalski` or `FIRMA\jan.kowalski`) |
| `Framed-IP-Address` (8) | RFC 2865 | The IP address assigned to the user's session |

Both attributes **must** be present in the Accounting-Request. Packets missing either attribute are logged as errors and discarded.

The `Acct-Status-Type` is not checked — TrueID processes Start, Interim-Update, and Stop equally (it always takes the latest mapping).

---

## 6. RADIUS — Microsoft NPS

Microsoft Network Policy Server (NPS) can forward RADIUS accounting to TrueID. NPS is available on Windows Server 2016, 2019, 2022, and 2025.

### 6.1 Install the NPS Role

If NPS is not already installed:

```powershell
Install-WindowsFeature NPAS -IncludeManagementTools
```

Or via Server Manager: **Add Roles → Network Policy and Access Services**.

### 6.2 Configure TrueID as a Remote RADIUS Server

1. Open **Network Policy Server** console (`nps.msc`).
2. Expand **RADIUS Clients and Servers** → right-click **Remote RADIUS Server Groups** → **New**.
3. Group name: `TrueID`
4. Click **Add** to add a server:
   - **Server**: `TRUEID_SERVER_IP`
   - **Authentication/Accounting** tab:
     - Shared secret: `YourSharedSecret` (must match TrueID's `RADIUS_SECRET`)
     - Authentication port: `1812` (not used, but required)
     - Accounting port: `1813`
   - **Load Balancing** tab:
     - Increase timeout to **10 seconds**
5. Click **OK** to save.

### 6.3 Create a Connection Request Policy

1. Expand **Policies** → right-click **Connection Request Policies** → **New**.
2. Policy name: `Forward Accounting to TrueID`
3. **Conditions** tab: Add condition **Day and Time Restrictions** → select **All days, all times**.
4. **Settings** tab:
   - **Authentication**: `Forward requests to the following remote RADIUS server group for authentication` → select `TrueID`
   - **Accounting**: Check `Forward accounting requests to this remote RADIUS server group` → select `TrueID`
5. Click **Finish**.

> **Note:** If you want NPS to continue handling authentication locally and only forward accounting, configure the policy to authenticate locally but forward accounting to TrueID.

### 6.4 Windows Server Version Differences

| Version | Notes |
|---------|-------|
| **Windows Server 2025** | Full support. NPS console is under **Tools** in Server Manager. NPAS role name. |
| **Windows Server 2022** | Full support. Same as 2025. |
| **Windows Server 2019** | Full support. Identical configuration. |
| **Windows Server 2016** | Full support. Supports IP range-based RADIUS clients (Datacenter edition only). |
| **Windows Server 2012 R2** | Supported. The NPS console UI is slightly different (no "NPAS" — look for "Network Policy and Access Services"). Configuration is functionally identical. |

### 6.5 Verify NPS Forwarding

```powershell
# Check NPS event log for forwarded requests
Get-WinEvent -FilterHashtable @{
    LogName='Security';
    Id=6272,6273  # NPS success/failure events
} -MaxEvents 5

# Check Windows Event Viewer → Custom Views → Server Roles → Network Policy and Access Services
```

---

## 7. DHCP — ISC DHCP + rsyslog (Linux)

The most common Linux DHCP server (ISC dhcpd) logs `DHCPACK` messages to syslog. rsyslog forwards these messages to TrueID on port **5516**.

### 7.1 TrueID's Expected DHCP Format

TrueID's DHCP adapter recognizes two message patterns:

```
DHCPACK on 10.0.1.42 to 00:1a:2b:3c:4d:5e (laptop-jan) via eth0
DHCPACK(eth0) 10.0.1.42 00:1a:2b:3c:4d:5e (laptop-jan)
```

Both patterns extract: **IP address**, **MAC address**, and optionally the **hostname**.

ISC DHCP (dhcpd) produces the first format natively — no special configuration of dhcpd is needed.

### 7.2 Configure rsyslog to Forward DHCP Logs

ISC dhcpd logs to syslog facility `daemon` (or `local7` if configured). Create a forwarding rule in rsyslog.

**Step 1 — Create rsyslog configuration**

Create `/etc/rsyslog.d/60-trueid-dhcp.conf`:

```
# Forward ISC DHCP DHCPACK messages to TrueID
# Adjust facility if dhcpd uses a different one (check /etc/dhcp/dhcpd.conf for log-facility)

if $programname == 'dhcpd' and $msg contains 'DHCPACK' then {
    action(
        type="omfwd"
        target="TRUEID_SERVER_IP"
        port="5516"
        protocol="udp"
        template="RSYSLOG_SyslogProtocol23Format"
    )
}
```

**Replace `TRUEID_SERVER_IP`** with your TrueID server address.

**Step 2 — Restart rsyslog**

```bash
sudo systemctl restart rsyslog
sudo systemctl status rsyslog
```

**Step 3 — Verify**

Trigger a DHCP renewal on a client and check TrueID logs:

```bash
# On a DHCP client
sudo dhclient -r && sudo dhclient

# On the DHCP server, verify dhcpd is logging
sudo journalctl -u isc-dhcp-server --since "1 minute ago" | grep DHCPACK
```

### 7.3 Alternative: Forward All dhcpd Messages

If you prefer simplicity and don't mind a few extra (non-DHCPACK) messages:

```
# /etc/rsyslog.d/60-trueid-dhcp.conf
if $programname == 'dhcpd' then @TRUEID_SERVER_IP:5516
```

TrueID silently ignores non-DHCPACK messages — they're parsed and discarded without errors.

### 7.4 ISC dhcpd log-facility

If dhcpd is configured with a custom log facility, match it in rsyslog:

```
# In /etc/dhcp/dhcpd.conf:
log-facility local7;

# Then in rsyslog:
local7.* @TRUEID_SERVER_IP:5516
```

---

## 8. DHCP — Kea DHCP + rsyslog

ISC Kea is the modern replacement for ISC dhcpd. Kea uses a different logging system but can also output to syslog.

### 8.1 Enable Syslog Logging in Kea

Edit `/etc/kea/kea-dhcp4.conf`, in the `"Dhcp4"` → `"loggers"` section:

```json
{
  "Dhcp4": {
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output-options": [
          {
            "output": "syslog:local7"
          }
        ],
        "severity": "INFO"
      }
    ]
  }
}
```

### 8.2 Kea DHCPACK Log Format

Kea logs lease events differently than ISC dhcpd. A typical lease allocation message looks like:

```
kea-dhcp4: DHCP4_LEASE_ALLOC ... address 10.0.1.42 ... hwaddr 00:1a:2b:3c:4d:5e
```

> **Note:** Kea's log format does not match the `DHCPACK on ...` pattern that TrueID expects. Two options:
>
> **Option A** — Use rsyslog's `mmexternal` or a template to reformat:
>
> ```
> # /etc/rsyslog.d/60-trueid-kea.conf
> template(name="keaToDhcpack" type="string"
>     string="DHCPACK on %$.ip% to %$.mac% (%$.hostname%)\n")
> ```
>
> **Option B (recommended)** — Enable Kea's **Forensic Logging Hook** which produces ISC dhcpd–compatible output, or use the **Run Script Hook** to generate compatible syslog messages.
>
> In practice, if you are running Kea, the simplest approach is to use a small script that tails Kea's lease file (`/var/lib/kea/kea-leases4.csv`) and sends formatted syslog messages to TrueID. An example is available in `scripts/kea-to-trueid.sh` (if present in your repo).

---

## 9. DHCP — Windows DHCP Server + NXLog

> **Alternative:** The [TrueID Agent](#3-trueid-agent-recommended-for-windows) with `mode = "dhcp"` or `mode = "both"` natively collects Windows DHCP Server events over TLS — no NXLog required.

Windows DHCP Server logs lease events to the Windows Event Log (Microsoft-Windows-DHCP-Server). NXLog forwards these events to TrueID.

### 9.1 Enable DHCP Audit Logging

1. Open **DHCP Manager** (`dhcpmgmt.msc`).
2. Right-click the server → **Properties** → **General** tab.
3. Check **Enable DHCP audit logging**.
4. Click **OK**.

Or via PowerShell:

```powershell
Set-DhcpServerAuditLog -Enable $true
```

### 9.2 DHCP Event IDs

| Event ID | Description | TrueID Use |
|----------|-------------|------------|
| **10** | A new lease was created | IP + MAC + hostname |
| **11** | A lease was renewed | IP + MAC + hostname |
| **12** | A lease was released | (ignored by TrueID) |

### 9.3 NXLog Configuration for Windows DHCP

Add to `C:\Program Files\nxlog\conf\nxlog.conf`:

```xml
## TrueID — Forward Windows DHCP Server events

<Input dhcp_eventlog>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-DHCP-Server-Events/Operational">
                    *[System[(EventID=10 or EventID=11)]]
                </Select>
            </Query>
        </QueryList>
    </QueryXML>
    # Reformat to match ISC dhcpd DHCPACK format that TrueID expects
    Exec    if defined($IPAddress) and defined($MAC) \
            $raw_event = "DHCPACK on " + $IPAddress + " to " + $MAC + \
                         " (" + ($HostName // "unknown") + ")";
</Input>

<Output trueid_dhcp>
    Module  om_udp
    Host    TRUEID_SERVER_IP
    Port    5516
</Output>

<Route dhcp_to_trueid>
    Path    dhcp_eventlog => trueid_dhcp
</Route>
```

> **Note:** The exact field names (`$IPAddress`, `$MAC`, `$HostName`) depend on how Windows DHCP Server formats the event. You may need to inspect actual events and adjust accordingly. Use `nxlog -v` or write events to a local file first to verify the field names.

If you already have NXLog running for AD events (Section 3), simply add the `<Input>`, `<Output>`, and `<Route>` blocks to the existing `nxlog.conf`.

### 9.4 Alternative: DHCP Audit Log Files

Windows DHCP Server also writes CSV audit logs to `%systemroot%\system32\dhcp\`. NXLog can tail these files:

```xml
<Input dhcp_audit_file>
    Module  im_file
    File    "C:\\Windows\\System32\\dhcp\\DhcpSrvLog-*.log"
    # Parse CSV: Date,Time,Description,IP Address,Hostname,MAC Address,...
    Exec    if $raw_event =~ /^(\d+),.*?,(\d+\.\d+\.\d+\.\d+),(.*?),([0-9A-Fa-f]{12,17})/ \
            { \
                $raw_event = "DHCPACK on " + $2 + " to " + $4 + " (" + $3 + ")"; \
            } \
            else drop();
</Input>
```

---

## 10. Verification & Troubleshooting

### 10.1 Quick Verification Tests

**AD (from TrueID server):**

```bash
# Send a mock AD syslog event
echo '{"EventID":4624,"TargetUserName":"testuser","IpAddress":"10.0.1.42"}' | \
    nc -u TRUEID_SERVER_IP 5514
```

**RADIUS (requires `radclient` — installed with `freeradius-utils`):**

```bash
echo "User-Name = testuser
Framed-IP-Address = 10.0.1.100
Acct-Status-Type = Start
Acct-Session-Id = test-001" | radclient -x TRUEID_SERVER_IP:1813 acct YourSharedSecret
```

**DHCP (from TrueID server):**

```bash
echo "DHCPACK on 10.0.1.42 to 00:1a:2b:3c:4d:5e (laptop-test)" | \
    nc -u TRUEID_SERVER_IP 5516
```

After each test, check the TrueID dashboard at `http://TRUEID_SERVER_IP:3000` — you should see a new mapping row.

### 10.2 Checking Adapter Status

TrueID exposes adapter status via the API:

```bash
curl -s http://localhost:3000/api/v1/admin/adapters | python3 -m json.tool
```

Each adapter shows `"status": "active"` if it received an event in the last 5 minutes, or `"idle"` otherwise.

### 10.3 Common Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| No data on dashboard | Firewall blocking port | `sudo ufw allow 5514/udp` (or 1813, 5516) |
| AD events seen but no mappings created | Wrong Event IDs being forwarded | Verify NXLog QueryXML filters for 4624/4768 only |
| AD events parsed but IP is empty | `IpAddress` field missing or `-` | This happens for local/service logons (LogonType 5). Filter to `LogonType=3` (network) in NXLog if desired |
| RADIUS "Invalid packet" errors | Shared secret mismatch | Ensure `RADIUS_SECRET` in TrueID `.env` matches `secret` in FreeRADIUS `proxy.conf` |
| RADIUS "Missing Framed-IP-Address" | NAS not including the attribute | Check NAS/switch configuration — `Framed-IP-Address` must be present in Accounting-Request |
| DHCP events received but no MAC extracted | Non-standard DHCPACK format | Check the exact syslog message format; TrueID expects `DHCPACK on <ip> to <mac>` |
| "Connection refused" from NXLog | TrueID engine not running | Start engine: `cargo run -p trueid-engine` |

### 10.4 Increase Log Verbosity

For debugging, run TrueID with debug-level logging:

```bash
RUST_LOG=debug cargo run -p trueid-engine
```

This prints every parsed event, including raw payloads, making it easy to diagnose format issues.

---

## 11. Security: TLS Transport (Optional)

For production deployments, TrueID supports **TLS-encrypted syslog** (RFC 5425) on dedicated ports. This requires deploying the TrueID Agent on the source host.

| Listener | Default Port | Protocol |
|----------|-------------|----------|
| AD TLS | **5615** | TCP + mutual TLS |
| DHCP TLS | **5617** | TCP + mutual TLS |

### 11.1 Generate Certificates

```bash
cd certs/

# CA
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout ca-key.pem -out ca.pem \
    -subj "/CN=TrueID CA"

# Server cert
openssl req -newkey rsa:4096 -nodes \
    -keyout server-key.pem -out server.csr \
    -subj "/CN=trueid-server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365

# Client cert (for each agent)
openssl req -newkey rsa:4096 -nodes \
    -keyout agent-key.pem -out agent.csr \
    -subj "/CN=agent-dc01"
openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out agent.pem -days 365
```

### 11.2 TrueID TLS Configuration

Place cert files in the `certs/` directory and set in `.env`:

```env
TLS_CA_CERT=./certs/ca.pem
TLS_SERVER_CERT=./certs/server.pem
TLS_SERVER_KEY=./certs/server-key.pem
AD_TLS_BIND=0.0.0.0:5615
DHCP_TLS_BIND=0.0.0.0:5617
```

TrueID automatically enables TLS listeners when all three cert files exist.

### 11.3 TLS Message Format

TLS listeners expect messages prefixed with `TrueID-Agent:`:

```
TrueID-Agent: AD_LOGON user=jan.kowalski ip=10.0.1.42 event_id=4624 status=success
TrueID-Agent: DHCP_LEASE ip=10.0.1.42 mac=00:1a:2b:3c:4d:5e hostname=laptop-jan lease=86400
TrueID-Agent: HEARTBEAT hostname=DC01 uptime=3600 events_sent=142 events_dropped=0
```

This format is produced by the **TrueID Agent** (`trueid-agent`), which is a lightweight binary that runs on the source host and handles certificate management, buffering, and heartbeats.

---

## Summary: What Goes Where

| Source | Option A: TrueID Agent | Option B: Third-Party | TrueID Port | Protocol |
|--------|----------------------|----------------------|-------------|----------|
| Active Directory (Windows DC) | **`net-identity-agent`** mode=`ad` | NXLog CE | Agent: **5615** (TLS) / NXLog: **5514** (UDP) | TLS / Syslog |
| Windows DHCP Server | **`net-identity-agent`** mode=`dhcp` | NXLog CE | Agent: **5617** (TLS) / NXLog: **5516** (UDP) | TLS / Syslog |
| AD + DHCP on same host | **`net-identity-agent`** mode=`both` | NXLog CE (two routes) | **5615** + **5617** (TLS) | TLS |
| FreeRADIUS | — | Built-in proxy | **1813** | RADIUS Accounting |
| Microsoft NPS | — | Built-in proxy | **1813** | RADIUS Accounting |
| ISC DHCP (Linux) | — | rsyslog rule | **5516** | UDP Syslog |
| Kea DHCP (Linux) | — | rsyslog + formatter | **5516** | UDP Syslog |

**Decision flow:**

1. **Windows host?** → Use the TrueID Agent (encrypted, zero-dependency, heartbeats, buffering).
2. **Linux DHCP?** → Use rsyslog (Section [7](#7-dhcp--isc-dhcp--rsyslog-linux) or [8](#8-dhcp--kea-dhcp--rsyslog)).
3. **RADIUS?** → Configure FreeRADIUS ([Section 5](#5-radius--freeradius)) or NPS ([Section 6](#6-radius--microsoft-nps)) proxy — always native RADIUS protocol.
4. **Corporate policy mandates NXLog?** → Use NXLog ([Section 4](#4-active-directory--nxlog-ce) / [Section 9](#9-dhcp--windows-dhcp-server--nxlog)) — works over plain UDP/TCP.

Each data source can be enabled independently — you don't need all three. Start with whichever source is most available in your environment, verify it on the dashboard, then add more.

---

## API Key Authentication for Connectors

External connectors (Sycope sync, custom scripts, SIEM integrations) can authenticate
to the TrueID API using API keys instead of username/password.

### Creating an API key

1. Log in as Admin to the TrueID dashboard.
2. An Admin can create API keys via `POST /api/v1/api-keys`:

```bash
curl -s -X POST https://trueid.example.com/api/v1/api-keys \
  -H "X-API-Key: <existing-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Sycope sync connector", "role": "Viewer"}'
```

The response includes the raw key (shown **only once**):
```json
{
  "id": 1,
  "key": "trueid_abc123...full-key...",
  "key_prefix": "abc123",
  "description": "Sycope sync connector",
  "role": "Viewer"
}
```

**Save the `key` value immediately** — it cannot be retrieved later.

### Using an API key

Include the key in the `X-API-Key` header on every request:

```bash
# Read mappings
curl -s https://trueid.example.com/api/v1/mappings \
  -H "X-API-Key: trueid_abc123...full-key..."

# Read events
curl -s https://trueid.example.com/api/v1/events \
  -H "X-API-Key: trueid_abc123...full-key..."
```

### Role assignment

- **Viewer** — read-only access (mappings, events, stats). Best for monitoring connectors.
- **Operator** — read + write mappings. For connectors that push data.
- **Admin** — full access including user management. Use sparingly.

### Rate limiting

API keys are rate-limited to 100 requests per 60 seconds per key.
If exceeded, requests return `429 Too Many Requests`.

### Revoking a key

```bash
curl -s -X DELETE https://trueid.example.com/api/v1/api-keys/1 \
  -H "X-API-Key: <admin-key>"
```

Revoked keys are immediately invalidated.
