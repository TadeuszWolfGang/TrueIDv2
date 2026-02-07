# TrueID → Sycope Integration Connector

Synchronizes identity data from TrueID to Sycope for real-time NetFlow enrichment and forensic event analysis.

## Architecture

```
TrueID (Rust/Axum, SQLite)
  → GET /api/v1/mappings
  → GET /api/v1/events?since=<ts>
    → trueid_sync.py
      → Sycope Lookup API (Pattern A: CSV Lookup merge)
      → Sycope Index API  (Pattern B: event injection)
```

| Pattern | Description | Sycope Target |
|---------|-------------|---------------|
| **A** — Lookup Enrichment | Active IP→identity mappings | CSV Lookup (`TrueID_Enrichment`) |
| **B** — Event History | Auth/mapping change events | Custom Index (`trueid_events`) |

## Prerequisites

1. **TrueID** running with `trueid-web` on port 3000
2. **Sycope** >= 3.1 with:
   - User `trueid_sync` with role: "Edit Lookup values" + "Inject into custom indexes"
   - CSV Lookup `TrueID_Enrichment` created manually (columns: `ip, mac, user, hostname, vendor, last_seen`)
3. **Sycope SDK** (`sycope/` package) available at `../sycope/` relative to this directory

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Edit config
cp config.json config.json.bak
vi config.json   # set trueid_host, sycope_host, sycope_login, sycope_pass

# 3. (Optional) Create Custom Index for Pattern B
python3 install.py

# 4. Run sync
python3 trueid_sync.py
```

## Configuration

Edit `config.json`:

| Key | Description | Default |
|-----|-------------|---------|
| `trueid_host` | TrueID web URL | `http://localhost:3000` |
| `sycope_host` | Sycope appliance URL | `https://192.168.1.14` |
| `sycope_login` | Sycope API username | `trueid_sync` |
| `sycope_pass` | Sycope API password | — |
| `lookup_name` | CSV Lookup name in Sycope | `TrueID_Enrichment` |
| `enable_event_index` | Enable Pattern B | `true` |
| `index_name` | Custom Index name | `trueid_events` |

## Scheduling

The script runs **once per invocation** (no internal loop). Use a timer:

**systemd (recommended):**
```bash
sudo cp trueid-sycope-sync.{service,timer} /etc/systemd/system/
sudo systemctl enable --now trueid-sycope-sync.timer
```

**Docker:**
```bash
docker compose -f docker-compose.connector.yml up --build -d
```

## NQL Usage

After sync, use the lookup in Sycope NQL queries:

```
src stream="netflow" | lookup "TrueID_Enrichment" on clientIp
```

## Cleanup

```bash
python3 uninstall.py   # removes Custom Index (Pattern B data)
```
