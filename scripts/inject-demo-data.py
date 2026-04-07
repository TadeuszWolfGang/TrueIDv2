#!/usr/bin/env python3
"""Inject realistic demo data into TrueID for screenshot/demo purposes."""

import json
import random
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
ADMIN_USER = "admin"
ADMIN_PASS = "integration12345"

# --- Demo users across multiple sources ---
DEMO_ENTRIES = [
    # AD users (corporate workstations)
    {"ip": "10.50.1.10", "user": "anna.kowalska", "mac": "00:1A:2B:3C:4D:01", "source": "AdLog", "hostname": "WS-ANNA", "groups": ["Domain Users", "Finance"]},
    {"ip": "10.50.1.11", "user": "piotr.nowak", "mac": "00:1A:2B:3C:4D:02", "source": "AdLog", "hostname": "WS-PIOTR", "groups": ["Domain Users", "IT"]},
    {"ip": "10.50.1.12", "user": "maria.wisniewska", "mac": "00:1A:2B:3C:4D:03", "source": "AdLog", "hostname": "WS-MARIA", "groups": ["Domain Users", "HR"]},
    {"ip": "10.50.1.13", "user": "tomasz.zielinski", "mac": "00:1A:2B:3C:4D:04", "source": "AdLog", "hostname": "WS-TOMASZ", "groups": ["Domain Users", "Engineering"]},
    {"ip": "10.50.1.14", "user": "katarzyna.lewandowska", "mac": "00:1A:2B:3C:4D:05", "source": "AdLog", "hostname": "WS-KASIA", "groups": ["Domain Users", "Marketing"]},
    {"ip": "10.50.1.15", "user": "jan.kaminski", "mac": "00:1A:2B:3C:4D:06", "source": "AdLog", "hostname": "WS-JAN", "groups": ["Domain Users", "Engineering"]},
    {"ip": "10.50.1.16", "user": "ewa.dabrowska", "mac": "00:1A:2B:3C:4D:07", "source": "AdLog", "hostname": "WS-EWA", "groups": ["Domain Users", "Finance"]},
    {"ip": "10.50.1.17", "user": "michal.wojciechowski", "mac": "00:1A:2B:3C:4D:08", "source": "AdLog", "hostname": "WS-MICHAL", "groups": ["Domain Users", "IT", "Domain Admins"]},
    {"ip": "10.50.1.18", "user": "agnieszka.szymanska", "mac": "00:1A:2B:3C:4D:09", "source": "AdLog", "hostname": "WS-AGNIESZKA", "groups": ["Domain Users", "Sales"]},
    {"ip": "10.50.1.19", "user": "adam.wozniak", "mac": "00:1A:2B:3C:4D:0A", "source": "AdLog", "hostname": "WS-ADAM", "groups": ["Domain Users", "Engineering"]},
    {"ip": "10.50.1.20", "user": "monika.jankowska", "mac": "00:1A:2B:3C:4D:0B", "source": "AdLog", "hostname": "WS-MONIKA", "groups": ["Domain Users", "Legal"]},
    {"ip": "10.50.1.21", "user": "krzysztof.mazur", "mac": "00:1A:2B:3C:4D:0C", "source": "AdLog", "hostname": "WS-KRZYSIEK", "groups": ["Domain Users", "IT"]},
    # RADIUS users (WiFi / VPN)
    {"ip": "10.50.2.50", "user": "lukasz.krawczyk@corp.local", "mac": "AA:BB:CC:11:22:01", "source": "Radius", "hostname": "IPHONE-LUKASZ"},
    {"ip": "10.50.2.51", "user": "natalia.pawlak@corp.local", "mac": "AA:BB:CC:11:22:02", "source": "Radius", "hostname": "MACBOOK-NATALIA"},
    {"ip": "10.50.2.52", "user": "bartosz.michalski@corp.local", "mac": "AA:BB:CC:11:22:03", "source": "Radius", "hostname": "DELL-BARTOSZ"},
    {"ip": "10.50.2.53", "user": "aleksandra.grabowska@corp.local", "mac": "AA:BB:CC:11:22:04", "source": "Radius", "hostname": "SURFACE-ALEKSANDRA"},
    {"ip": "10.50.2.54", "user": "marek.nowakowski@corp.local", "mac": "AA:BB:CC:11:22:05", "source": "Radius", "hostname": "THINKPAD-MAREK"},
    {"ip": "10.50.2.55", "user": "karolina.adamska@corp.local", "mac": "AA:BB:CC:11:22:06", "source": "Radius", "hostname": "IPAD-KAROLINA"},
    {"ip": "10.50.2.56", "user": "dawid.krol@corp.local", "mac": "AA:BB:CC:11:22:07", "source": "Radius", "hostname": "PIXEL-DAWID"},
    {"ip": "10.50.2.57", "user": "paulina.sikora@corp.local", "mac": "AA:BB:CC:11:22:08", "source": "Radius", "hostname": "MACBOOK-PAULINA"},
    # DHCP leases (printers, IoT, infra)
    {"ip": "10.50.3.10", "user": "", "mac": "00:17:C8:AA:BB:01", "source": "DhcpLog", "hostname": "PRINTER-FL2-HP"},
    {"ip": "10.50.3.11", "user": "", "mac": "00:17:C8:AA:BB:02", "source": "DhcpLog", "hostname": "PRINTER-FL3-XEROX"},
    {"ip": "10.50.3.20", "user": "", "mac": "B8:27:EB:AA:BB:01", "source": "DhcpLog", "hostname": "IOT-SENSOR-01"},
    {"ip": "10.50.3.21", "user": "", "mac": "B8:27:EB:AA:BB:02", "source": "DhcpLog", "hostname": "IOT-SENSOR-02"},
    {"ip": "10.50.3.30", "user": "", "mac": "00:50:56:AA:BB:01", "source": "DhcpLog", "hostname": "ESXI-MGMT-01"},
    {"ip": "10.50.3.31", "user": "", "mac": "00:50:56:AA:BB:02", "source": "DhcpLog", "hostname": "VCENTER-01"},
    {"ip": "10.50.3.40", "user": "", "mac": "3C:52:82:AA:BB:01", "source": "DhcpLog", "hostname": "AP-FL1-CISCO"},
    {"ip": "10.50.3.41", "user": "", "mac": "3C:52:82:AA:BB:02", "source": "DhcpLog", "hostname": "AP-FL2-CISCO"},
    {"ip": "10.50.3.42", "user": "", "mac": "3C:52:82:AA:BB:03", "source": "DhcpLog", "hostname": "SW-CORE-01"},
    # VPN users
    {"ip": "10.50.4.100", "user": "remote.contractor1", "mac": "", "source": "VpnLog", "hostname": "VPN-CONTRACTOR1"},
    {"ip": "10.50.4.101", "user": "remote.contractor2", "mac": "", "source": "VpnLog", "hostname": "VPN-CONTRACTOR2"},
    {"ip": "10.50.4.102", "user": "jan.kaminski", "mac": "", "source": "VpnLog", "hostname": "VPN-JAN-HOME"},
    {"ip": "10.50.4.103", "user": "piotr.nowak", "mac": "", "source": "VpnLog", "hostname": "VPN-PIOTR-HOME"},
    {"ip": "10.50.4.104", "user": "tomasz.zielinski", "mac": "", "source": "VpnLog", "hostname": "VPN-TOMASZ-HOME"},
    # Manual entries (guest, conference rooms)
    {"ip": "10.50.5.10", "user": "guest.visitor1", "mac": "DE:AD:BE:EF:00:01", "source": "Manual", "hostname": "GUEST-CONF-A"},
    {"ip": "10.50.5.11", "user": "guest.visitor2", "mac": "DE:AD:BE:EF:00:02", "source": "Manual", "hostname": "GUEST-CONF-B"},
    {"ip": "10.50.5.12", "user": "", "mac": "DE:AD:BE:EF:00:03", "source": "Manual", "hostname": "CONF-ROOM-DISPLAY"},
]

# --- Login ---
login_data = json.dumps({"username": ADMIN_USER, "password": ADMIN_PASS}).encode()
req = urllib.request.Request(f"{BASE_URL}/api/auth/login", data=login_data, headers={"Content-Type": "application/json"})
resp = urllib.request.urlopen(req)
cookies = resp.headers.get_all("Set-Cookie")
cookie_header = "; ".join(c.split(";")[0] for c in cookies)
csrf = ""
for c in cookies:
    if "trueid_csrf_token" in c:
        csrf = c.split("trueid_csrf_token=")[1].split(";")[0]

now = datetime.now(timezone.utc)

# --- Build events ---
all_events = []
for entry in DEMO_ENTRIES:
    for i in range(random.randint(2, 5)):
        ts = now - timedelta(minutes=random.randint(1, 1440), seconds=random.randint(0, 59))
        event = {
            "ip": entry["ip"],
            "user": entry["user"] or "DHCP-LEASE",
            "mac": entry["mac"],
            "source": entry["source"],
            "timestamp": ts.isoformat(),
        }
        if entry.get("hostname"):
            event["hostname"] = entry["hostname"]
        all_events.append(event)

random.shuffle(all_events)

# --- Import in batches ---
BATCH = 50
imported = 0
for i in range(0, len(all_events), BATCH):
    batch = all_events[i:i+BATCH]
    payload = json.dumps({"events": batch}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/v2/import/events",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Cookie": cookie_header,
            "X-CSRF-Token": csrf,
        },
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    body = json.loads(resp.read())
    imported += body.get("imported", 0)
    print(f"Batch {i//BATCH + 1}: imported={body.get('imported')}, skipped={body.get('skipped')}")

print(f"\nTotal events imported: {imported}")
print(f"Unique IPs: {len(set(e['ip'] for e in DEMO_ENTRIES))}")
print(f"Sources used: {sorted(set(e['source'] for e in DEMO_ENTRIES))}")
