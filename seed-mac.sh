#!/bin/bash
# === TrueID — generowanie danych testowych v3 ===
# Tworzy subnety PRZED eventami, dopisuje MAC, tagi, DNS, alerty.

BASE="http://localhost:3000"

# ─── 1. Login ───
echo "Logowanie..."
LOGIN=$(curl -s -c cookies.txt -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"8611Mnpm8611"}')

CSRF=$(grep trueid_csrf_token cookies.txt | awk '{print $NF}')
echo ""
if [ -z "$CSRF" ]; then
  echo "BLAD: Brak CSRF tokena."
  echo "Odpowiedz serwera: $LOGIN"
  rm -f cookies.txt
  exit 1
fi
echo "OK, CSRF: ${CSRF:0:16}..."

# Helper
post() {
  curl -s -b cookies.txt -X POST "$BASE$1" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $CSRF" \
    -d "$2"
}

# ─── 2. Subnety NAJPIERW (zeby engine mogl matchowac) ───
echo ""
echo ">>> Subnety (6)..."
post "/api/v2/subnets" '{"name":"Office LAN","cidr":"10.0.1.0/24","vlan_id":100,"location":"Bydgoszcz HQ","description":"Siec biurowa, pietra 1-3"}'
echo ""
post "/api/v2/subnets" '{"name":"Dev Lab","cidr":"10.0.2.0/24","vlan_id":150,"location":"Bydgoszcz Lab","description":"Srodowisko deweloperskie"}'
echo ""
post "/api/v2/subnets" '{"name":"Server VLAN","cidr":"10.10.0.0/24","vlan_id":200,"location":"DC1 Bydgoszcz","description":"Serwery produkcyjne VMware"}'
echo ""
post "/api/v2/subnets" '{"name":"Guest WiFi","cidr":"192.168.1.0/24","vlan_id":300,"location":"Bydgoszcz HQ","description":"Siec goscinna, izolowana"}'
echo ""
post "/api/v2/subnets" '{"name":"VPN Pool","cidr":"172.16.0.0/24","vlan_id":500,"location":"Remote","description":"GlobalProtect VPN pool"}'
echo ""
post "/api/v2/subnets" '{"name":"Management","cidr":"10.99.0.0/24","vlan_id":999,"location":"DC1 Bydgoszcz","description":"Out-of-band management"}'
echo ""

sleep 1

# ─── 3. Radius — jkowalski (notebook, rozne porty) ───
echo ">>> Import Radius — jkowalski (20 stacji)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.0.1.1","user":"jkowalski","mac":"aa:bb:cc:01:01:01","source":"Radius"},
    {"ip":"10.0.1.2","user":"jkowalski","mac":"aa:bb:cc:01:01:02","source":"Radius"},
    {"ip":"10.0.1.3","user":"jkowalski","mac":"aa:bb:cc:01:01:03","source":"Radius"},
    {"ip":"10.0.1.4","user":"jkowalski","mac":"aa:bb:cc:01:01:04","source":"Radius"},
    {"ip":"10.0.1.5","user":"jkowalski","mac":"aa:bb:cc:01:01:05","source":"Radius"},
    {"ip":"10.0.1.6","user":"jkowalski","mac":"aa:bb:cc:01:01:06","source":"Radius"},
    {"ip":"10.0.1.7","user":"jkowalski","mac":"aa:bb:cc:01:01:07","source":"Radius"},
    {"ip":"10.0.1.8","user":"jkowalski","mac":"aa:bb:cc:01:01:08","source":"Radius"},
    {"ip":"10.0.1.9","user":"jkowalski","mac":"aa:bb:cc:01:01:09","source":"Radius"},
    {"ip":"10.0.1.10","user":"jkowalski","mac":"aa:bb:cc:01:01:0a","source":"Radius"},
    {"ip":"10.0.1.11","user":"jkowalski","mac":"aa:bb:cc:01:01:0b","source":"Radius"},
    {"ip":"10.0.1.12","user":"jkowalski","mac":"aa:bb:cc:01:01:0c","source":"Radius"},
    {"ip":"10.0.1.13","user":"jkowalski","mac":"aa:bb:cc:01:01:0d","source":"Radius"},
    {"ip":"10.0.1.14","user":"jkowalski","mac":"aa:bb:cc:01:01:0e","source":"Radius"},
    {"ip":"10.0.1.15","user":"jkowalski","mac":"aa:bb:cc:01:01:0f","source":"Radius"},
    {"ip":"10.0.1.16","user":"jkowalski","mac":"aa:bb:cc:01:01:10","source":"Radius"},
    {"ip":"10.0.1.17","user":"jkowalski","mac":"aa:bb:cc:01:01:11","source":"Radius"},
    {"ip":"10.0.1.18","user":"jkowalski","mac":"aa:bb:cc:01:01:12","source":"Radius"},
    {"ip":"10.0.1.19","user":"jkowalski","mac":"aa:bb:cc:01:01:13","source":"Radius"},
    {"ip":"10.0.1.20","user":"jkowalski","mac":"aa:bb:cc:01:01:14","source":"Radius"}
  ]
}'
echo ""

# ─── 4. AD eventy — anowak (logowania domenowe) ───
echo ">>> Import AD — anowak (20 stacji)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.0.1.21","user":"anowak","mac":"de:ad:be:ef:02:15","source":"AdLog"},
    {"ip":"10.0.1.22","user":"anowak","mac":"de:ad:be:ef:02:16","source":"AdLog"},
    {"ip":"10.0.1.23","user":"anowak","mac":"de:ad:be:ef:02:17","source":"AdLog"},
    {"ip":"10.0.1.24","user":"anowak","mac":"de:ad:be:ef:02:18","source":"AdLog"},
    {"ip":"10.0.1.25","user":"anowak","mac":"de:ad:be:ef:02:19","source":"AdLog"},
    {"ip":"10.0.1.26","user":"anowak","mac":"de:ad:be:ef:02:1a","source":"AdLog"},
    {"ip":"10.0.1.27","user":"anowak","mac":"de:ad:be:ef:02:1b","source":"AdLog"},
    {"ip":"10.0.1.28","user":"anowak","mac":"de:ad:be:ef:02:1c","source":"AdLog"},
    {"ip":"10.0.1.29","user":"anowak","mac":"de:ad:be:ef:02:1d","source":"AdLog"},
    {"ip":"10.0.1.30","user":"anowak","mac":"de:ad:be:ef:02:1e","source":"AdLog"},
    {"ip":"10.0.1.31","user":"anowak","mac":"de:ad:be:ef:02:1f","source":"AdLog"},
    {"ip":"10.0.1.32","user":"anowak","mac":"de:ad:be:ef:02:20","source":"AdLog"},
    {"ip":"10.0.1.33","user":"anowak","mac":"de:ad:be:ef:02:21","source":"AdLog"},
    {"ip":"10.0.1.34","user":"anowak","mac":"de:ad:be:ef:02:22","source":"AdLog"},
    {"ip":"10.0.1.35","user":"anowak","mac":"de:ad:be:ef:02:23","source":"AdLog"},
    {"ip":"10.0.1.36","user":"anowak","mac":"de:ad:be:ef:02:24","source":"AdLog"},
    {"ip":"10.0.1.37","user":"anowak","mac":"de:ad:be:ef:02:25","source":"AdLog"},
    {"ip":"10.0.1.38","user":"anowak","mac":"de:ad:be:ef:02:26","source":"AdLog"},
    {"ip":"10.0.1.39","user":"anowak","mac":"de:ad:be:ef:02:27","source":"AdLog"},
    {"ip":"10.0.1.40","user":"anowak","mac":"de:ad:be:ef:02:28","source":"AdLog"}
  ]
}'
echo ""

# ─── 5. DHCP — mwisniewska (lab) ───
echo ">>> Import DHCP — mwisniewska (20 lease)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.0.2.41","user":"mwisniewska","mac":"00:1a:2b:03:41:01","source":"DhcpLease"},
    {"ip":"10.0.2.42","user":"mwisniewska","mac":"00:1a:2b:03:42:02","source":"DhcpLease"},
    {"ip":"10.0.2.43","user":"mwisniewska","mac":"00:1a:2b:03:43:03","source":"DhcpLease"},
    {"ip":"10.0.2.44","user":"mwisniewska","mac":"00:1a:2b:03:44:04","source":"DhcpLease"},
    {"ip":"10.0.2.45","user":"mwisniewska","mac":"00:1a:2b:03:45:05","source":"DhcpLease"},
    {"ip":"10.0.2.46","user":"mwisniewska","mac":"00:1a:2b:03:46:06","source":"DhcpLease"},
    {"ip":"10.0.2.47","user":"mwisniewska","mac":"00:1a:2b:03:47:07","source":"DhcpLease"},
    {"ip":"10.0.2.48","user":"mwisniewska","mac":"00:1a:2b:03:48:08","source":"DhcpLease"},
    {"ip":"10.0.2.49","user":"mwisniewska","mac":"00:1a:2b:03:49:09","source":"DhcpLease"},
    {"ip":"10.0.2.50","user":"mwisniewska","mac":"00:1a:2b:03:50:0a","source":"DhcpLease"},
    {"ip":"10.0.2.51","user":"mwisniewska","mac":"00:1a:2b:03:51:0b","source":"DhcpLease"},
    {"ip":"10.0.2.52","user":"mwisniewska","mac":"00:1a:2b:03:52:0c","source":"DhcpLease"},
    {"ip":"10.0.2.53","user":"mwisniewska","mac":"00:1a:2b:03:53:0d","source":"DhcpLease"},
    {"ip":"10.0.2.54","user":"mwisniewska","mac":"00:1a:2b:03:54:0e","source":"DhcpLease"},
    {"ip":"10.0.2.55","user":"mwisniewska","mac":"00:1a:2b:03:55:0f","source":"DhcpLease"},
    {"ip":"10.0.2.56","user":"mwisniewska","mac":"00:1a:2b:03:56:10","source":"DhcpLease"},
    {"ip":"10.0.2.57","user":"mwisniewska","mac":"00:1a:2b:03:57:11","source":"DhcpLease"},
    {"ip":"10.0.2.58","user":"mwisniewska","mac":"00:1a:2b:03:58:12","source":"DhcpLease"},
    {"ip":"10.0.2.59","user":"mwisniewska","mac":"00:1a:2b:03:59:13","source":"DhcpLease"},
    {"ip":"10.0.2.60","user":"mwisniewska","mac":"00:1a:2b:03:60:14","source":"DhcpLease"}
  ]
}'
echo ""

# ─── 6. Konflikty — ten sam IP, rozni userzy (podejrzane) ───
echo ">>> Konflikty (3 IP z podwojnymi userami)..."
post "/api/v2/import/events" '{"events":[
  {"ip":"10.0.1.5","user":"intruz_1","mac":"66:66:66:00:00:01","source":"AdLog"},
  {"ip":"10.0.1.10","user":"intruz_2","mac":"66:66:66:00:00:02","source":"DhcpLease"},
  {"ip":"10.0.2.50","user":"ghost_user","mac":"66:66:66:00:00:03","source":"Radius"}
]}'
echo ""

# ─── 7. Biuro — rozni pracownicy ───
echo ">>> Import biuro (15 pracownikow)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"192.168.1.10","user":"jdoe","mac":"b4:2e:99:a1:00:10","source":"Radius"},
    {"ip":"192.168.1.11","user":"pawel","mac":"b4:2e:99:a1:00:11","source":"Radius"},
    {"ip":"192.168.1.12","user":"kasia","mac":"b4:2e:99:a1:00:12","source":"AdLog"},
    {"ip":"192.168.1.13","user":"tomek","mac":"b4:2e:99:a1:00:13","source":"Radius"},
    {"ip":"192.168.1.14","user":"ania","mac":"b4:2e:99:a1:00:14","source":"AdLog"},
    {"ip":"192.168.1.15","user":"marek","mac":"b4:2e:99:a1:00:15","source":"DhcpLease"},
    {"ip":"192.168.1.16","user":"gosia","mac":"b4:2e:99:a1:00:16","source":"Radius"},
    {"ip":"192.168.1.17","user":"bartek","mac":"b4:2e:99:a1:00:17","source":"AdLog"},
    {"ip":"192.168.1.18","user":"ola","mac":"b4:2e:99:a1:00:18","source":"DhcpLease"},
    {"ip":"192.168.1.19","user":"jan","mac":"b4:2e:99:a1:00:19","source":"Radius"},
    {"ip":"192.168.1.20","user":"ewa","mac":"b4:2e:99:a1:00:20","source":"Radius"},
    {"ip":"192.168.1.21","user":"michal","mac":"b4:2e:99:a1:00:21","source":"AdLog"},
    {"ip":"192.168.1.22","user":"dorota","mac":"b4:2e:99:a1:00:22","source":"DhcpLease"},
    {"ip":"192.168.1.23","user":"piotr","mac":"b4:2e:99:a1:00:23","source":"Radius"},
    {"ip":"192.168.1.24","user":"magda","mac":"b4:2e:99:a1:00:24","source":"AdLog"}
  ]
}'
echo ""

# ─── 8. Serwery (VMware OUI: 00:50:56) ───
echo ">>> Import serwery (8)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.10.0.1","user":"srv_backup","mac":"00:50:56:01:00:01","source":"Manual"},
    {"ip":"10.10.0.2","user":"srv_db_primary","mac":"00:50:56:01:00:02","source":"Manual"},
    {"ip":"10.10.0.3","user":"srv_web_frontend","mac":"00:50:56:01:00:03","source":"Manual"},
    {"ip":"10.10.0.4","user":"srv_monitoring","mac":"00:50:56:01:00:04","source":"Manual"},
    {"ip":"10.10.0.5","user":"srv_db_replica","mac":"00:50:56:01:00:05","source":"Manual"},
    {"ip":"10.10.0.6","user":"srv_redis","mac":"00:50:56:01:00:06","source":"Manual"},
    {"ip":"10.10.0.7","user":"srv_ci_runner","mac":"00:50:56:01:00:07","source":"Manual"},
    {"ip":"10.10.0.8","user":"srv_log_collector","mac":"00:50:56:01:00:08","source":"Manual"}
  ]
}'
echo ""

# ─── 9. Dodatkowy ruch — 5 userow, Radius ───
echo ">>> Ruch Radius — 5 userow x 10 IP..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.0.1.100","user":"kacper","mac":"c0:ff:ee:01:64:01","source":"Radius"},
    {"ip":"10.0.1.101","user":"kacper","mac":"c0:ff:ee:01:65:02","source":"Radius"},
    {"ip":"10.0.1.102","user":"kacper","mac":"c0:ff:ee:01:66:03","source":"Radius"},
    {"ip":"10.0.1.103","user":"kacper","mac":"c0:ff:ee:01:67:04","source":"Radius"},
    {"ip":"10.0.1.104","user":"kacper","mac":"c0:ff:ee:01:68:05","source":"Radius"},
    {"ip":"10.0.1.105","user":"zuza","mac":"c0:ff:ee:02:69:01","source":"Radius"},
    {"ip":"10.0.1.106","user":"zuza","mac":"c0:ff:ee:02:6a:02","source":"Radius"},
    {"ip":"10.0.1.107","user":"zuza","mac":"c0:ff:ee:02:6b:03","source":"Radius"},
    {"ip":"10.0.1.108","user":"zuza","mac":"c0:ff:ee:02:6c:04","source":"Radius"},
    {"ip":"10.0.1.109","user":"zuza","mac":"c0:ff:ee:02:6d:05","source":"Radius"},
    {"ip":"10.0.1.110","user":"filip","mac":"c0:ff:ee:03:6e:01","source":"Radius"},
    {"ip":"10.0.1.111","user":"filip","mac":"c0:ff:ee:03:6f:02","source":"Radius"},
    {"ip":"10.0.1.112","user":"filip","mac":"c0:ff:ee:03:70:03","source":"Radius"},
    {"ip":"10.0.1.113","user":"filip","mac":"c0:ff:ee:03:71:04","source":"Radius"},
    {"ip":"10.0.1.114","user":"filip","mac":"c0:ff:ee:03:72:05","source":"Radius"},
    {"ip":"10.0.1.115","user":"natalia","mac":"c0:ff:ee:04:73:01","source":"Radius"},
    {"ip":"10.0.1.116","user":"natalia","mac":"c0:ff:ee:04:74:02","source":"Radius"},
    {"ip":"10.0.1.117","user":"natalia","mac":"c0:ff:ee:04:75:03","source":"Radius"},
    {"ip":"10.0.1.118","user":"natalia","mac":"c0:ff:ee:04:76:04","source":"Radius"},
    {"ip":"10.0.1.119","user":"natalia","mac":"c0:ff:ee:04:77:05","source":"Radius"},
    {"ip":"10.0.1.120","user":"igor","mac":"c0:ff:ee:05:78:01","source":"Radius"},
    {"ip":"10.0.1.121","user":"igor","mac":"c0:ff:ee:05:79:02","source":"Radius"},
    {"ip":"10.0.1.122","user":"igor","mac":"c0:ff:ee:05:7a:03","source":"Radius"},
    {"ip":"10.0.1.123","user":"igor","mac":"c0:ff:ee:05:7b:04","source":"Radius"},
    {"ip":"10.0.1.124","user":"igor","mac":"c0:ff:ee:05:7c:05","source":"Radius"}
  ]
}'
echo ""

# ─── 10. VPN (GlobalProtect) ───
echo ">>> Import VPN (10 zdalnych userow)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"172.16.0.1","user":"vpn_kowalski","mac":"fa:ce:00:00:00:01","source":"VpnLog"},
    {"ip":"172.16.0.2","user":"vpn_nowak","mac":"fa:ce:00:00:00:02","source":"VpnLog"},
    {"ip":"172.16.0.3","user":"vpn_wisniewska","mac":"fa:ce:00:00:00:03","source":"VpnLog"},
    {"ip":"172.16.0.4","user":"vpn_wojcik","mac":"fa:ce:00:00:00:04","source":"VpnLog"},
    {"ip":"172.16.0.5","user":"vpn_kaminski","mac":"fa:ce:00:00:00:05","source":"VpnLog"},
    {"ip":"172.16.0.6","user":"vpn_lewandowski","mac":"fa:ce:00:00:00:06","source":"VpnLog"},
    {"ip":"172.16.0.7","user":"vpn_zielinski","mac":"fa:ce:00:00:00:07","source":"VpnLog"},
    {"ip":"172.16.0.8","user":"vpn_szymanski","mac":"fa:ce:00:00:00:08","source":"VpnLog"},
    {"ip":"172.16.0.9","user":"vpn_wozniak","mac":"fa:ce:00:00:00:09","source":"VpnLog"},
    {"ip":"172.16.0.10","user":"vpn_dabrowski","mac":"fa:ce:00:00:00:0a","source":"VpnLog"}
  ]
}'
echo ""

# ─── 11. Management network ───
echo ">>> Import mgmt (5 urzadzen)..."
post "/api/v2/import/events" '{
  "events": [
    {"ip":"10.99.0.1","user":"sw_core_01","mac":"00:0c:29:01:01:01","source":"Manual"},
    {"ip":"10.99.0.2","user":"sw_access_02","mac":"00:0c:29:01:01:02","source":"Manual"},
    {"ip":"10.99.0.3","user":"fw_palo_01","mac":"00:0c:29:01:01:03","source":"Manual"},
    {"ip":"10.99.0.4","user":"ap_wifi_01","mac":"00:0c:29:01:01:04","source":"Manual"},
    {"ip":"10.99.0.5","user":"ups_dc1","mac":"00:0c:29:01:01:05","source":"Manual"}
  ]
}'
echo ""

# ─── 12. Tagi IP ───
echo ">>> Tagi (10)..."
post "/api/v2/tags" '{"ip":"10.10.0.1","tag":"server","color":"#00b4ff"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.10.0.2","tag":"database","color":"#ffb800"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.10.0.3","tag":"web","color":"#00ff41"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.10.0.5","tag":"database","color":"#ffb800"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.10.0.6","tag":"cache","color":"#a78bfa"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.10.0.7","tag":"ci-cd","color":"#00b4ff"}' > /dev/null
post "/api/v2/tags" '{"ip":"192.168.1.10","tag":"vip","color":"#a78bfa"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.0.1.5","tag":"quarantine","color":"#ff2d2d"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.99.0.3","tag":"firewall","color":"#ff2d2d"}' > /dev/null
post "/api/v2/tags" '{"ip":"10.99.0.1","tag":"core-switch","color":"#00b4ff"}' > /dev/null
echo " done"

# ─── 13. Alert rules ───
echo ">>> Alert rules (3)..."
post "/api/v2/alerts/rules" '{"name":"IP Conflict Detected","rule_type":"conflict_detected","severity":"critical","enabled":true}' > /dev/null
post "/api/v2/alerts/rules" '{"name":"New Server Subnet Mapping","rule_type":"new_mapping","severity":"warning","enabled":true,"conditions":{"subnet":"10.10.0.0/24"}}' > /dev/null
post "/api/v2/alerts/rules" '{"name":"VPN Pool Activity","rule_type":"new_mapping","severity":"info","enabled":true,"conditions":{"subnet":"172.16.0.0/24"}}' > /dev/null
echo " done"

# ─── 14. DNS entries ───
echo ">>> DNS (10 wpisow)..."
post "/api/v2/dns" '{"ip":"10.10.0.1","hostname":"backup.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.2","hostname":"db01.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.3","hostname":"web01.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.4","hostname":"mon.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.5","hostname":"db02.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.6","hostname":"redis01.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.7","hostname":"ci.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.10.0.8","hostname":"logs.trueid.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.99.0.1","hostname":"sw-core-01.mgmt.local","source":"Manual"}' > /dev/null
post "/api/v2/dns" '{"ip":"10.99.0.3","hostname":"fw-palo-01.mgmt.local","source":"Manual"}' > /dev/null
echo " done"

# ─── 15. Wiecej konfliktow (rozne zrodla na tym samym IP) ───
echo ">>> Wiecej konfliktow (dodatkowe zdarzenia)..."
post "/api/v2/import/events" '{"events":[
  {"ip":"10.0.1.100","user":"nieznany_1","mac":"ee:ee:ee:00:00:01","source":"DhcpLease"},
  {"ip":"10.0.1.105","user":"nieznany_2","mac":"ee:ee:ee:00:00:02","source":"AdLog"},
  {"ip":"192.168.1.10","user":"intruz_wifi","mac":"ee:ee:ee:00:00:03","source":"DhcpLease"},
  {"ip":"10.10.0.3","user":"nieautoryzowany","mac":"ee:ee:ee:00:00:04","source":"Radius"}
]}'
echo ""

# ─── 16. Weryfikacja ───
echo ""
echo "=== PODSUMOWANIE ==="
echo -n "Mappings:   "
curl -s -b cookies.txt "$BASE/api/v1/mappings" | grep -o '"total":[0-9]*' | cut -d: -f2
echo -n "Subnety:    "
curl -s -b cookies.txt "$BASE/api/v2/subnets" | grep -o '"total":[0-9]*' | cut -d: -f2
echo -n "DNS:        "
curl -s -b cookies.txt "$BASE/api/v2/dns" | grep -o '"total":[0-9]*' | cut -d: -f2
echo ""
echo "Gotowe! Odswież: http://localhost:3000"
echo ""
echo "UWAGA: Location/Subnet matching wymaga ok. 60s — engine przetworzy w tle."
echo "       Groups wymagaja LDAP — w demo beda puste."

# Cleanup
rm -f cookies.txt
