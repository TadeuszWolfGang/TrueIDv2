# IDsense Integration Guide

This guide explains how to configure your infrastructure to send identity signals
to IDsense. Use the examples below as copy-ready starting points.

## A. Active Directory (Windows Server)
Windows does not natively send Syslog. Install an agent such as **NXLog Community
Edition** to forward Security events to IDsense.

### NXLog example (Security log, Event ID 4624, UDP Syslog)
```conf
define IDSENSE_HOST 192.168.1.X
define IDSENSE_PORT 5514

<Input in_security>
    Module im_msvistalog
    Query <QueryList>\
            <Query Id="0">\
                <Select Path="Security">\
                    *[System[(EventID=4624)]]\
                </Select>\
            </Query>\
          </QueryList>
</Input>

<Processor add_fields>
    Module pm_null
    Exec $Message = "TargetUserName=" + $EventData.TargetUserName + \
                    " IpAddress=" + $EventData.IpAddress;
</Processor>

<Output out_syslog>
    Module om_udp
    Host %IDSENSE_HOST%
    Port %IDSENSE_PORT%
    Exec to_syslog_ietf(); # RFC 5424 (use to_syslog_bsd() for RFC 3164)
</Output>

<Route r_security>
    Path in_security => add_fields => out_syslog
</Route>
```

## B. RADIUS (FreeRADIUS / Windows NPS)
IDsense acts as an **Accounting Server**. Configure your RADIUS infrastructure to
send accounting packets to IDsense.

### FreeRADIUS (option 1: proxy/mirror accounting to IDsense)
```conf
# raddb/proxy.conf
home_server idsense_acct {
    type = acct
    ipaddr = 192.168.1.X
    port = 1813
    secret = sharedsecret
}

home_server_pool idsense_pool {
    type = fail-over
    home_server = idsense_acct
}

realm idsense {
    acct_pool = idsense_pool
}
```

```conf
# raddb/acct_users
DEFAULT
    Proxy-To-Realm := "idsense"
```

### FreeRADIUS (option 2: add IDsense as a client/NAS)
```conf
# raddb/clients.conf
client idsense {
    ipaddr = 192.168.1.X
    secret = sharedsecret
    shortname = idsense
}
```

### Windows NPS (Accounting)
1. Open **NPS** → **Accounting** → **Accounting Requests**.
2. Create or edit a **Remote RADIUS Server Group**.
3. Add the IDsense server IP and set **Accounting** to send to that group.

## C. DHCP (ISC DHCP / Kea / Dnsmasq)
IDsense listens for **DHCPACK** log messages. Forward DHCP daemon logs to IDsense
over UDP (port 5516).

### ISC DHCP / Linux (rsyslog)
```conf
# /etc/rsyslog.d/30-dhcp-forward.conf
if $programname == 'dhcpd' and $msg contains 'DHCPACK' then @192.168.1.X:5516
& stop
```
