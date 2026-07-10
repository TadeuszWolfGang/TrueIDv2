//! Unit tests for XML event parsers and syslog framing.

use net_identity_agent::collector::ad_events::parse_ad_xml;
use net_identity_agent::collector::dhcp_events::parse_dhcp_xml;
use net_identity_agent::transport::syslog::{
    format_ad_event, format_dhcp_event, format_heartbeat, frame_octet_counting, parse_octet_frame,
};

const EVENT_4768_XML: &str = include_str!("fixtures/event_4768.xml");
const EVENT_4624_XML: &str = include_str!("fixtures/event_4624.xml");
const DHCP_10_XML: &str = include_str!("fixtures/dhcp_event_10.xml");

#[test]
fn parse_kerberos_tgt_4768() {
    let ev = parse_ad_xml(EVENT_4768_XML).expect("failed to parse 4768");
    assert_eq!(ev.event_id, 4768);
    assert_eq!(ev.user, "jan.kowalski");
    assert_eq!(ev.ip, "10.0.1.50"); // ::ffff: prefix stripped
    assert_eq!(ev.port, "52431");
    assert_eq!(ev.status, "0x0");
}

#[test]
fn parse_logon_4624() {
    let ev = parse_ad_xml(EVENT_4624_XML).expect("failed to parse 4624");
    assert_eq!(ev.event_id, 4624);
    assert_eq!(ev.user, "jan.kowalski");
    assert_eq!(ev.ip, "10.0.1.50");
    assert_eq!(ev.port, "52432");
}

#[test]
fn parse_dhcp_new_lease() {
    let ev = parse_dhcp_xml(DHCP_10_XML).expect("failed to parse DHCP 10");
    assert_eq!(ev.event_id, 10);
    assert_eq!(ev.ip, "10.0.1.50");
    assert_eq!(ev.mac, "AA:BB:CC:DD:EE:FF");
    assert_eq!(ev.hostname, "WORKSTATION01");
    assert_eq!(ev.lease_duration, 86400);
}

#[test]
fn parse_ad_xml_preserves_entity_fragments() {
    let xml = r#"<Event><System><EventID>47&#54;8</EventID></System><EventData><Data Name="TargetUserName">Alice &amp; Bob</Data></EventData></Event>"#;
    let ev = parse_ad_xml(xml).expect("failed to parse entity fragments");

    assert_eq!(ev.event_id, 4768);
    assert_eq!(ev.user, "Alice & Bob");
}

#[test]
fn parse_dhcp_xml_preserves_entity_fragments() {
    let xml = r#"<Event><System><EventID>10</EventID></System><EventData><Data Name="HostName">WORK&#x53;TATION &amp; LAB</Data></EventData></Event>"#;
    let ev = parse_dhcp_xml(xml).expect("failed to parse entity fragments");

    assert_eq!(ev.hostname, "WORKSTATION & LAB");
}

#[test]
fn parse_ad_xml_rejects_unknown_entity() {
    let xml = r#"<Event><System><EventID>4768</EventID></System><EventData><Data Name="TargetUserName">Alice &unknown;</Data></EventData></Event>"#;

    assert!(parse_ad_xml(xml).is_err());
}

#[test]
fn parse_ad_xml_rejects_doctype() {
    let xml = r#"<!DOCTYPE Event [<!ENTITY user "Alice">]><Event><System><EventID>4768</EventID></System><EventData><Data Name="TargetUserName">&user;</Data></EventData></Event>"#;

    assert!(parse_ad_xml(xml).is_err());
}

#[test]
fn syslog_ad_format() {
    let msg = format_ad_event("DC01", "jan.kowalski", "10.0.1.50", "52431", 4768, "0x0");
    assert!(msg.contains("<13>"));
    assert!(msg.contains("TrueID-Agent: AD_LOGON"));
    assert!(msg.contains("user=jan.kowalski"));
    assert!(msg.contains("ip=10.0.1.50"));
    assert!(msg.contains("event_id=4768"));
}

#[test]
fn syslog_dhcp_format() {
    let msg = format_dhcp_event(
        "DHCP01",
        "10.0.1.50",
        "AA:BB:CC:DD:EE:FF",
        "WORKSTATION01",
        86400,
    );
    assert!(msg.contains("<13>"));
    assert!(msg.contains("TrueID-Agent: DHCP_LEASE"));
    assert!(msg.contains("mac=AA:BB:CC:DD:EE:FF"));
    assert!(msg.contains("hostname=WORKSTATION01"));
}

#[test]
fn syslog_heartbeat_format() {
    let msg = format_heartbeat("DC01", 3600, 1542, 0);
    assert!(msg.contains("HEARTBEAT"));
    assert!(msg.contains("uptime=3600"));
    assert!(msg.contains("events_sent=1542"));
    assert!(msg.contains("transport=tls"));
}

#[test]
fn octet_counting_roundtrip() {
    let payload = "<13>Jan 29 12:30:00 DC01 TrueID-Agent: AD_LOGON user=test ip=1.2.3.4";
    let frame = frame_octet_counting(payload);
    let (parsed, consumed) = parse_octet_frame(&frame).expect("failed to parse frame");
    assert_eq!(parsed, payload);
    assert_eq!(consumed, frame.len());
}

#[test]
fn octet_counting_incomplete() {
    let result = parse_octet_frame(b"100 short");
    assert!(result.is_none(), "incomplete frame should return None");
}
