//! Parser for Windows DHCP Server events (XML from Event Log).

use anyhow::{anyhow, Result};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use super::decode_xml_reference;

/// Parsed DHCP event.
#[derive(Debug, Clone)]
pub struct DhcpEvent {
    pub event_id: u32,
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub lease_duration: u32,
}

/// Parses a Windows DHCP Server event XML into a `DhcpEvent`.
///
/// Supports Event IDs 10 (new lease), 11 (renewed), 12 (released).
/// Extracts IP Address, MAC Address, Host Name, Lease Duration from EventData.
///
/// Parameters: `xml` - raw XML string from EvtRender.
/// Returns: parsed `DhcpEvent` or an error.
pub fn parse_dhcp_xml(xml: &str) -> Result<DhcpEvent> {
    let mut reader = Reader::from_str(xml);

    let mut event_id: Option<u32> = None;
    let mut ip: Option<String> = None;
    let mut mac: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut lease_duration: Option<u32> = None;

    let mut in_system = false;
    let mut in_event_data = false;
    let mut current_data_name: Option<String> = None;
    let mut capture_event_id = false;
    let mut event_id_text = String::new();
    let mut current_data_value = String::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "System" => in_system = true,
                    "EventID" if in_system => {
                        capture_event_id = true;
                        event_id_text.clear();
                    }
                    "EventData" => in_event_data = true,
                    "Data" if in_event_data => {
                        current_data_name = None;
                        current_data_value.clear();
                        for attr in e.attributes() {
                            let attr = attr?;
                            if attr.key.as_ref() == b"Name" {
                                current_data_name = Some(
                                    attr.decoded_and_normalized_value(
                                        XmlVersion::Implicit1_0,
                                        e.decoder(),
                                    )?
                                    .into_owned(),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "System" => in_system = false,
                    "EventID" if capture_event_id => {
                        event_id = Some(
                            event_id_text
                                .trim()
                                .parse()
                                .map_err(|_| anyhow!("invalid EventID"))?,
                        );
                        capture_event_id = false;
                    }
                    "EventData" => in_event_data = false,
                    "Data" => {
                        if let Some(name) = current_data_name.take() {
                            let text = current_data_value.trim().to_string();
                            match name.as_str() {
                                "IPAddress" | "IP Address" => ip = Some(text),
                                "MACAddress" | "MAC Address" => mac = Some(text),
                                "HostName" | "Host Name" => hostname = Some(text),
                                "LeaseDuration" | "Lease Duration" => {
                                    lease_duration = text.parse().ok();
                                }
                                _ => {}
                            }
                        }
                        current_data_value.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if capture_event_id {
                    event_id_text.push_str(&e.xml10_content()?);
                }
                if current_data_name.is_some() {
                    current_data_value.push_str(&e.xml10_content()?);
                }
            }
            Ok(Event::CData(ref e)) => {
                if capture_event_id {
                    event_id_text.push_str(&e.xml10_content()?);
                }
                if current_data_name.is_some() {
                    current_data_value.push_str(&e.xml10_content()?);
                }
            }
            Ok(Event::GeneralRef(ref e)) => {
                let value = decode_xml_reference(e)?;
                if capture_event_id {
                    event_id_text.push_str(&value);
                }
                if current_data_name.is_some() {
                    current_data_value.push_str(&value);
                }
            }
            Ok(Event::DocType(_)) => return Err(anyhow!("DOCTYPE is not supported")),
            Ok(Event::Eof) => break,
            Err(err) => return Err(anyhow!("XML parse error: {}", err)),
            _ => {}
        }
        buf.clear();
    }

    Ok(DhcpEvent {
        event_id: event_id.ok_or_else(|| anyhow!("missing EventID"))?,
        ip: ip.unwrap_or_default(),
        mac: mac.unwrap_or_default(),
        hostname: hostname.unwrap_or_default(),
        lease_duration: lease_duration.unwrap_or(0),
    })
}
