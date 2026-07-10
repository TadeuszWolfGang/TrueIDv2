//! Parser for Active Directory security events (XML from Windows Event Log).

use anyhow::{anyhow, Result};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use super::decode_xml_reference;

/// Parsed AD security event.
#[derive(Debug, Clone)]
pub struct AdEvent {
    pub event_id: u32,
    pub user: String,
    pub ip: String,
    pub port: String,
    pub status: String,
}

/// Parses a Windows Security event XML into an `AdEvent`.
///
/// Supports Event IDs 4768, 4769, 4770, 4624, 4625.
/// Extracts TargetUserName, IpAddress, IpPort, Status from EventData.
///
/// Parameters: `xml` - raw XML string from EvtRender.
/// Returns: parsed `AdEvent` or an error.
pub fn parse_ad_xml(xml: &str) -> Result<AdEvent> {
    let mut reader = Reader::from_str(xml);

    let mut event_id: Option<u32> = None;
    let mut user: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut port: Option<String> = None;
    let mut status: Option<String> = None;

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
                                "TargetUserName" => user = Some(text),
                                "IpAddress" => {
                                    // Strip leading "::ffff:" for IPv4-mapped addresses.
                                    let clean = text.strip_prefix("::ffff:").unwrap_or(&text);
                                    ip = Some(clean.to_string());
                                }
                                "IpPort" => port = Some(text),
                                "Status" => status = Some(text),
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

    Ok(AdEvent {
        event_id: event_id.ok_or_else(|| anyhow!("missing EventID"))?,
        user: user.unwrap_or_default(),
        ip: ip.unwrap_or_default(),
        port: port.unwrap_or_else(|| "0".to_string()),
        status: status.unwrap_or_else(|| "0x0".to_string()),
    })
}
