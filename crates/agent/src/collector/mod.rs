//! Event collectors: Windows Event Log subscription and XML parsers.

use anyhow::{anyhow, Result};
use quick_xml::{escape::resolve_xml_entity, events::BytesRef};

pub mod ad_events;
pub mod dhcp_events;
pub mod evtlog;

pub(super) fn decode_xml_reference(reference: &BytesRef<'_>) -> Result<String> {
    if let Some(ch) = reference.resolve_char_ref()? {
        return Ok(ch.to_string());
    }

    let name = reference.decode()?;
    resolve_xml_entity(name.as_ref())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("unsupported XML entity reference: &{};", name))
}
