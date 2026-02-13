//! Vendor lookup helpers backed by OUI CSV.

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

/// OUI-to-vendor lookup table (key: uppercase 6-char hex prefix).
pub(crate) type VendorMap = HashMap<String, String>;

/// Loads the IEEE OUI database from CSV into a vendor map.
///
/// Parameters: `path` - filesystem path to `oui.csv`.
/// Returns: populated vendor map or CSV parsing error.
pub(crate) fn load_oui_csv(path: &Path) -> Result<VendorMap> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut map = HashMap::with_capacity(40_000);
    let mut sample_count = 0_u32;

    for result in reader.records() {
        let record = result?;
        let oui = record.get(1).unwrap_or("").trim().to_ascii_uppercase();
        let vendor = record.get(2).unwrap_or("").trim().to_string();

        if sample_count < 5 {
            info!(oui = %oui, vendor = %vendor, "Sample parsed");
            sample_count += 1;
        }

        if !oui.is_empty() && !vendor.is_empty() {
            map.insert(oui, vendor);
        }
    }
    Ok(map)
}

/// Resolves a MAC address to a vendor using the OUI map.
///
/// Parameters: `mac` - raw MAC with arbitrary separators, `vendors` - OUI map.
/// Returns: vendor name when OUI is present in the map.
pub(crate) fn resolve_vendor(mac: &str, vendors: &VendorMap) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    let oui_key = &hex[..6];
    info!(oui_key = %oui_key, mac = %mac, "Looking up OUI");
    vendors.get(oui_key).cloned()
}
