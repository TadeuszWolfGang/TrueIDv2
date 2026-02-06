//! TLS configuration — loading certificates and building rustls config.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// Builds a `TlsConnector` configured for mutual TLS.
///
/// Parameters: `ca_path` - path to CA certificate (PEM),
/// `cert_path` - path to client certificate (PEM),
/// `key_path` - path to client private key (PEM).
/// Returns: configured `TlsConnector` or an error.
pub fn build_tls_connector(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<TlsConnector> {
    let ca_certs = load_certs(ca_path)?;
    let client_certs = load_certs(cert_path)?;
    let client_key = load_private_key(key_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .context("adding CA certificate to root store")?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("building TLS client config with mTLS")?;

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Loads PEM-encoded certificates from a file.
///
/// Parameters: `path` - filesystem path to PEM file.
/// Returns: vector of parsed certificates or an error.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening cert: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certs from: {}", path.display()))?;
    Ok(certs)
}

/// Loads a PEM-encoded private key from a file.
///
/// Parameters: `path` - filesystem path to key PEM file.
/// Returns: parsed private key or an error.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening key: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing key from: {}", path.display()))?
        .with_context(|| format!("no private key found in: {}", path.display()))?;
    Ok(key)
}
