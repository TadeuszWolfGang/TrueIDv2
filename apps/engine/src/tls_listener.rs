//! TCP+TLS syslog listener with mutual TLS for secure agent connections.
//!
//! Runs alongside the existing UDP listeners. After TLS handshake,
//! reads RFC 5425 octet-counted syslog frames and forwards raw payloads
//! into the same `mpsc::Sender<IdentityEvent>` pipeline as UDP.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// Callback that receives a decrypted syslog payload string and the peer address.
pub type MessageHandler = Arc<dyn Fn(&str, SocketAddr) + Send + Sync>;

/// Builds a `TlsAcceptor` configured for mutual TLS (client cert verification).
///
/// Parameters: `ca_path` - CA cert for client verification,
/// `cert_path` - server certificate, `key_path` - server private key.
/// Returns: configured `TlsAcceptor` or an error.
pub fn build_tls_acceptor(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<TlsAcceptor> {
    let ca_certs = load_certs(ca_path)?;
    let server_certs = load_certs(cert_path)?;
    let server_key = load_private_key(key_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .context("adding CA cert to root store")?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("building client verifier")?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("building TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Runs the TLS syslog listener, accepting connections and parsing frames.
///
/// Parameters: `bind_addr` - address to bind, `acceptor` - TLS acceptor,
/// `handler` - callback for each decoded syslog message, `label` - listener name.
pub async fn run_tls_listener(
    bind_addr: SocketAddr,
    acceptor: TlsAcceptor,
    handler: MessageHandler,
    label: &'static str,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, label, "TLS syslog listener started");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let handler = handler.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    info!(%peer, label, "TLS client connected");
                    if let Err(err) = handle_tls_client(tls_stream, peer, handler, label).await {
                        warn!(%peer, label, error = %err, "TLS client error");
                    }
                }
                Err(err) => {
                    warn!(%peer, label, error = %err, "TLS handshake failed");
                }
            }
        });
    }
}

/// Handles a single TLS client, reading octet-counted syslog frames.
///
/// Parameters: `stream` - accepted TLS stream, `peer` - remote address,
/// `handler` - message callback, `label` - listener name.
/// Returns: `Ok(())` on client disconnect or an error.
async fn handle_tls_client(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: SocketAddr,
    handler: MessageHandler,
    label: &str,
) -> Result<()> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            info!(%peer, label, "TLS client disconnected");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);

        // Parse all complete octet-counted frames in the buffer.
        while let Some((msg, consumed)) = parse_octet_frame(&buf) {
            handler(&msg, peer);
            buf.drain(..consumed);
        }
    }
}

/// Parses an RFC 5425 octet-counted frame from a byte buffer.
///
/// Parameters: `buf` - input bytes.
/// Returns: `Some((message, consumed_bytes))` or `None` if incomplete.
fn parse_octet_frame(buf: &[u8]) -> Option<(String, usize)> {
    let space_pos = buf.iter().position(|&b| b == b' ')?;
    let len_str = std::str::from_utf8(&buf[..space_pos]).ok()?;
    let msg_len: usize = len_str.parse().ok()?;
    let total = space_pos + 1 + msg_len;
    if buf.len() < total {
        return None;
    }
    let msg = std::str::from_utf8(&buf[space_pos + 1..space_pos + 1 + msg_len])
        .ok()?
        .to_string();
    let consumed = if buf.len() > total && buf[total] == b'\n' {
        total + 1
    } else {
        total
    };
    Some((msg, consumed))
}

/// Loads PEM certificates from a file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certs: {}", path.display()))
}

/// Loads a PEM private key from a file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing key: {}", path.display()))?
        .with_context(|| format!("no key found in: {}", path.display()))
}
