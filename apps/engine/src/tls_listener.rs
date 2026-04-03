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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

const MAX_FRAME_SIZE: usize = 65_536;
#[cfg(test)]
const FRAME_READ_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
async fn handle_tls_client<S>(
    mut stream: S,
    peer: SocketAddr,
    handler: MessageHandler,
    label: &str,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    loop {
        let n = if buf.is_empty() {
            stream.read(&mut tmp).await?
        } else {
            match tokio::time::timeout(FRAME_READ_TIMEOUT, stream.read(&mut tmp)).await {
                Ok(Ok(read)) => read,
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => anyhow::bail!(
                    "TLS frame read timeout after {}s",
                    FRAME_READ_TIMEOUT.as_secs_f64()
                ),
            }
        };
        if n == 0 {
            info!(%peer, label, "TLS client disconnected");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(declared_len) = parse_declared_frame_len(&buf) {
            if declared_len > MAX_FRAME_SIZE {
                anyhow::bail!(
                    "TLS frame declared size {declared_len} exceeds max {MAX_FRAME_SIZE}"
                );
            }
        }

        // Parse all complete octet-counted frames in the buffer.
        while let Some((msg, consumed)) = parse_octet_frame(&buf) {
            handler(&msg, peer);
            buf.drain(..consumed);
        }
        if buf.len() > MAX_FRAME_SIZE {
            anyhow::bail!("TLS frame buffer exceeded max {MAX_FRAME_SIZE} bytes");
        }
    }
}

/// Parses only the declared frame length from an RFC 5425 buffer prefix.
fn parse_declared_frame_len(buf: &[u8]) -> Option<usize> {
    let space_pos = buf.iter().position(|&b| b == b' ')?;
    let len_str = std::str::from_utf8(&buf[..space_pos]).ok()?;
    len_str.parse().ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{duplex, AsyncWriteExt};

    fn test_peer() -> SocketAddr {
        "127.0.0.1:5514".parse().expect("peer parse failed")
    }

    #[tokio::test]
    async fn test_handle_tls_client_rejects_oversized_declared_frame() {
        let (mut client, server) = duplex(256);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = calls.clone();
        let handler: MessageHandler = Arc::new(move |_, _| {
            handler_calls.fetch_add(1, Ordering::Relaxed);
        });

        let task =
            tokio::spawn(
                async move { handle_tls_client(server, test_peer(), handler, "test").await },
            );
        client
            .write_all(format!("{} ", MAX_FRAME_SIZE + 1).as_bytes())
            .await
            .expect("write oversized prefix failed");

        let err = task
            .await
            .expect("join failed")
            .expect_err("oversized frame should fail");
        assert!(
            err.to_string().contains("exceeds max"),
            "unexpected error: {err}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_handle_tls_client_times_out_on_incomplete_frame() {
        let (mut client, server) = duplex(256);
        let handler: MessageHandler = Arc::new(|_, _| {});
        let task =
            tokio::spawn(
                async move { handle_tls_client(server, test_peer(), handler, "test").await },
            );
        client
            .write_all(b"10 hello")
            .await
            .expect("write partial frame failed");

        let err = task
            .await
            .expect("join failed")
            .expect_err("incomplete frame should time out");
        assert!(
            err.to_string().contains("timeout"),
            "unexpected error: {err}"
        );
    }
}
