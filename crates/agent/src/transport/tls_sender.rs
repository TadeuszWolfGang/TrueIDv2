//! Persistent TCP+TLS sender with exponential-backoff reconnect.

use crate::transport::buffer::RingBuffer;
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

/// Counters shared with the heartbeat task.
pub struct SenderStats {
    pub events_sent: AtomicU64,
    pub events_dropped: AtomicU64,
}

impl SenderStats {
    /// Creates zeroed counters.
    pub fn new() -> Self {
        Self {
            events_sent: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        }
    }
}

/// Runs the sender loop: reads framed messages from `rx`, sends over TLS,
/// buffers on failure, reconnects with exponential backoff.
///
/// Parameters: `connector` - TLS connector, `server` - target host,
/// `port` - target port, `rx` - incoming framed messages,
/// `buffer_cap` - ring buffer capacity, `stats` - shared counters,
/// `initial_backoff_secs` - starting reconnect delay.
pub async fn run_sender(
    connector: TlsConnector,
    server: String,
    port: u16,
    mut rx: mpsc::Receiver<Vec<u8>>,
    buffer_cap: usize,
    stats: &SenderStats,
    initial_backoff_secs: u64,
) {
    let mut buffer = RingBuffer::new(buffer_cap);
    let mut stream: Option<TlsStream<TcpStream>> = None;
    let mut backoff = Duration::from_secs(initial_backoff_secs);
    let max_backoff = Duration::from_secs(60);
    let server_name: ServerName<'static> = ServerName::try_from(server.clone())
        .unwrap_or_else(|_| ServerName::try_from("localhost".to_string()).unwrap());

    loop {
        // Ensure we have a connection.
        if stream.is_none() {
            match connect(&connector, &server, port, server_name.clone()).await {
                Ok(s) => {
                    info!(server = %server, port, "TLS connection established");
                    stream = Some(s);
                    backoff = Duration::from_secs(initial_backoff_secs);
                    // Flush buffer.
                    flush_buffer(&mut buffer, stream.as_mut().unwrap(), stats).await;
                }
                Err(err) => {
                    warn!(error = %err, backoff_secs = backoff.as_secs(), "TLS connect failed, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }
            }
        }

        // Wait for the next message.
        let Some(data) = rx.recv().await else {
            // Channel closed — graceful shutdown.
            if let Some(mut s) = stream.take() {
                flush_buffer(&mut buffer, &mut s, stats).await;
                let _ = s.shutdown().await;
            }
            return;
        };

        // Try to send.
        if let Some(ref mut s) = stream {
            if let Err(err) = s.write_all(&data).await {
                warn!(error = %err, "TLS write failed, buffering");
                buffer.push(data);
                stats.events_dropped.store(buffer.dropped(), Ordering::Relaxed);
                stream = None; // Force reconnect on next iteration.
            } else {
                stats.events_sent.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            buffer.push(data);
        }
    }
}

/// Establishes a new TCP+TLS connection.
///
/// Parameters: `connector` - TLS config, `server` - host, `port` - port,
/// `name` - SNI server name.
/// Returns: connected TLS stream or an error.
async fn connect(
    connector: &TlsConnector,
    server: &str,
    port: u16,
    name: ServerName<'static>,
) -> Result<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", server, port);
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {}", addr))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .context("TLS handshake")?;
    Ok(tls)
}

/// Flushes all buffered messages over an active TLS stream.
///
/// Parameters: `buffer` - ring buffer to drain, `stream` - TLS stream,
/// `stats` - shared counters.
async fn flush_buffer(
    buffer: &mut RingBuffer,
    stream: &mut TlsStream<TcpStream>,
    stats: &SenderStats,
) {
    if buffer.is_empty() {
        return;
    }
    info!(count = buffer.len(), "Flushing buffered messages");
    for data in buffer.drain() {
        if let Err(err) = stream.write_all(&data).await {
            warn!(error = %err, "Flush write failed, dropping remaining");
            return;
        }
        stats.events_sent.fetch_add(1, Ordering::Relaxed);
    }
}
