//! Iroh QUIC-based P2P streaming layer for RLN.
//!
//! This module provides two primary operations:
//! - **Receiving**: [`P2pNode::listen_for_peers`] accepts incoming QUIC connections,
//!   authenticates the remote peer via Ed25519, receives chunked files, and verifies
//!   the SHA-256 digest supplied by the sender.
//! - **Sending**: [`P2pNode::send_file`] connects to a peer, chunks a local file,
//!   hashes it incrementally, and transmits the final digest for receiver verification.
//!
//! ## Wire Protocol
//! ```text
//! Client → Server:
//!   [u32 big-endian] filename_length
//!   [u8; filename_length] filename_utf8
//!   [u64 big-endian] file_size_bytes
//!   [u8; file_size] file_data (chunked, 64 KB at a time)
//!   [u8; 64] sha256_hex_digest  (lowercase ASCII)
//! ```
//!
//! ## Iroh 0.98 API Notes
//! - `Endpoint::builder(presets::N0)` replaces the old zero-arg builder
//! - `endpoint.id()` returns `EndpointId` (replaces `node_id()` → `NodeId`)
//! - `connection.remote_id()` replaces `get_remote_node_id(&conn)`
//! - `send_stream.finish()` is now synchronous (no `?` needed for async)
use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointId, SecretKey};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// The ALPN identifier for the RLN protocol.
/// Only peers advertising this identifier will be accepted.
pub const RLN_ALPN: &[u8] = b"rln/v2.0";

/// The P2P networking node backed by Iroh's QUIC endpoint.
pub struct P2pNode {
    /// The underlying Iroh endpoint. Exposed publicly so tests and advanced
    /// callers can query the local node ID or create connections directly.
    pub endpoint: Endpoint,
}

impl P2pNode {
    /// Initializes an Iroh `Endpoint` using a pre-existing Ed25519 secret key.
    ///
    /// The endpoint uses the `N0` preset (enables n0.computer relay + PKARR DNS),
    /// listening on a random OS-assigned UDP port and filtering connections by
    /// the [`RLN_ALPN`] identifier.
    ///
    /// # Errors
    /// Returns an error if the underlying QUIC socket cannot be bound.
    pub async fn new(secret_key_bytes: &[u8; 32]) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(secret_key_bytes);

        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![RLN_ALPN.to_vec()])
            .bind()
            .await
            .context("Failed to bind Iroh Endpoint")?;

        Ok(Self { endpoint })
    }

    /// Accepts incoming QUIC connections in a loop and spawns a handler task per peer.
    ///
    /// Each accepted connection goes through Iroh's mutual Ed25519 authentication
    /// before the stream reading begins. Progress events are forwarded to the TUI
    /// via the supplied `tx` channel.
    ///
    /// This function runs indefinitely and should be spawned as a background task.
    ///
    /// # Errors
    /// Returns `Ok(())` when the endpoint is closed gracefully.
    pub async fn listen_for_peers(
        self: Arc<Self>,
        tx: tokio::sync::mpsc::Sender<crate::tui::event::AppEvent>,
    ) -> Result<()> {
        // In iroh 0.98, endpoint.id() returns EndpointId (the new name for NodeId)
        let node_id = self.endpoint.id();
        let _ = tx
            .send(crate::tui::event::AppEvent::Log(format!(
                "[P2P] Node online. ID: {}",
                node_id
            )))
            .await;

        // accept() now returns an Accept stream iterator-style
        while let Some(incoming) = self.endpoint.accept().await {
            let connecting = match incoming.accept() {
                Ok(conn) => conn,
                Err(e) => {
                    let _ = tx
                        .send(crate::tui::event::AppEvent::Log(format!(
                            "[WARNING] [P2P] Rejected connection: {}",
                            e
                        )))
                        .await;
                    continue;
                }
            };

            let tx_clone = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming_connection(connecting, tx_clone).await {
                    eprintln!("[ERROR] [P2P] Connection handler error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Connects to a remote peer and sends a file using the RLN wire protocol.
    ///
    /// The file is read in 64 KB chunks, hashed incrementally, and the final
    /// SHA-256 hex digest is appended to the stream for the receiver to verify.
    /// Transfer progress is emitted to the TUI via the `tx` channel.
    ///
    /// In iroh 0.98, we connect using an `EndpointId` (previously `NodeId`).
    ///
    /// # Errors
    /// Returns an error if the connection, file open, or any stream write fails.
    pub async fn send_file(
        self: Arc<Self>,
        // In iroh 0.98, NodeId is replaced by EndpointId
        peer_id: EndpointId,
        file_path: &std::path::Path,
        tx: tokio::sync::mpsc::Sender<crate::tui::event::AppEvent>,
    ) -> Result<()> {
        use crate::app::TransferState;
        use crate::transfer::hash::HashVerification;
        use std::time::Instant;
        use tokio::io::AsyncReadExt;

        // Validate file_path has a usable filename before connecting
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("file_path does not have a valid filename component")?
            .to_string();

        // connect() now takes an EndpointAddr or EndpointId (which impl Into<EndpointAddr>)
        let connection = self
            .endpoint
            .connect(peer_id, RLN_ALPN)
            .await
            .context("Failed to connect to peer")?;

        let (mut send_stream, _recv_stream) = connection
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        let mut file = tokio::fs::File::open(file_path).await?;
        let file_size = file.metadata().await?.len();
        if file_size == 0 {
            bail!("Cannot transfer an empty file: {}", filename);
        }
        let peer_id_str = peer_id.to_string();

        // --- Wire protocol: header ---
        let filename_bytes = filename.as_bytes();
        send_stream
            .write_all(&(filename_bytes.len() as u32).to_be_bytes())
            .await?;
        send_stream.write_all(filename_bytes).await?;
        send_stream.write_all(&file_size.to_be_bytes()).await?;

        // --- Wire protocol: file chunks ---
        let mut hasher = HashVerification::new();
        let mut buffer = [0u8; 65_536]; // 64 KB
        let mut sent_bytes = 0u64;
        let start_time = Instant::now();
        let mut last_ui_update = Instant::now();

        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break; // EOF
            }

            hasher.update(&buffer[..n]);
            send_stream.write_all(&buffer[..n]).await?;
            sent_bytes += n as u64;

            // Throttle TUI updates to ~4 Hz to avoid channel flooding
            if last_ui_update.elapsed().as_millis() > 250 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let speed_mbps = (sent_bytes as f64 * 8.0) / (elapsed * 1_000_000.0).max(1.0);
                let progress_pct = ((sent_bytes as f64 / file_size as f64) * 100.0) as u8;

                let _ = tx
                    .send(crate::tui::event::AppEvent::TransferProgress(
                        TransferState {
                            filename: filename.clone(),
                            peer_id: peer_id_str.clone(),
                            progress_pct,
                            speed_mbps,
                        },
                    ))
                    .await;
                last_ui_update = Instant::now();
            }
        }

        // --- Wire protocol: trailing hash ---
        let final_hash = hasher.finalize();
        send_stream.write_all(final_hash.as_bytes()).await?;
        // In iroh 0.98, finish() is still synchronous
        send_stream
            .finish()
            .context("Failed to finish send stream")?;

        let _ = tx
            .send(crate::tui::event::AppEvent::Log(format!(
                "[SUCCESS] [P2P] Sent {} → {}  sha256: {}",
                filename, peer_id_str, final_hash
            )))
            .await;

        Ok(())
    }
}

/// Handles a single authenticated incoming connection: reads the file stream
/// frame-by-frame, hashes the payload, and verifies the sender's digest.
async fn handle_incoming_connection(
    // In iroh 0.98, this is an Accepting (awaitable future → Connection)
    connecting: iroh::endpoint::Accepting,
    tx: tokio::sync::mpsc::Sender<crate::tui::event::AppEvent>,
) -> Result<()> {
    use crate::app::TransferState;
    use crate::transfer::hash::HashVerification;
    use std::time::Instant;

    let connection = connecting.await.context("Incoming connection failed")?;

    // In iroh 0.98, remote_id() replaces get_remote_node_id()
    let peer_id = connection.remote_id();
    let peer_id_str = peer_id.to_string();

    let _ = tx
        .send(crate::tui::event::AppEvent::Log(format!(
            "[P2P] Authenticated connection from: {}",
            peer_id_str
        )))
        .await;

    let (_send_stream, mut recv_stream) = connection
        .accept_bi()
        .await
        .context("Failed to accept bidirectional stream")?;

    // --- Read header ---
    let mut len_buf = [0u8; 4];
    recv_stream.read_exact(&mut len_buf).await?;
    let filename_len = u32::from_be_bytes(len_buf) as usize;

    if filename_len == 0 || filename_len > 4096 {
        bail!("Received invalid filename length: {}", filename_len);
    }

    let mut filename_buf = vec![0u8; filename_len];
    recv_stream.read_exact(&mut filename_buf).await?;
    let filename = String::from_utf8(filename_buf).context("Filename is not valid UTF-8")?;

    let mut size_buf = [0u8; 8];
    recv_stream.read_exact(&mut size_buf).await?;
    let file_size = u64::from_be_bytes(size_buf);

    if file_size == 0 {
        bail!("Peer sent zero-length file: {}", filename);
    }

    // --- Ensure downloads directory exists ---
    let data_dir = std::env::var("RLN_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let downloads_dir = std::path::Path::new(&data_dir).join("downloads");
    tokio::fs::create_dir_all(&downloads_dir).await.context("Failed to create downloads directory")?;
    
    let safe_filename = std::path::Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file");
        
    let out_path = downloads_dir.join(safe_filename);
    let mut out_file = tokio::fs::File::create(&out_path).await.context("Failed to create output file")?;

    // --- Read file chunks ---
    let mut hasher = HashVerification::new();
    let mut received_bytes = 0u64;
    let mut buffer = [0u8; 65_536];
    let start_time = Instant::now();
    let mut last_ui_update = Instant::now();

    while received_bytes < file_size {
        let to_read = std::cmp::min(buffer.len() as u64, file_size - received_bytes) as usize;

        match recv_stream.read_exact(&mut buffer[..to_read]).await {
            Ok(_) => {
                hasher.update(&buffer[..to_read]);
                out_file.write_all(&buffer[..to_read]).await.context("Failed to write to local file")?;
                received_bytes += to_read as u64;

                if last_ui_update.elapsed().as_millis() > 250 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let speed_mbps =
                        (received_bytes as f64 * 8.0) / (elapsed * 1_000_000.0).max(1.0);
                    let progress_pct = ((received_bytes as f64 / file_size as f64) * 100.0) as u8;

                    let _ = tx
                        .send(crate::tui::event::AppEvent::TransferProgress(
                            TransferState {
                                filename: filename.clone(),
                                peer_id: peer_id_str.clone(),
                                progress_pct,
                                speed_mbps,
                            },
                        ))
                        .await;
                    last_ui_update = Instant::now();
                }
            }
            Err(e) => {
                bail!("Stream read error while receiving {}: {}", filename, e);
            }
        }
    }

    // --- Verify hash ---
    let mut expected_hash_buf = [0u8; 64];
    recv_stream.read_exact(&mut expected_hash_buf).await?;
    let expected_hash =
        String::from_utf8(expected_hash_buf.to_vec()).context("Hash is not valid UTF-8")?;
    let computed_hash = hasher.finalize();

    if expected_hash == computed_hash {
        let _ = tx
            .send(crate::tui::event::AppEvent::Log(format!(
                "[SUCCESS] [P2P] Verified '{}' saved to '{}'  sha256: {}",
                filename, out_path.display(), computed_hash
            )))
            .await;
    } else {
        let _ = tx
            .send(crate::tui::event::AppEvent::Log(format!(
                "[ERROR] [P2P] Hash mismatch for '{}'! Expected: {} | Got: {}",
                filename, expected_hash, computed_hash
            )))
            .await;
    }

    // Signal 100% completion
    let _ = tx
        .send(crate::tui::event::AppEvent::TransferProgress(
            TransferState {
                filename: filename.clone(),
                peer_id: peer_id_str.clone(),
                progress_pct: 100,
                speed_mbps: 0.0,
            },
        ))
        .await;

    Ok(())
}
