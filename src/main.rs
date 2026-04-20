use anyhow::Result;
use crossterm::event::KeyCode;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

use lan_asin::app::{App, InputMode};
use lan_asin::discovery::{l2_scanner, mdns_scanner};
use lan_asin::identity::keys::NodeIdentity;
use lan_asin::storage::db::Database;
use lan_asin::storage::drift::calculate_drift;
use lan_asin::system::privileges;
use lan_asin::transfer::stream::P2pNode;
use lan_asin::tui::{
    event::{setup_key_listener, AppEvent},
    layout::{restore_terminal, setup_terminal},
    views::dashboard,
};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initial Data Load
    let data_dir = std::env::var("RLN_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("Failed to create data directory '{}': {}", data_dir, e);
    }
    let db_path = format!("{}/rln_state.db", data_dir);

    let db = Database::new(&db_path)?;
    let historical_snapshots = db.get_all_snapshots()?;
    let known_devices = historical_snapshots.len();

    // 2. Setup Crypto Identity
    let id_path = format!("{}/identity.key", data_dir);

    let identity = NodeIdentity::load_or_generate(&id_path)?;
    let p2p_node = Arc::new(P2pNode::new(&identity.secret_bytes()).await?);

    // 3. Setup Event Channels
    let (tx, mut rx) = mpsc::channel(100);
    setup_key_listener(tx.clone(), Duration::from_millis(250));

    // Spawn P2P Listener
    tokio::spawn({
        let node = Arc::clone(&p2p_node);
        let tx_p2p = tx.clone();
        async move {
            let _ = node.listen_for_peers(tx_p2p).await;
        }
    });

    // 4. Initialize UI & State
    let mut terminal = setup_terminal()?;
    let mut app = App::new(known_devices);
    app.local_peer_id = identity.peer_id_hex();
    app.add_log(format!("[ID] Peer ID: {}", app.local_peer_id));

    // Topologies and transfers will be dynamically updated by network scans and peers

    // 5. Spawn Background Discovery Engine
    if privileges::is_privileged() {
        app.add_log("[SYSTEM] CAP_NET_RAW granted. Starting full L2+L3+ICMP discovery...".into());
        let iface = l2_scanner::get_active_interface()?;
        let tx_net = tx.clone();

        let local_pid = app.local_peer_id.clone();
        let mdns_discovery = Arc::new(mdns_scanner::setup_mdns(&local_pid)?);

        tokio::spawn(async move {
            let mut is_first_scan = true;
            loop {
                let current_mode = if is_first_scan {
                    is_first_scan = false;
                    lan_asin::discovery::l2_scanner::ScanMode::Quick
                } else {
                    lan_asin::discovery::l2_scanner::ScanMode::Thorough
                };

                let arp_task = tokio::spawn({
                    let iface = iface.clone();
                    async move { l2_scanner::run_arp_sweep(&iface, current_mode).await }
                });

                let mdns_disc_clone = mdns_discovery.clone();
                let mdns_task = tokio::spawn(async move {
                    mdns_scanner::run_mdns_scan_step(&mdns_disc_clone).await
                });

                let (arp_res, mdns_res) = tokio::join!(arp_task, mdns_task);

                if let (Ok(Ok(mut arp)), Ok(Ok((mut mdns, peers)))) = (arp_res, mdns_res) {
                    arp.append(&mut mdns);

                    let _ = tx_net.send(AppEvent::RlnPeerDiscovered(peers)).await;

                    let db_scan_path = std::env::var("RLN_DATA_DIR")
                        .map(|d| format!("{}/rln_state.db", d))
                        .unwrap_or_else(|_| "data/rln_state.db".to_string());

                    if let Ok(bg_db) = Database::new(&db_scan_path) {
                        // Persist freshly scanned devices to DB
                        for dev in &arp {
                            let _ = bg_db.upsert_device(
                                &dev.mac_address,
                                &dev.ip_address,
                                dev.service_name.as_deref(),
                            );
                        }

                        if let Ok(history) = bg_db.get_all_snapshots() {
                            // Filter out 'NoChange' events to prevent TUI spam
                            let drift = calculate_drift(&history, &arp)
                                .into_iter()
                                .filter(|e| !matches!(e, lan_asin::storage::drift::DriftEvent::NoChange { .. }))
                                .collect();

                            // Build a merged list of all devices seen recently to display in UI
                            let now = chrono::Utc::now();
                            let mut active_devices = Vec::new();
                            for hist in history {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&hist.last_seen) {
                                    let duration = now.signed_duration_since(dt.with_timezone(&chrono::Utc));
                                    // Treat device as active in topology if seen within last 5 minutes
                                    if duration.num_minutes() < 5 {
                                        active_devices.push(lan_asin::storage::drift::ScannedDevice {
                                            mac_address: hist.mac_address,
                                            ip_address: hist.ip_address,
                                            service_name: hist.service_name,
                                        });
                                    }
                                }
                            }

                            let _ = tx_net.send(AppEvent::NetworkUpdate(drift, active_devices)).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        // Spawn LLDP continuous scanner task
        let tx_lldp = tx.clone();
        let iface_lldp = l2_scanner::get_active_interface()?;
        tokio::spawn(async move {
            loop {
                let topo = lan_asin::intelligence::topology::run_lldp_scan(
                    &iface_lldp,
                    Duration::from_secs(30),
                )
                .await;
                if !topo.is_empty() {
                    let _ = tx_lldp.send(AppEvent::TopologyUpdate(topo)).await;
                }
            }
        });
    } else {
        // Print the guide to stderr before the TUI takes over
        privileges::print_privilege_guide();

        app.add_log("[DEGRADED] No CAP_NET_RAW — L2 ARP disabled. Using mDNS-only mode.".into());
        app.add_log("[DEGRADED] Run: sudo setcap cap_net_raw=eip $(which lan-asin)".into());

        // Still run mDNS in degraded mode
        let tx_mdns = tx.clone();

        let local_pid = app.local_peer_id.clone();
        let mdns_discovery = Arc::new(mdns_scanner::setup_mdns(&local_pid)?);

        tokio::spawn(async move {
            loop {
                if let Ok((mdns_devices, peers)) =
                    mdns_scanner::run_mdns_scan_step(&mdns_discovery).await
                {
                    let _ = tx_mdns.send(AppEvent::RlnPeerDiscovered(peers)).await;

                    let db_scan_path = std::env::var("RLN_DATA_DIR")
                        .map(|d| format!("{}/rln_state.db", d))
                        .unwrap_or_else(|_| "data/rln_state.db".to_string());

                    if let Ok(bg_db) = Database::new(&db_scan_path) {
                        if let Ok(history) = bg_db.get_all_snapshots() {
                            let drift = calculate_drift(&history, &mdns_devices);
                            let _ = tx_mdns
                                .send(AppEvent::NetworkUpdate(drift, mdns_devices))
                                .await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    // 6. Main Application Loop
    while app.is_running {
        // Draw the UI
        terminal.draw(|f| dashboard::draw(f, &app))?;

        // Handle events
        if let Some(event) = rx.recv().await {
            match event {
                AppEvent::Key(key) => match app.input_mode {
                    // --- Normal mode: single-key shortcuts ---
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                        KeyCode::Char('s') => {
                            app.input_mode = InputMode::SendFile;
                            app.input_buffer.clear();
                            app.add_log(
                                "[SEND] Enter: <peer_id_or_name> <filepath>  (Esc to cancel)"
                                    .into(),
                            );
                        }
                        KeyCode::Up => {
                            app.log_scroll_offset = app.log_scroll_offset.saturating_add(1);
                        }
                        KeyCode::Down => {
                            app.log_scroll_offset = app.log_scroll_offset.saturating_sub(1);
                        }
                        KeyCode::PageUp => {
                            let max_scroll = app.logs.len().saturating_sub(1) as u16;
                            app.log_scroll_offset =
                                app.log_scroll_offset.saturating_add(5).min(max_scroll);
                        }
                        KeyCode::PageDown => {
                            app.log_scroll_offset = app.log_scroll_offset.saturating_sub(5);
                        }
                        _ => {}
                    },
                    // --- Send-file input mode ---
                    InputMode::SendFile => match key.code {
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.input_buffer.clear();
                            app.add_log("[SEND] Cancelled.".into());
                        }
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        KeyCode::Enter => {
                            let raw = app.input_buffer.trim().to_string();
                            app.input_mode = InputMode::Normal;
                            app.input_buffer.clear();

                            // Parse "<peer_id> <filepath>" separated by first space
                            let mut parts = raw.splitn(2, ' ');
                            let peer_str = parts.next().unwrap_or("").to_string();
                            let path_str = parts.next().unwrap_or("").trim().to_string();

                            if peer_str.is_empty() || path_str.is_empty() {
                                app.add_log(
                                    "[ERROR] [SEND] Usage: <peer_id_or_name> <filepath>".into(),
                                );
                            } else {
                                // Try finding peer in our known RLN peers map
                                let target_peer = app
                                    .known_rln_peers
                                    .get(&peer_str)
                                    .cloned()
                                    .unwrap_or(peer_str.clone());

                                app.add_log(format!(
                                    "[SEND] Connecting to {}...",
                                    &target_peer[..target_peer.len().min(16)]
                                ));
                                let node_send = Arc::clone(&p2p_node);
                                let tx_send = tx.clone();
                                tokio::spawn(async move {
                                    use std::path::PathBuf;
                                    use std::str::FromStr;
                                    match iroh::EndpointId::from_str(&target_peer) {
                                        Ok(peer_id) => {
                                            let path = PathBuf::from(&path_str);
                                            if let Err(e) = node_send
                                                .send_file(peer_id, &path, tx_send.clone())
                                                .await
                                            {
                                                let _ = tx_send
                                                    .send(AppEvent::Log(format!(
                                                        "[ERROR] [SEND] Failed: {}",
                                                        e
                                                    )))
                                                    .await;
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx_send
                                                .send(AppEvent::Log(format!(
                                                    "[ERROR] [SEND] Invalid Peer ID: {}",
                                                    e
                                                )))
                                                .await;
                                        }
                                    }
                                });
                            }
                        }
                        KeyCode::Char(c) => {
                            app.input_buffer.push(c);
                        }
                        _ => {}
                    },
                },
                AppEvent::NetworkUpdate(drift_events, scanned_devices) => {
                    app.add_log("[NETWORK] Scan complete. Updating drift state.".into());
                    app.active_drift_events = drift_events;

                    let mut devices = Vec::new();
                    for d in scanned_devices {
                        devices.push(lan_asin::intelligence::topology::LldpDevice {
                            mac_address: d.mac_address,
                            ip_address: d.ip_address,
                            hostname: d.service_name,
                        });
                    }

                    let topo = lan_asin::intelligence::topology::SwitchTopology {
                        switch_name: "Local Network".to_string(),
                        port_id: "LAN".to_string(),
                        devices,
                    };

                    app.topology.insert("Local Network".to_string(), topo);
                }
                AppEvent::TopologyUpdate(lldp_topo) => {
                    for (k, v) in lldp_topo {
                        app.topology.insert(k, v);
                    }
                }
                AppEvent::RlnPeerDiscovered(peers) => {
                    for (k, v) in peers {
                        app.known_rln_peers.insert(k, v);
                    }
                }
                AppEvent::Log(msg) => {
                    app.add_log(msg);
                }
                AppEvent::TransferProgress(state) => {
                    app.active_transfers
                        .retain(|t| t.peer_id != state.peer_id || t.filename != state.filename);
                    if state.progress_pct < 100 {
                        app.active_transfers.push(state);
                    }
                }
                AppEvent::Tick => {}
            }
        }
    }

    // 7. Cleanup
    restore_terminal()?;
    println!("Goodbye!");
    std::process::exit(0);
}
