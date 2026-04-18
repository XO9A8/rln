use anyhow::Result;
use crossterm::event::KeyCode;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

use lan_asin::app::App;
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
    let db = Database::new("data/rln_state.db")?;
    let historical_snapshots = db.get_all_snapshots()?;
    let known_devices = historical_snapshots.len();

    // 2. Setup Crypto Identity
    let identity = NodeIdentity::load_or_generate("data/identity.key")?;
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
    app.add_log(format!("[ID] Peer ID: {}", identity.peer_id_hex()));

    // MOCK DATA FOR MILESTONE 3.2
    use lan_asin::app::TransferState;
    use lan_asin::intelligence::topology::run_lldp_scan;
    app.topology = run_lldp_scan().await;
    app.active_transfers.push(TransferState {
        filename: "ubuntu-24.04-desktop-amd64.iso".to_string(),
        peer_id: "AA:BB:CC:DD:EE:FF".to_string(),
        progress_pct: 45,
        speed_mbps: 112.5,
    });
    app.active_transfers.push(TransferState {
        filename: "project_backup.tar.gz".to_string(),
        peer_id: "11:22:33:44:55:66".to_string(),
        progress_pct: 88,
        speed_mbps: 45.2,
    });

    // 5. Spawn Background Discovery Engine
    if privileges::is_privileged() {
        app.add_log("[SYSTEM] CAP_NET_RAW granted. Starting full L2+L3+ICMP discovery...".into());
        let iface = l2_scanner::get_active_interface()?;
        let tx_net = tx.clone();

        tokio::spawn(async move {
            loop {
                let arp_task = tokio::spawn({
                    let iface = iface.clone();
                    async move { l2_scanner::run_arp_sweep(&iface).await }
                });
                let mdns_task =
                    tokio::spawn(async move { mdns_scanner::run_mdns_scan().await });

                let (arp_res, mdns_res) = tokio::join!(arp_task, mdns_task);

                if let (Ok(Ok(mut arp)), Ok(Ok(mut mdns))) = (arp_res, mdns_res) {
                    arp.append(&mut mdns);
                    if let Ok(bg_db) = Database::new("data/rln_state.db") {
                        if let Ok(history) = bg_db.get_all_snapshots() {
                            let drift = calculate_drift(&history, &arp);
                            let _ = tx_net.send(AppEvent::NetworkUpdate(drift)).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    } else {
        // Print the guide to stderr before the TUI takes over
        privileges::print_privilege_guide();

        app.add_log("[DEGRADED] No CAP_NET_RAW — L2 ARP disabled. Using mDNS-only mode.".into());
        app.add_log("[DEGRADED] Run: sudo setcap cap_net_raw=eip $(which lan-asin)".into());

        // Still run mDNS in degraded mode
        let tx_mdns = tx.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(mdns_devices) = mdns_scanner::run_mdns_scan().await {
                    if let Ok(bg_db) = Database::new("data/rln_state.db") {
                        if let Ok(history) = bg_db.get_all_snapshots() {
                            let drift = calculate_drift(&history, &mdns_devices);
                            let _ = tx_mdns.send(AppEvent::NetworkUpdate(drift)).await;
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
                AppEvent::Key(key) => {
                    // Press 'q' or 'Esc' to quit
                    if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                        app.quit();
                    }
                }
                AppEvent::NetworkUpdate(drift_events) => {
                    app.add_log("[NETWORK] Scan complete. Updating drift state.".into());
                    app.active_drift_events = drift_events;
                }
                AppEvent::Log(msg) => {
                    app.add_log(msg);
                }
                AppEvent::TransferProgress(state) => {
                    // Overwrite the existing progress for this peer/file or add new
                    app.active_transfers.retain(|t| t.peer_id != state.peer_id || t.filename != state.filename);
                    if state.progress_pct < 100 {
                        app.active_transfers.push(state);
                    }
                }
                AppEvent::Tick => {} // We just let the loop continue to redraw
            }
        }
    }

    // 7. Cleanup
    restore_terminal()?;
    println!("Goodbye! 🛰️");
    Ok(())
}
