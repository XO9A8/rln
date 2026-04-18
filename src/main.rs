mod app;
mod discovery;
mod identity;
mod storage;
mod transfer;
mod tui;

use anyhow::Result;
use app::App;
use crossterm::event::KeyCode;
use discovery::{l2_scanner, mdns_scanner};
use identity::keys::NodeIdentity;
use std::{sync::Arc, time::Duration};
use storage::db::Database;
use storage::drift::calculate_drift;
use tokio::sync::mpsc;
use transfer::stream::P2pNode;
use tui::{
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

    // Spawn P2P Listener
    tokio::spawn({
        let node = Arc::clone(&p2p_node);
        async move {
            let _ = node.listen_for_peers().await;
        }
    });

    // 3. Initialize UI & State
    let mut terminal = setup_terminal()?;
    let mut app = App::new(known_devices);
    app.add_log(format!("[ID] Peer ID: {}", identity.peer_id_hex()));

    // 4. Setup Event Channels
    let (tx, mut rx) = mpsc::channel(100);
    setup_key_listener(tx.clone(), Duration::from_millis(250));

    // 5. Spawn Background Discovery Engine
    let iface = l2_scanner::get_active_interface()?;
    if l2_scanner::verify_privileges(&iface).is_ok() {
        app.add_log("[SYSTEM] Raw socket permissions granted. Starting scanners...".into());
        let tx_net = tx.clone();

        // Background loop that scans every 10 seconds
        tokio::spawn(async move {
            loop {
                let arp_task = tokio::spawn({
                    let iface = iface.clone();
                    async move { l2_scanner::run_arp_sweep(&iface).await }
                });
                let mdns_task =
                    tokio::spawn(async move { mdns_scanner::run_mdns_discoveryy().await });

                let (arp_res, mdns_res) = tokio::join!(arp_task, mdns_task);

                if let (Ok(Ok(mut arp)), Ok(Ok(mut mdns))) = (arp_res, mdns_res) {
                    arp.append(&mut mdns);
                    // We need a fresh DB connection here since this is a background thread
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
        app.add_log("[WARNING] Missing privileges for raw L2 scanning.".into());
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
                AppEvent::Tick => {} // We just let the loop continue to redraw
            }
        }
    }

    // 7. Cleanup
    restore_terminal()?;
    println!("Goodbye! 🛰️");
    Ok(())
}
