mod discovery;
mod storage;

use anyhow::Result;
use discovery::l2_scanner;
use discovery::mdns_scanner;
use storage::db::Database;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🛰️ Starting RLN v2.0 Initialization...");

    // 1. Initialize Storage
    let db = Database::new("data/rln_state.db")?;
    println!("✅ Database initialized successfully.\n");

    // 2. Setup Network Interface & Check Privileges
    let iface = match l2_scanner::get_active_interface() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("❌ Network Interface Error: {}", e);
            return Ok(());
        }
    };

    if let Err(e) = l2_scanner::verify_privileges(&iface) {
        eprintln!("🔒 Security Alert: {}", e);
        eprintln!("💡 Tip: Run via `sudo` or apply capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip target/debug/rln`");
        return Ok(());
    }

    // 3. Launch Discovery Scanners Concurrently
    println!("🚀 Launching Discovery Engines on {}...", iface.name);

    // We use tokio::spawn to run them at the same time
    let arp_task = tokio::spawn({
        let iface = iface.clone();
        async move {
            let _ = l2_scanner::run_arp_sweep(&iface).await;
        }
    });

    let mdns_task = tokio::spawn(async move {
        let _ = mdns_scanner::run_mdns_discovery().await;
    });

    // Wait for both discovery tasks to finish
    let _ = tokio::join!(arp_task, mdns_task);

    println!("\n✅ Phase 1 Discovery Complete.");

    Ok(())
}
