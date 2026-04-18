mod storage;

use anyhow::Result;
use storage::db::Database;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🛰️ Starting RLN v2.0 Initialization...");

    // Initialize the DB in our data folder
    let db = Database::new("data/rln_state.db")?;
    println!("✅ Database initialized successfully.");

    // Test an upsert
    db.upsert_device("00:1B:44:11:3A:B7", "192.168.1.10", Some("Router"))?;

    // Test retrieval
    let snapshots = db.get_all_snapshots()?;
    println!("Current Snapshots in DB:");
    for snap in snapshots {
        println!(
            "  - MAC: {}, IP: {}, Last Seen: {}",
            snap.mac_address, snap.ip_address, snap.last_seen
        );
    }

    Ok(())
}
