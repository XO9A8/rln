use chrono::Utc;
use rusqlite::{params, Connection, Result};

#[derive(Debug)]
pub struct DeviceSnapshot {
    pub mac_address: String,
    pub ip_address: String,
    pub service_name: Option<String>,
    pub last_seen: String,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Initializes the database connection and creates the schema if it doesn't exist.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS network_snapshots (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                service_name TEXT,
                last_seen TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Database { conn })
    }

    /// Inserts or updates a device snapshot in the database.
    pub fn upsert_device(&self, mac: &str, ip: &str, service_name: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO network_snapshots (mac_address, ip_address, service_name, last_seen)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                service_name = COALESCE(excluded.service_name, network_snapshots.service_name),
                last_seen = excluded.last_seen",
            params![mac, ip, service_name, now],
        )?;

        Ok(())
    }

    /// Retrieves all known devices to act as the baseline for drift comparison.
    pub fn get_all_snapshots(&self) -> Result<Vec<DeviceSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac_address, ip_address, service_name, last_seen FROM network_snapshots",
        )?;

        let device_iter = stmt.query_map([], |row| {
            Ok(DeviceSnapshot {
                mac_address: row.get(0)?,
                ip_address: row.get(1)?,
                service_name: row.get(2)?,
                last_seen: row.get(3)?,
            })
        })?;

        let mut devices = Vec::new();
        for device in device_iter {
            devices.push(device?);
        }

        Ok(devices)
    }
}
