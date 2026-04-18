use crate::storage::db::DeviceSnapshot;
use std::collections::HashMap;

/// Represents a device found during the current scan.
#[derive(Debug, Clone)]
pub struct ScannedDevice {
    pub mac_address: String,
    pub ip_address: String,
    pub service_name: Option<String>,
}

/// The types of state changes we care about on the network.
#[derive(Debug, PartialEq)]
pub enum DriftEvent {
    NewDevice {
        mac: String,
        ip: String,
    },
    IpChanged {
        mac: String,
        old_ip: String,
        new_ip: String,
    },
    DeviceOffline {
        mac: String,
        last_ip: String,
    },
    NoChange {
        mac: String,
    },
}

/// Compares historical database snapshots against a fresh network scan.
pub fn calculate_drift(
    historical: &[DeviceSnapshot],
    current: &[ScannedDevice],
) -> Vec<DriftEvent> {
    let mut events = Vec::new();

    // Hash the current scan for O(1) lookups by MAC address
    let mut current_map: HashMap<&str, &ScannedDevice> = current
        .iter()
        .map(|d| (d.mac_address.as_str(), d))
        .collect();

    // 1. Check historical devices against the current scan
    for hist in historical {
        if let Some(curr) = current_map.remove(hist.mac_address.as_str()) {
            if hist.ip_address != curr.ip_address {
                events.push(DriftEvent::IpChanged {
                    mac: hist.mac_address.clone(),
                    old_ip: hist.ip_address.clone(),
                    new_ip: curr.ip_address.clone(),
                });
            } else {
                events.push(DriftEvent::NoChange {
                    mac: hist.mac_address.clone(),
                });
            }
        } else {
            // Device was in DB but not in the current scan
            events.push(DriftEvent::DeviceOffline {
                mac: hist.mac_address.clone(),
                last_ip: hist.ip_address.clone(),
            });
        }
    }

    // 2. Anything remaining in the current_map is a brand new device
    for curr in current_map.values() {
        events.push(DriftEvent::NewDevice {
            mac: curr.mac_address.clone(),
            ip: curr.ip_address.clone(),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to quickly mock DB snapshots
    fn mock_db_snapshot(mac: &str, ip: &str) -> DeviceSnapshot {
        DeviceSnapshot {
            mac_address: mac.to_string(),
            ip_address: ip.to_string(),
            service_name: None,
            last_seen: "2023-10-01T12:00:00Z".to_string(),
        }
    }

    // Helper to quickly mock L2 Scans
    fn mock_l2_scan(mac: &str, ip: &str) -> ScannedDevice {
        ScannedDevice {
            mac_address: mac.to_string(),
            ip_address: ip.to_string(),
            service_name: None,
        }
    }

    #[test]
    fn test_drift_detection() {
        // Setup: What the DB remembers
        let historical = vec![
            mock_db_snapshot("00:1A:2B:3C:4D:5E", "192.168.1.10"), // Will stay the same
            mock_db_snapshot("AA:BB:CC:DD:EE:FF", "192.168.1.20"), // Will change IP
            mock_db_snapshot("11:22:33:44:55:66", "192.168.1.30"), // Will go offline
        ];

        // Setup: What our L2/L3 scanners just found
        let current_scan = vec![
            mock_l2_scan("00:1A:2B:3C:4D:5E", "192.168.1.10"), // No change
            mock_l2_scan("AA:BB:CC:DD:EE:FF", "192.168.1.25"), // IP Changed
            mock_l2_scan("99:88:77:66:55:44", "192.168.1.50"), // Brand new device
        ];

        // Execute Drift Engine
        let events = calculate_drift(&historical, &current_scan);

        // Assertions
        assert!(events.contains(&DriftEvent::NoChange {
            mac: "00:1A:2B:3C:4D:5E".to_string()
        }));

        assert!(events.contains(&DriftEvent::IpChanged {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            old_ip: "192.168.1.20".to_string(),
            new_ip: "192.168.1.25".to_string()
        }));

        assert!(events.contains(&DriftEvent::DeviceOffline {
            mac: "11:22:33:44:55:66".to_string(),
            last_ip: "192.168.1.30".to_string()
        }));

        assert!(events.contains(&DriftEvent::NewDevice {
            mac: "99:88:77:66:55:44".to_string(),
            ip: "192.168.1.50".to_string()
        }));
    }
}
