use crate::storage::drift::ScannedDevice;
use anyhow::{bail, Result};
use pnet::datalink::{self, NetworkInterface};

/// Finds the primary active network interface (up, not loopback, has an IP).
pub fn get_active_interface() -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    let active_iface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty());

    match active_iface {
        Some(iface) => Ok(iface),
        None => bail!("No active, non-loopback network interface found."),
    }
}

/// Checks if the application has raw socket permissions (root / CAP_NET_RAW).
pub fn verify_privileges(iface: &NetworkInterface) -> Result<()> {
    // Attempt to open a dummy raw channel to test permissions
    let channel_config = datalink::Config::default();
    match datalink::channel(iface, channel_config) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                bail!("Permission Denied: RLN requires root, Administrator, or CAP_NET_RAW privileges to perform Layer 2 ARP/NDP scanning. Please elevate your permissions.");
            }
            bail!("Failed to open raw socket: {}", e);
        }
    }
}

/// Initiates the asynchronous ARP sweep across the interface's subnet.
pub async fn run_arp_sweep(iface: &NetworkInterface) -> Result<Vec<ScannedDevice>> {
    println!("📡 [L2] Starting ARP sweep on interface: {}", iface.name);
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Simulating a couple of discovered devices
    let devices = vec![
        ScannedDevice {
            mac_address: "00:1B:44:11:3A:B7".to_string(),
            ip_address: "192.168.1.10".to_string(), // Our router from earlier
            service_name: None,
        },
        ScannedDevice {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            ip_address: "192.168.1.105".to_string(), // A brand new device
            service_name: None,
        },
    ];

    Ok(devices)
}
