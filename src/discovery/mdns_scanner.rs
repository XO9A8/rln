#![allow(dead_code)]
use crate::storage::drift::ScannedDevice;
use anyhow::{Context, Result};
use simple_mdns::NetworkScope;
use crate::discovery::l2_scanner;
use simple_mdns::async_discovery::ServiceDiscovery;
use simple_mdns::InstanceInformation;
use std::time::Duration;

/// Initiates the mDNS Service Discovery instance that advertises our node's Peer ID
/// and listens for other RLN nodes broadcasting `_rln._udp.local`.
pub fn setup_mdns(peer_id: &str) -> Result<ServiceDiscovery> {
    let hostname = match gethostname::gethostname().into_string() {
        Ok(h) => h,
        Err(_) => "unknown-pc".to_owned(),
    };
    let mut info = InstanceInformation::new(hostname);
    info.attributes
        .insert("peer_id".to_string(), Some(peer_id.to_string()));

    // On Linux and macOS, the OS multicast routing table handles `0.0.0.0` correctly and 
    // seamlessly broadcasts across the physical adapter. On Windows, VirtualBox/WSL/VPN adapters
    // can trap `0.0.0.0` multicast packets. We explicitly bind to the correct physical adapter's IPv4.
    let mut scope = NetworkScope::V4;

    #[cfg(target_os = "windows")]
    if let Ok(iface) = l2_scanner::get_active_interface() {
        for ip in iface.ips {
            if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                scope = NetworkScope::V4WithInterface(ipv4);
                break;
            }
        }
    }

    ServiceDiscovery::new_with_scope(info, "_rln._udp.local", 60, None, scope)
        .context("Failed to create mDNS Service Discovery")
}

/// Runs a single pass to fetch known `_rln._udp.local` services.
/// It uses the long-lived ServiceDiscovery instance so we continually rebroadcast our presence.
pub async fn run_mdns_scan_step(
    discovery: &ServiceDiscovery,
) -> Result<(
    Vec<ScannedDevice>,
    std::collections::HashMap<String, String>,
)> {
    // Allow time for devices to respond to the multicast query
    tokio::time::sleep(Duration::from_secs(3)).await;

    let services = discovery.get_known_services().await;
    let mut devices = Vec::new();
    let mut rln_peers = std::collections::HashMap::new();

    for service in services {
        // Find the first IPv4 address if available
        let ip_addr = service.ip_addresses.iter().find(|ip| ip.is_ipv4());

        if let Some(std::net::IpAddr::V4(ipv4)) = ip_addr {
            let mut name = service.unescaped_instance_name();

            // If the peer exposes a peer_id as a TXT attribute, inject it into the service name mapped
            if let Some(Some(peer_id)) = service.attributes.get("peer_id") {
                let shortcode = format!("{}", &peer_id[..8.min(peer_id.len())]);
                name = format!("{} [{}]", name, shortcode);

                // Map the full Peer ID locally for ease of use via shortcuts
                rln_peers.insert(name.clone(), peer_id.clone());
                rln_peers.insert(shortcode, peer_id.clone());
                rln_peers.insert(service.unescaped_instance_name(), peer_id.clone());
            }

            devices.push(ScannedDevice {
                mac_address: "".to_string(), // mDNS doesn't resolve MAC directly
                ip_address: ipv4.to_string(),
                service_name: Some(name),
            });
        }
    }

    Ok((devices, rln_peers))
}
