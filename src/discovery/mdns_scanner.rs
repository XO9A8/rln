use crate::storage::drift::ScannedDevice;
use anyhow::Result;
use simple_mdns::async_discovery::ServiceDiscovery;
use simple_mdns::InstanceInformation;
use std::time::Duration;

pub async fn run_mdns_discovery() -> Result<()> {
    println!("🌐 Starting L3 mDNS discovery...");

    // Create a discovery instance.
    let instance_info = InstanceInformation::new("null".to_string());
    let discovery = ServiceDiscovery::new(instance_info, "_http._tcp.local", 60)?;

    // Allow some time for local devices to respond to the multicast query
    tokio::time::sleep(Duration::from_secs(3)).await;

    let services = discovery.get_known_services().await;

    if services.is_empty() {
        println!("🔍 [mDNS] No services found on local subnet.");
    } else {
        for service in services {
            println!("🔍 [mDNS] Discovered service: {:?}", service);
        }
    }
    Ok(())
}
pub async fn run_mdns_discoveryy() -> Result<Vec<ScannedDevice>> {
    println!("🌐 [L3] Starting mDNS discovery...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Simulating a discovered service (e.g., a local printer)
    let devices = vec![ScannedDevice {
        mac_address: "11:22:33:44:55:66".to_string(), // In reality, we correlate this from ARP table
        ip_address: "192.168.1.50".to_string(),
        service_name: Some("Brother_HL-L2350DW._http._tcp.local".to_string()),
    }];

    Ok(devices)
}
