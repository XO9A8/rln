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
