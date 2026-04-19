//! Layer 2 ARP sweep and interface discovery for the RLN network scanner.
//!
//! Performs an ARP sweep across the active interface's subnet and returns a
//! list of [`ScannedDevice`]s. Each discovered device is enriched with a
//! **vendor name** sourced from the bundled `mac_oui` Wireshark OUI database
//! (`mac_oui::Oui::default()`), which is loaded once per scan at the start of
//! [`run_arp_sweep`]. This gives the topology panel a human-readable label
//! (e.g. "Apple, Inc." or "Raspberry Pi Trading Ltd.") instead of "Unknown".
//!
//! Requires `CAP_NET_RAW` on Linux or Administrator on Windows for raw socket
//! access. A Windows stub is provided that returns an empty list and logs a
//! warning when Npcap/WinPcap is unavailable.
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
    let channel_config = datalink::Config::default();
    match datalink::channel(iface, channel_config) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                bail!("Permission Denied: RLN requires root, Administrator, or CAP_NET_RAW privileges to perform Layer 2 ARP/NDP scanning.");
            }
            bail!("Failed to open raw socket: {}", e);
        }
    }
}

/// Performs an ARP sweep across the interface subnet.
/// This function is only available on Unix-like operating systems.
#[cfg(unix)]
pub async fn run_arp_sweep(iface: &NetworkInterface) -> Result<Vec<ScannedDevice>> {
    use async_arp::{Client, ClientConfigBuilder, ClientSpinner, RequestInputBuilder};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    let network = iface.ips.iter().find(|ip| ip.is_ipv4());
    let (our_ip, network) = match network {
        Some(pnet::ipnetwork::IpNetwork::V4(net)) => (net.ip(), net),
        _ => bail!("No IPv4 address found on interface"),
    };

    let our_mac = iface.mac.unwrap_or(MacAddr::zero());
    if our_mac == MacAddr::zero() {
        bail!("Interface does not have a MAC address");
    }

    let config = ClientConfigBuilder::new(&iface.name)
        .with_response_timeout(std::time::Duration::from_millis(500))
        .build();
    let client = Client::new(config)?;
    let spinner = ClientSpinner::new(client).with_retries(1);

    let mut requests = Vec::new();
    let net_u32 = u32::from(network.network());
    let mask = network.prefix();
    let hosts = (1 << (32 - mask)) - 2;

    for i in 1..=hosts {
        let target_ip = Ipv4Addr::from(net_u32 + i);
        if target_ip == our_ip {
            continue;
        }

        if let Ok(req) = RequestInputBuilder::new()
            .with_sender_ip(our_ip)
            .with_sender_mac(our_mac)
            .with_target_ip(target_ip)
            .with_target_mac(MacAddr::zero())
            .build()
        {
            requests.push(req);
        }
    }

    let outcomes = spinner.request_batch(&requests).await?;
    let mut devices = Vec::new();
    let db = mac_oui::Oui::default().ok();

    // 1. Perform Reverse DNS lookups concurrently
    let mut dns_tasks = Vec::new();
    for outcome in outcomes {
        if let Ok(arp) = outcome.response_result {
            let ip_addr = std::net::IpAddr::V4(arp.sender_proto_addr);
            let mac_str = format!("{}", arp.sender_hw_addr);
            let ip_str = format!("{}", arp.sender_proto_addr);

            dns_tasks.push(tokio::spawn(async move {
                let ip_str_clone = ip_str.clone();
                let name = tokio::task::spawn_blocking(move || {
                    if let Ok(n) = dns_lookup::lookup_addr(&ip_addr) {
                        if !n.is_empty() && n != ip_str_clone && !n.starts_with("localhost") {
                            return Some(n);
                        }
                    }
                    None
                })
                .await
                .unwrap_or(None);

                (mac_str, ip_str, name)
            }));
        }
    }

    // 2. Resolve final names, combining DNS and OUI
    for task in dns_tasks {
        if let Ok((mac_str, ip_str, dns_name)) = task.await {
            let oui_name = db.as_ref().and_then(|oui_db| {
                oui_db.lookup_by_mac(&mac_str).ok().flatten().map(|res| res.company_name.clone())
            });

            let service_name = match (dns_name, oui_name) {
                (Some(dns), Some(oui)) => Some(format!("{} ({})", dns, oui)),
                (Some(dns), None) => Some(dns),
                (None, Some(oui)) => Some(oui),
                (None, None) => None,
            };

            devices.push(ScannedDevice {
                mac_address: mac_str,
                ip_address: ip_str,
                service_name,
            });
        }
    }

    Ok(devices)
}

/// Stub for Windows: ARP sweep is not supported without Npcap/WinPcap.
/// Returns an empty device list and logs a warning.
#[cfg(target_os = "windows")]
pub async fn run_arp_sweep(_iface: &NetworkInterface) -> Result<Vec<ScannedDevice>> {
    eprintln!("[L2] ARP sweep is not supported on Windows without Npcap/WinPcap. Skipping.");
    Ok(vec![])
}
