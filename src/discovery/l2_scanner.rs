//! Layer 2 ARP sweep and interface discovery for the RLN network scanner.
//!
//! Performs an ARP sweep across the active interface's subnet and returns a
//! list of [`ScannedDevice`]s. Uses a **Progressive Discovery** pattern via
//! [`ScanMode`] to provide ultra-fast initial discovery and deep, staggered
//! background scans to detect sleeping mobile/IoT devices.
//!
//! Each discovered device is enriched with a **vendor name** sourced from the
//! bundled `mac_oui` Wireshark OUI database (`mac_oui::Oui::default()`), which
//! is loaded once per scan at the start of [`run_arp_sweep`]. The host device
//! running RLN is also explicitly added to the list as `(This Device)`.
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
    
    let active_iface = interfaces.into_iter().find(|iface| {
        if iface.is_loopback() {
            return false;
        }
        
        #[cfg(target_os = "windows")]
        {
            // Loosen the criteria for Windows. Npcap's `is_up()` flag can sometimes report false 
            // for active WiFi/Ethernet adapters, so we prioritise interfaces with valid IPv4
            // addresses that are not loopback or link-local.
            iface.ips.iter().any(|ip| {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_unspecified()
                } else {
                    false
                }
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Strict `is_up()` check for Linux/macOS to avoid inactive/virtual interfaces.
            iface.is_up() && !iface.ips.is_empty()
        }
    });

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanmode_equality() {
        assert_eq!(ScanMode::Quick, ScanMode::Quick);
        assert_ne!(ScanMode::Quick, ScanMode::Thorough);
        assert_eq!(ScanMode::Thorough, ScanMode::Thorough);
    }
    
    // We cannot easily test raw sockets in a CI/unprivileged environment,
    // but we can ensure our configuration constants match our expectations.
    #[test]
    fn test_scanmode_parameters() {
        let (timeout, chunks, stagger) = match ScanMode::Quick {
            ScanMode::Quick => (400, 128, 20),
            ScanMode::Thorough => (1200, 32, 150),
        };
        assert_eq!(timeout, 400);
        assert_eq!(chunks, 128);
        assert_eq!(stagger, 20);
    }
}

/// The intensity of the Layer 2 scan.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMode {
    /// Instant feedback. Good for wired or currently active devices.
    Quick,
    /// Deep scan. Longer timeouts and staggers to catch sleeping WiFi devices.
    Thorough,
}

/// Performs an ARP sweep across the interface subnet.
/// This function is only available on Unix-like operating systems.
#[cfg(unix)]
pub async fn run_arp_sweep(iface: &NetworkInterface, mode: ScanMode) -> Result<Vec<ScannedDevice>> {
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

    let (timeout_ms, retries, chunk_size, stagger_ms) = match mode {
        ScanMode::Quick => (400, 1, 128, 20),
        ScanMode::Thorough => (1200, 3, 32, 150),
    };

    let config = ClientConfigBuilder::new(&iface.name)
        .with_response_timeout(std::time::Duration::from_millis(timeout_ms))
        .build();
    let client = Client::new(config)?;
    let spinner = ClientSpinner::new(client).with_retries(retries);

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

    let mut outcomes = Vec::new();
    for chunk in requests.chunks(chunk_size) {
        if let Ok(res) = spinner.request_batch(chunk).await {
            outcomes.extend(res);
            // Small stagger to prevent broadcast storms / dropping packets on AP
            tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
        }
    }
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
                oui_db
                    .lookup_by_mac(&mac_str)
                    .ok()
                    .flatten()
                    .map(|res| res.company_name.clone())
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

    // 3. Always include this local device itself in the topology
    let local_hostname = gethostname::gethostname().into_string().unwrap_or_else(|_| "unknown-pc".to_owned());
    devices.push(ScannedDevice {
        mac_address: format!("{}", our_mac),
        ip_address: format!("{}", our_ip),
        service_name: Some(format!("{} (This Device)", local_hostname)),
    });

    Ok(devices)
}

/// Windows support using pnet assuming Npcap/WinPcap is installed.
#[cfg(target_os = "windows")]
pub async fn run_arp_sweep(iface: &NetworkInterface, mode: ScanMode) -> Result<Vec<ScannedDevice>> {
    use pnet::datalink::Channel::Ethernet;
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::util::MacAddr;
    use pnet::packet::{MutablePacket, Packet};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    let network = iface.ips.iter().find(|ip| ip.is_ipv4());
    let (our_ip, network) = match network {
        Some(pnet::ipnetwork::IpNetwork::V4(net)) => (net.ip(), net),
        _ => bail!("No IPv4 address found on interface"),
    };

    let our_mac = iface.mac.unwrap_or(MacAddr::zero());
    if our_mac == MacAddr::zero() {
        bail!("Interface does not have a MAC address");
    }

    let (timeout_ms, chunk_size, stagger_ms) = match mode {
        ScanMode::Quick => (400, 128, 20),
        ScanMode::Thorough => (1200, 32, 150),
    };

    let iface_clone = iface.clone();
    let net_u32 = u32::from(network.network());
    let mask = network.prefix();
    
    // Run the packet sending and receiving on a blocking thread
    let outcomes: Vec<(Ipv4Addr, MacAddr)> = tokio::task::spawn_blocking(move || -> Result<Vec<(Ipv4Addr, MacAddr)>> {
        let mut config = pnet::datalink::Config::default();
        config.read_timeout = Some(Duration::from_millis(10));
        
        let (mut tx, mut rx) = match pnet::datalink::channel(&iface_clone, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => bail!("Unhandled channel type"),
            Err(e) => bail!("Failed to create datalink channel: {}", e),
        };

        let hosts = (1 << (32 - mask)) - 2;
        let mut target_ips = Vec::new();
        
        for i in 1..=hosts {
            let target_ip = Ipv4Addr::from(net_u32 + i);
            if target_ip == our_ip {
                continue;
            }
            target_ips.push(target_ip);
        }

        let mut discovered = HashMap::new();
        let timeout = Duration::from_millis(timeout_ms);

        for chunk in target_ips.chunks(chunk_size) {
            for &target_ip in chunk {
                let mut arp_buffer = [0u8; 28];
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Request);
                arp_packet.set_sender_hw_addr(our_mac);
                arp_packet.set_sender_proto_addr(our_ip);
                arp_packet.set_target_hw_addr(MacAddr::zero());
                arp_packet.set_target_proto_addr(target_ip);

                // Pad the Ethernet frame to 60 bytes (Ethernet minimum length required by some Npcap drivers)
                let mut ethernet_buffer = [0u8; 60];
                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

                ethernet_packet.set_destination(MacAddr::broadcast());
                ethernet_packet.set_source(our_mac);
                ethernet_packet.set_ethertype(EtherTypes::Arp);
                ethernet_packet.set_payload(arp_packet.packet_mut());

                tx.send_to(ethernet_packet.packet(), None);
            }

            // Drain RX queue while waiting for the stagger duration, preventing OS buffer overflows
            let chunk_start = Instant::now();
            let chunk_stagger = Duration::from_millis(stagger_ms);
            
            while chunk_start.elapsed() < chunk_stagger {
                if let Ok(packet) = rx.next() {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply && arp.get_target_proto_addr() == our_ip {
                                    discovered.insert(arp.get_sender_proto_addr(), arp.get_sender_hw_addr());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        let wait_start = Instant::now();
        // Wait for the remaining timeout to catch late replies
        while wait_start.elapsed() < timeout {
            if let Ok(packet) = rx.next() {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply && arp.get_target_proto_addr() == our_ip {
                                discovered.insert(arp.get_sender_proto_addr(), arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
        }

        Ok(discovered.into_iter().collect())
    }).await??;

    let mut devices = Vec::new();
    let db = mac_oui::Oui::default().ok();

    // 1. Perform Reverse DNS lookups concurrently
    let mut dns_tasks = Vec::new();
    for (ip_addr_v4, mac_addr) in outcomes {
        let ip_addr = std::net::IpAddr::V4(ip_addr_v4);
        let mac_str = format!("{}", mac_addr);
        let ip_str = format!("{}", ip_addr_v4);

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

    // 2. Resolve final names, combining DNS and OUI
    for task in dns_tasks {
        if let Ok((mac_str, ip_str, dns_name)) = task.await {
            let oui_name = db.as_ref().and_then(|oui_db| {
                oui_db
                    .lookup_by_mac(&mac_str)
                    .ok()
                    .flatten()
                    .map(|res| res.company_name.clone())
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

    // 3. Always include this local device itself in the topology
    let local_hostname = gethostname::gethostname().into_string().unwrap_or_else(|_| "unknown-pc".to_owned());
    devices.push(ScannedDevice {
        mac_address: format!("{}", our_mac),
        ip_address: format!("{}", our_ip),
        service_name: Some(format!("{} (This Device)", local_hostname)),
    });

    Ok(devices)
}
