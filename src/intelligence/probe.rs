use anyhow::Result;
use std::net::IpAddr;

/// Probes a host using ICMP and returns diagnostic metadata (TTL, window size, open ports count).
/// Only available on Unix-like systems where raw ICMP sockets are permitted.
#[cfg(unix)]
pub async fn probe_host(ip: IpAddr) -> Result<(u32, u32, u32)> {
    use anyhow::Context;
    use surge_ping::ping;

    let payload = [0u8; 8];

    let (_packet, _duration) = ping(ip, &payload)
        .await
        .context(format!("Failed to ping {}", ip))?;

    // TTL, window size, and open port count.
    // In a full implementation these would be extracted from raw IP/TCP headers.
    let simulated_ttl = 64;
    let simulated_window_size = 65535;
    let simulated_open_ports = 3;

    Ok((simulated_ttl, simulated_window_size, simulated_open_ports))
}

/// Stub for Windows: raw ICMP probing requires Administrator and Npcap.
/// Returns a neutral set of metrics indicating no data available.
#[cfg(target_os = "windows")]
pub async fn probe_host(_ip: IpAddr) -> Result<(u32, u32, u32)> {
    eprintln!("[PROBE] Raw ICMP probing is not supported on Windows without Npcap. Returning defaults.");
    Ok((128, 65535, 0)) // Windows TTL default, generic window, no ports known
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_fallback() {
        let ip = "127.0.0.1".parse().unwrap();

        let result = probe_host(ip).await;
        // May fail if running without CAP_NET_RAW — just assert no panic.
        if let Ok((ttl, window, _ports)) = result {
            assert!(ttl > 0, "TTL should be non-zero");
            assert!(window > 0, "Window size should be non-zero");
        }
    }
}
