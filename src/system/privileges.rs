/// Checks if the running process has the privileges required for raw socket operations
/// (ARP sweeping, raw ICMP pinging).
///
/// On Linux/macOS this is determined by attempting to open a raw socket.
/// On Windows this checks for Administrator role.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // Attempt to bind a raw ICMP socket. If it succeeds we have CAP_NET_RAW or are root.
        use pnet::datalink;
        let interfaces = datalink::interfaces();
        if let Some(iface) = interfaces
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        {
            return datalink::channel(&iface, datalink::Config::default()).is_ok();
        }
        false
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, check if the process is running as Administrator.
        // This uses the IsUserAnAdmin Win32 function.
        // Safety: This is a read-only query with no side effects.
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        // Unsupported platform — conservative fallback
        false
    }
}

/// Prints a user-friendly, formatted guide explaining how to run RLN
/// without full `sudo` by granting `CAP_NET_RAW` to the binary.
pub fn print_privilege_guide() {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║         ⚠️  RLN: INSUFFICIENT PRIVILEGES DETECTED            ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                              ║");
    eprintln!("║  Layer 2 ARP scanning and raw ICMP probing require           ║");
    eprintln!("║  elevated network privileges.                                ║");
    eprintln!("║                                                              ║");
    eprintln!("║  RLN will continue in DEGRADED MODE (mDNS-only discovery).   ║");
    eprintln!("║                                                              ║");
    eprintln!("║  To enable full scanning, choose one of the following:       ║");
    eprintln!("║                                                              ║");
    eprintln!("║  Option 1 — Grant CAP_NET_RAW (recommended, no full sudo):   ║");
    eprintln!("║    sudo setcap cap_net_raw=eip /path/to/lan-asin             ║");
    eprintln!("║                                                              ║");
    eprintln!("║  Option 2 — Run as root (less secure):                       ║");
    eprintln!("║    sudo ./lan-asin                                           ║");
    eprintln!("║                                                              ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_check_returns_bool() {
        // We can't guarantee the test runner has raw socket permissions,
        // but we CAN guarantee the function doesn't panic.
        let _result: bool = is_privileged();
    }
}
