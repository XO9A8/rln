//! LLDP topology parsing and switch hierarchy mapping.
//!
//! In a production deployment, `run_lldp_scan` would capture raw Ethernet frames
//! using `pnet` and parse them with `packet-dissector-lldp` to discover which devices
//! are connected to which switch port.
//!
//! The current implementation provides a deterministic mock that demonstrates the
//! expected data shape for UI development and integration testing.
use std::collections::HashMap;

/// A device discovered via Link Layer Discovery Protocol (LLDP).
#[derive(Debug, Clone)]
pub struct LldpDevice {
    /// The device's hardware (MAC) address.
    pub mac_address: String,
    /// The device's IPv4 address at time of discovery.
    pub ip_address: String,
    /// The LLDP system name, if advertised.
    pub hostname: Option<String>,
}

/// Represents a single network switch and the devices it reports as connected.
#[derive(Debug, Clone)]
pub struct SwitchTopology {
    /// The LLDP system name of the switch.
    pub switch_name: String,
    /// The specific port on the switch where the RLN node received the LLDP frame.
    pub port_id: String,
    /// All devices that reported being connected via this switch.
    pub devices: Vec<LldpDevice>,
}

/// Scans for LLDP advertisements and builds a switch-grouped topology map.
///
/// Returns a `HashMap` keyed by switch name, with each value describing
/// the switch and the devices attached to it.
///
/// # Note
/// Currently returns mock data representing a realistic 2-switch LAN topology.
/// Future versions will use `pnet` to capture live LLDP frames.
pub async fn run_lldp_scan() -> HashMap<String, SwitchTopology> {
    let mut topology = HashMap::new();

    topology.insert(
        "Core-Switch-01".to_string(),
        SwitchTopology {
            switch_name: "Core-Switch-01".to_string(),
            port_id: "GigabitEthernet1/0/1".to_string(),
            devices: vec![
                LldpDevice {
                    mac_address: "00:1B:44:11:3A:B7".to_string(),
                    ip_address: "192.168.1.10".to_string(),
                    hostname: Some("Router".to_string()),
                },
                LldpDevice {
                    mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
                    ip_address: "192.168.1.105".to_string(),
                    hostname: Some("Desktop-PC".to_string()),
                },
            ],
        },
    );

    topology.insert(
        "Access-Switch-02".to_string(),
        SwitchTopology {
            switch_name: "Access-Switch-02".to_string(),
            port_id: "FastEthernet0/1".to_string(),
            devices: vec![LldpDevice {
                mac_address: "11:22:33:44:55:66".to_string(),
                ip_address: "192.168.1.50".to_string(),
                hostname: Some("Brother-Printer".to_string()),
            }],
        },
    );

    topology
}