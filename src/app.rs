/// Core application state for the RLN TUI dashboard.
///
/// `App` is the single source of truth consumed by the rendering layer.
/// All background tasks communicate with it via `AppEvent` channels.
use crate::intelligence::topology::SwitchTopology;
use crate::storage::drift::DriftEvent;
use std::collections::{HashMap, VecDeque};

/// Controls which keyboard mode the application is in.
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    /// Normal mode — arrow keys and single-letter shortcuts active.
    Normal,
    /// Send-file mode — user is typing `<peer_id> <filepath>` into the input bar.
    SendFile,
}

/// Represents a file transfer that is currently in progress over an Iroh P2P stream.
#[derive(Clone, Debug)]
pub struct TransferState {
    /// The filename being transferred.
    pub filename: String,
    /// The remote Peer ID (as a display string).
    pub peer_id: String,
    /// Transfer completion percentage (0–100).
    pub progress_pct: u8,
    /// Current throughput in megabits per second.
    pub speed_mbps: f64,
}

/// The central application state struct.
pub struct App {
    /// Whether the application event loop should continue running.
    pub is_running: bool,
    /// Current keyboard interaction mode.
    pub input_mode: InputMode,
    /// The text the user has typed into the active input bar.
    pub input_buffer: String,
    /// A bounded ring-buffer of log messages shown in the TUI log panel.
    pub logs: VecDeque<String>,
    /// Count of devices known from persistent storage at startup.
    pub known_devices: usize,
    /// The latest list of drift events produced by the discovery engine.
    pub active_drift_events: Vec<DriftEvent>,
    /// Currently active P2P file transfers being streamed.
    pub active_transfers: Vec<TransferState>,
    /// LLDP-derived network topology grouped by switch name.
    pub topology: HashMap<String, SwitchTopology>,
    /// Our own Iroh Peer ID (needed so the user can easily share it).
    pub local_peer_id: String,
    /// Known RLN peers discovered via mDNS, mapping friendly name or shortcode to full PeerId.
    pub known_rln_peers: HashMap<String, String>,
    /// The current scroll offset (in lines) for the system logs view.
    pub log_scroll_offset: u16,
}

impl App {
    /// Maximum number of log lines held in memory.
    const MAX_LOGS: usize = 50;

    /// Creates a new `App` instance with sensible defaults.
    pub fn new(known_devices: usize) -> Self {
        let mut logs = VecDeque::with_capacity(Self::MAX_LOGS + 1);
        logs.push_back("[SYSTEM] RLN v2.0 Initialized...".to_string());
        logs.push_back("[SYSTEM] Press 's' to send a file to a peer.".to_string());
        Self {
            is_running: true,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            logs,
            known_devices,
            active_drift_events: Vec::new(),
            active_transfers: Vec::new(),
            topology: HashMap::new(),
            local_peer_id: String::new(),
            known_rln_peers: HashMap::new(),
            log_scroll_offset: 0,
        }
    }

    /// Signals the application to stop at the end of the current event loop tick.
    pub fn quit(&mut self) {
        self.is_running = false;
    }

    /// Appends a message to the log panel, evicting the oldest if full (O(1)).
    pub fn add_log(&mut self, message: String) {
        if self.logs.len() >= Self::MAX_LOGS {
            self.logs.pop_front();
        }
        self.logs.push_back(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_log_bounding() {
        let mut app = App::new(0);
        app.logs.clear();
        for i in 0..60 {
            app.add_log(format!("Log message {}", i));
        }
        assert_eq!(app.logs.len(), 50);
        assert_eq!(app.logs[0], "Log message 10");
        assert_eq!(app.logs.back().unwrap(), "Log message 59");
    }

    #[test]
    fn test_input_mode_starts_normal() {
        let app = App::new(0);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(app.input_buffer.is_empty());
    }
}
