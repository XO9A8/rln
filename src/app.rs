/// Core application state for the RLN TUI dashboard.
///
/// `App` is the single source of truth consumed by the rendering layer.
/// All background tasks communicate with it via `AppEvent` channels.
use crate::intelligence::topology::SwitchTopology;
use crate::storage::drift::DriftEvent;
use std::collections::{HashMap, VecDeque};

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
    /// A bounded ring-buffer of log messages shown in the TUI log panel.
    /// Capped at [`App::MAX_LOGS`] entries; oldest entries are evicted first.
    pub logs: VecDeque<String>,
    /// Count of devices known from persistent storage at startup.
    pub known_devices: usize,
    /// The latest list of drift events produced by the discovery engine.
    pub active_drift_events: Vec<DriftEvent>,
    /// Currently active P2P file transfers being streamed.
    pub active_transfers: Vec<TransferState>,
    /// LLDP-derived network topology grouped by switch name.
    pub topology: HashMap<String, SwitchTopology>,
}

impl App {
    /// Maximum number of log lines held in memory.
    const MAX_LOGS: usize = 50;

    /// Creates a new `App` instance with sensible defaults.
    pub fn new(known_devices: usize) -> Self {
        let mut logs = VecDeque::with_capacity(Self::MAX_LOGS + 1);
        logs.push_back("[SYSTEM] RLN v2.0 Initialized...".to_string());
        Self {
            is_running: true,
            logs,
            known_devices,
            active_drift_events: Vec::new(),
            active_transfers: Vec::new(),
            topology: HashMap::new(),
        }
    }

    /// Signals the application to stop at the end of the current event loop tick.
    pub fn quit(&mut self) {
        self.is_running = false;
    }

    /// Appends a message to the log panel.
    ///
    /// If the log buffer exceeds [`App::MAX_LOGS`] entries, the oldest entry is
    /// evicted first (O(1) with `VecDeque`).
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
}
