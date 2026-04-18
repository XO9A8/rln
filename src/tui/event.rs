#![allow(dead_code)]
use crate::storage::drift::DriftEvent;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// The unified event type for the RLN Dashboard.
pub enum AppEvent {
    /// A regular timer tick to update loaders or graphs.
    Tick,
    /// A user pressed a key.
    Key(KeyEvent),
    /// The discovery engine found new network state changes.
    NetworkUpdate(Vec<DriftEvent>),
    /// P2P streaming logs or events.
    Log(String),
    /// File transfer progress update.
    TransferProgress(crate::app::TransferState),
}

/// Sets up a background thread that listens for terminal keystrokes
/// and sends them to our main UI loop.
pub fn setup_key_listener(tx: mpsc::Sender<AppEvent>, tick_rate: Duration) {
    tokio::spawn(async move {
        let mut last_tick = std::time::Instant::now();
        loop {
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            // Poll for crossterm events (keyboard inputs)
            if event::poll(timeout).unwrap_or(false) {
                if let Ok(CrosstermEvent::Key(key)) = event::read() {
                    if tx.send(AppEvent::Key(key)).await.is_err() {
                        break; // Channel closed
                    }
                }
            }

            // Send a tick event if the timeout expired
            if last_tick.elapsed() >= tick_rate {
                if tx.send(AppEvent::Tick).await.is_err() {
                    break;
                }
                last_tick = std::time::Instant::now();
            }
        }
    });
}
