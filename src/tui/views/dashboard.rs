use crate::app::App;
use crate::storage::drift::DriftEvent;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// Renders the main dashboard UI based on the current App state
pub fn draw(f: &mut Frame, app: &App) {
    // 1. Split the screen vertically into 3 chunks
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header (fixed height)
            Constraint::Min(10),    // Network State (flexible)
            Constraint::Length(10), // Logs (fixed height)
        ])
        .split(f.size());

    // 2. Render Header
    let header_text = format!(
        " 🛰️  RLN v2.0 Dashboard | Known Devices: {} | Status: Active",
        app.known_devices
    );
    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" RLN Orchestrator "),
        );
    f.render_widget(header, chunks[0]);

    // 3. Render Network State (Drift Events)
    let drift_items: Vec<ListItem> = app
        .active_drift_events
        .iter()
        .map(|event| {
            let (symbol, text, color) = match event {
                DriftEvent::NoChange { mac } => ("🟢", format!("STABLE: {}", mac), Color::Green),
                DriftEvent::NewDevice { mac, ip } => {
                    ("🚨", format!("NEW: {} at {}", mac, ip), Color::Yellow)
                }
                DriftEvent::IpChanged {
                    mac,
                    old_ip,
                    new_ip,
                } => (
                    "⚠️",
                    format!("DRIFT: {} ({} -> {})", mac, old_ip, new_ip),
                    Color::LightYellow,
                ),
                DriftEvent::DeviceOffline { mac, last_ip } => (
                    "👻",
                    format!("OFFLINE: {} (last seen: {})", mac, last_ip),
                    Color::DarkGray,
                ),
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", symbol), Style::default()),
                Span::styled(text, Style::default().fg(color)),
            ]))
        })
        .collect();

    let state_list = List::new(drift_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Network State "),
    );
    f.render_widget(state_list, chunks[1]);

    // 4. Render Logs
    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .map(|log| ListItem::new(log.clone()))
        .collect();

    let logs_list = List::new(log_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" System Logs "),
    );
    f.render_widget(logs_list, chunks[2]);
}
