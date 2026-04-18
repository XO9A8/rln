//! Dashboard view for the RLN TUI.
//!
//! Renders a four-pane layout:
//! ```text
//! ┌────────────────────── Header ───────────────────────┐
//! │─────────────── Network Topology (LLDP) ─────────────│
//! │──────────────── Active P2P Transfers ───────────────│
//! └───────────────────── System Logs ───────────────────┘
//! ```
use crate::app::App;
use crate::storage::drift::DriftEvent;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// Renders the complete dashboard UI for the current [`App`] state.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header bar
            Constraint::Min(8),    // Network Topology
            Constraint::Length(6), // Active Transfers
            Constraint::Length(8), // System Logs
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_topology(f, app, chunks[1]);
    draw_transfers(f, app, chunks[2]);
    draw_logs(f, app, chunks[3]);
}

/// Renders the top header bar with device count and status.
fn draw_header(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let status = if app.is_running { "Active" } else { "Stopping" };
    let header_text = format!(
        " 🛰️  RLN v2.0  |  Known Devices: {}  |  Status: {}",
        app.known_devices, status
    );
    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title(" RLN Orchestrator "));
    f.render_widget(header, area);
}

/// Renders the LLDP network topology panel, grouping devices under their parent switch.
/// Also appends any active drift alerts below the topology tree.
fn draw_topology(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let mut items: Vec<ListItem> = Vec::new();

    if app.topology.is_empty() {
        items.push(ListItem::new(Span::styled(
            "  Scanning LLDP topology...",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for (switch_name, topo) in &app.topology {
            // Switch header row
            items.push(ListItem::new(Line::from(vec![
                Span::styled("🔌 ", Style::default().fg(Color::Blue)),
                Span::styled(
                    switch_name.clone(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  ·  Port: {}", topo.port_id),
                    Style::default().fg(Color::DarkGray),
                ),
            ])));

            // Device rows under this switch
            let last_idx = topo.devices.len().saturating_sub(1);
            for (i, device) in topo.devices.iter().enumerate() {
                let prefix = if i == last_idx { "  └─ " } else { "  ├─ " };
                let hostname = device.hostname.as_deref().unwrap_or("Unknown");
                items.push(ListItem::new(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} ", hostname),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        format!("({})  ", device.ip_address),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        device.mac_address.clone(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])));
            }
        }
    }

    // Drift Alert section
    if !app.active_drift_events.is_empty() {
        items.push(ListItem::new(""));
        items.push(ListItem::new(Span::styled(
            "  ⚠  Drift Alerts",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for event in &app.active_drift_events {
            let (icon, text, color) = format_drift_event(event);
            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!("    {} ", icon), Style::default().fg(color)),
                Span::styled(text, Style::default().fg(Color::White)),
            ])));
        }
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Network Topology (LLDP) "));
    f.render_widget(list, area);
}

/// Formats a [`DriftEvent`] into a human-readable (icon, text, color) tuple.
fn format_drift_event(event: &DriftEvent) -> (&'static str, String, Color) {
    match event {
        DriftEvent::NewDevice { mac, ip } => (
            "NEW",
            format!("{} @ {}", mac, ip),
            Color::Green,
        ),
        DriftEvent::IpChanged { mac, old_ip, new_ip } => (
            "CHG",
            format!("{}: {} → {}", mac, old_ip, new_ip),
            Color::Yellow,
        ),
        DriftEvent::DeviceOffline { mac, last_ip } => (
            "OFF",
            format!("{} (last seen @ {})", mac, last_ip),
            Color::Red,
        ),
        DriftEvent::NoChange { mac } => (
            "OK ",
            format!("{} — stable", mac),
            Color::DarkGray,
        ),
    }
}

/// Renders the active P2P transfers panel with progress and speed.
fn draw_transfers(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let mut items: Vec<ListItem> = Vec::new();

    if app.active_transfers.is_empty() {
        items.push(ListItem::new(Span::styled(
            "  No active transfers.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for t in &app.active_transfers {
            // Build a simple ASCII progress bar (20 chars wide)
            let filled = (t.progress_pct as usize * 20) / 100;
            let bar: String = format!(
                "[{}{}]",
                "█".repeat(filled),
                "░".repeat(20 - filled)
            );

            let line = Line::from(vec![
                Span::styled("📦 ", Style::default()),
                Span::styled(
                    format!("{:<30}", &t.filename),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {} {}%  ", bar, t.progress_pct),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("{:.1} Mb/s", t.speed_mbps),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("  → {}", t.peer_id),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Active P2P Transfers "));
    f.render_widget(list, area);
}

/// Renders the system log panel showing the most recent buffered log messages.
fn draw_logs(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Show newest logs at the bottom by reversing the deque iterator
    let items: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .map(|msg| {
            let color = if msg.contains("[ERROR]") || msg.contains("❌") {
                Color::Red
            } else if msg.contains("[WARNING]") || msg.contains("[DEGRADED]") || msg.contains("⚠") {
                Color::Yellow
            } else if msg.contains("✅") || msg.contains("[NETWORK]") {
                Color::Green
            } else {
                Color::White
            };
            ListItem::new(Span::styled(msg.clone(), Style::default().fg(color)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" System Logs (newest first) "));
    f.render_widget(list, area);
}
