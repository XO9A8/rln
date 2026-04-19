//! Dashboard view for the RLN TUI.
//!
//! Renders a four-pane layout:
//! ```text
//! ┌────────────────────── Header ───────────────────────┐
//! │─────────────── Network Topology (LLDP) ─────────────│
//! │──────────────── Active P2P Transfers ───────────────│
//! └───────────────────── System Logs ───────────────────┘
//! ```
use crate::app::{App, InputMode};
use crate::storage::drift::DriftEvent;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, BorderType, Clear, List, ListItem, Paragraph, Wrap},
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

    // Render the send-file overlay on top when in SendFile mode
    if app.input_mode == InputMode::SendFile {
        draw_send_overlay(f, app);
    }
}

/// Renders the top header bar with device count and status.
fn draw_header(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let status = if app.is_running { "Active" } else { "Stopping" };
    let short_peer_id = &app.local_peer_id[..8.min(app.local_peer_id.len())];
    let header_text = format!(
        " 🛰️  RLN |  Known Devices: {}  |  Status: {}  |  My Peer ID: {}",
        app.known_devices, status, short_peer_id
    );
    let header = Paragraph::new(header_text)
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" RLN Orchestrator ")
                .title_alignment(Alignment::Center)
        );
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

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Blue))
            .title(" Network Topology (LLDP) "),
    );
    f.render_widget(list, area);
}

/// Formats a [`DriftEvent`] into a human-readable (icon, text, color) tuple.
fn format_drift_event(event: &DriftEvent) -> (&'static str, String, Color) {
    match event {
        DriftEvent::NewDevice { mac, ip } => ("NEW", format!("{} @ {}", mac, ip), Color::Green),
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
        DriftEvent::NoChange { mac } => ("OK ", format!("{} — stable", mac), Color::DarkGray),
    }
}

/// Renders the active P2P transfers panel with progress and speed.
///
/// Filenames are capped at 28 chars and Peer IDs at 16 chars to prevent
/// any single row from wrapping and breaking the fixed-height panel.
fn draw_transfers(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let mut items: Vec<ListItem> = Vec::new();

    if app.active_transfers.is_empty() {
        items.push(ListItem::new(Span::styled(
            "  No active transfers.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for t in &app.active_transfers {
            let filled = (t.progress_pct as usize * 20) / 100;
            let bar = format!("[{}{}]", "█".repeat(filled), "░".repeat(20 - filled));

            // Truncate so the row is guaranteed to fit on one terminal line
            let fname = truncate(&t.filename, 28);
            let peer  = truncate(&t.peer_id,  8);

            let line = Line::from(vec![
                Span::styled("📦 ", Style::default()),
                Span::styled(
                    format!("{:<28} ", fname),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} {}%  ", bar, t.progress_pct),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("{:.1} Mb/s", t.speed_mbps),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("  → {}", peer),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            items.push(ListItem::new(line));
        }
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Green))
            .title(" Active P2P Transfers "),
    );
    f.render_widget(list, area);
}

/// Renders the system log panel.
///
/// Uses [`Paragraph`] + [`Wrap`] instead of `List` so that long lines
/// (e.g. 52-char Iroh node ID hashes) wrap *within* the panel boundaries
/// rather than overflowing into the pane below and breaking the layout.
/// Logs are displayed newest-first.
fn draw_logs(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .map(|msg| {
            let color = if msg.contains("[ERROR]") {
                Color::Red
            } else if msg.contains("[WARNING]") || msg.contains("[DEGRADED]") {
                Color::Yellow
            } else if msg.contains("[SUCCESS]") || msg.contains("[NETWORK]") {
                Color::Green
            } else {
                Color::White
            };
            Line::from(Span::styled(msg.clone(), Style::default().fg(color)))
        })
        .collect();

    let paragraph = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(if app.log_scroll_offset > 0 {
                    " System Logs (newest first)  ↓ Scroll "
                } else {
                    " System Logs (newest first) "
                }),
        )
        .scroll((app.log_scroll_offset, 0))
        .wrap(Wrap { trim: true }); // long lines wrap inside the widget, not outside

    f.render_widget(paragraph, area);
}

/// Truncates `s` to at most `max_chars` Unicode scalar values.
/// Appends a `…` ellipsis character if the string was shortened.
fn truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}…", head)
    } else {
        head
    }
}

/// Renders a centered modal overlay for the send-file command.
///
/// The overlay clears its area with [`Clear`] before drawing so it sits
/// cleanly on top of whatever panel is underneath it.
fn draw_send_overlay(f: &mut Frame, app: &App) {
    let area = centered_rect(70, 7, f.area());

    // Clear the background so the popup doesn't show through
    f.render_widget(Clear, area);

    let prompt = Line::from(vec![
        Span::styled(
            "Peer ID/Name: ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "My-Laptop or b09ceb10 ",
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let example = Line::from(vec![
        Span::styled(
            "Filepath    : ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "/home/user/doc.pdf",
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let divider = Line::from("");
    let input_line = Line::from(vec![
        Span::styled(
            " 🚀 ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            app.input_buffer.clone(),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        // Blinking cursor block
        Span::styled(
            "█",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::RAPID_BLINK),
        ),
    ]);

    let text = Text::from(vec![prompt, example, divider, input_line]);

    let popup = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Yellow))
                .title(Span::styled(
                    " 📤 Send File  [Enter = send]  [Esc = cancel] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
                .title_alignment(Alignment::Center),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(popup, area);
}

/// Computes a centered [`Rect`] with the given percentage width and absolute height.
///
/// Used to position modal popups in the center of the terminal.
fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_width = r.width * percent_x / 100;
    let x = r.x + (r.width.saturating_sub(popup_width)) / 2;
    let y = r.y + (r.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width: popup_width.min(r.width),
        height: height.min(r.height),
    }
}
