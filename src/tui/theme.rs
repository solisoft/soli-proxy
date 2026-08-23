use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Mint-on-ink palette — distinct from the old default-cyan boxes.
pub const ACCENT: Color = Color::Rgb(0, 212, 170);
pub const ACCENT_DIM: Color = Color::Rgb(0, 120, 100);
pub const SUCCESS: Color = Color::Rgb(80, 250, 123);
pub const WARN: Color = Color::Rgb(255, 184, 108);
pub const DANGER: Color = Color::Rgb(255, 85, 85);
pub const MUTED: Color = Color::Rgb(98, 114, 164);
pub const FG: Color = Color::Rgb(248, 248, 242);
pub const SELECT_BG: Color = Color::Rgb(15, 55, 52);
pub const SIDEBAR_BG: Color = Color::Rgb(18, 22, 28);
pub const INK: Color = Color::Rgb(10, 12, 16);
pub const MAGENTA: Color = Color::Rgb(189, 147, 249);

pub const SIDEBAR_WIDTH: u16 = 16;

pub const SCREEN_SHORT: [&str; 6] = ["dash", "routes", "apps", "circuits", "errors", "config"];

/// Rows between the top of the sidebar and the first nav entry (brand block).
const NAV_TOP_OFFSET: u16 = 3;

pub fn selected_style() -> Style {
    Style::default()
        .bg(SELECT_BG)
        .fg(FG)
        .add_modifier(Modifier::BOLD)
}

pub fn row_style(selected: bool) -> Style {
    if selected {
        selected_style()
    } else {
        Style::default().fg(FG)
    }
}

/// Title chip, no wrapping cyan box — the old UI was "everything in a cyan frame".
pub fn list_block(title: &str) -> Block<'static> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(INK)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(ACCENT_DIM))
}

/// Content area of a full `Borders::ALL` box.
pub fn inner(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    )
}

/// Content area of a [`list_block`]: one column for the left rule, one row for
/// the title chip. Nothing is drawn on the right or bottom edge, so unlike
/// [`inner`] this keeps those cells.
pub fn body(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(1),
        area.height.saturating_sub(1),
    )
}

pub fn centered_modal(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2).max(1));
    let h = height.min(area.height.saturating_sub(2).max(1));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    Rect::new(area.x + x, area.y + y, w, h)
}

pub fn split_shell(area: Rect) -> (Rect, Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(10)])
        .split(area);
    (cols[0], cols[1])
}

pub fn render_sidebar(f: &mut Frame, area: Rect, current_idx: usize, version: &str) {
    f.render_widget(
        Block::default().style(Style::default().bg(SIDEBAR_BG)),
        area,
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(NAV_TOP_OFFSET),
            Constraint::Length(SCREEN_SHORT.len() as u16 + 2),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(area);

    let brand = Paragraph::new(vec![
        Line::from(Span::styled(
            " SOLI",
            Style::default()
                .fg(INK)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            " proxy",
            Style::default().fg(MUTED).bg(SIDEBAR_BG),
        )),
    ]);
    f.render_widget(brand, chunks[0]);

    let mut lines = Vec::new();
    for (i, short) in SCREEN_SHORT.iter().enumerate() {
        let active = i == current_idx;
        let marker = if active { "▸" } else { " " };
        let label = format!(" {marker} {} {short:<8}", i + 1);
        let style = if active {
            Style::default()
                .fg(ACCENT)
                .bg(SELECT_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED).bg(SIDEBAR_BG)
        };
        lines.push(Line::from(Span::styled(label, style)));
    }
    f.render_widget(Paragraph::new(lines), chunks[1]);

    let foot = Paragraph::new(vec![
        Line::from(Span::styled(
            format!(" v{version}"),
            Style::default().fg(MUTED).bg(SIDEBAR_BG),
        )),
        Line::from(Span::styled(
            " 1-6  ?",
            Style::default().fg(ACCENT_DIM).bg(SIDEBAR_BG),
        )),
    ]);
    f.render_widget(foot, chunks[3]);
}

/// Nav item under the brand block, or `None` when the click misses the list.
pub fn nav_at(area: Rect, col: u16, row: u16) -> Option<usize> {
    if col < area.x || col >= area.x.saturating_add(area.width) {
        return None;
    }
    if row >= area.y.saturating_add(area.height) {
        return None;
    }
    let first = area.y.saturating_add(NAV_TOP_OFFSET);
    if row < first {
        return None;
    }
    let idx = (row - first) as usize;
    if idx < SCREEN_SHORT.len() {
        Some(idx)
    } else {
        None
    }
}

pub fn spinner_frame(ticks: u64) -> char {
    const FRAMES: [char; 4] = ['⠋', '⠙', '⠹', '⠸'];
    FRAMES[(ticks as usize) % FRAMES.len()]
}

pub fn fmt_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub fn fmt_num(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

pub fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else if ms >= 1.0 {
        format!("{:.1}ms", ms)
    } else if ms > 0.0 {
        format!("{:.0}us", ms * 1000.0)
    } else {
        "-".to_string()
    }
}

pub fn fmt_uptime(uptime: std::time::Duration) -> String {
    let secs = uptime.as_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

pub fn rps_from_delta(prev: u64, next: u64, elapsed_secs: f64) -> u64 {
    if elapsed_secs <= 0.0 || next < prev {
        return 0;
    }
    ((next - prev) as f64 / elapsed_secs).round() as u64
}

pub fn render_toast(f: &mut Frame, area: Rect, message: &str) {
    if area.height == 0 || message.is_empty() {
        return;
    }
    f.render_widget(Clear, area);
    let para = Paragraph::new(format!(" {message} "))
        .style(
            Style::default()
                .fg(INK)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);
    f.render_widget(para, area);
}

pub fn kpi(f: &mut Frame, area: Rect, value: &str, label: &str, color: Color) {
    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(color));
    let inner = Rect::new(
        area.x.saturating_add(2),
        area.y,
        area.width.saturating_sub(2),
        area.height,
    );
    f.render_widget(block, area);
    let lines = vec![
        Line::from(Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(label, Style::default().fg(MUTED))),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rps_from_delta_basic() {
        assert_eq!(rps_from_delta(100, 200, 1.0), 100);
        assert_eq!(rps_from_delta(100, 100, 1.0), 0);
        assert_eq!(rps_from_delta(200, 100, 1.0), 0);
        assert_eq!(rps_from_delta(0, 50, 2.0), 25);
    }

    #[test]
    fn nav_at_picks_item() {
        let area = Rect::new(0, 0, 16, 24);
        assert_eq!(nav_at(area, 1, 3), Some(0));
        assert_eq!(nav_at(area, 1, 5), Some(2));
        assert_eq!(nav_at(area, 1, 2), None);
        assert_eq!(nav_at(area, 20, 3), None);
    }
}
