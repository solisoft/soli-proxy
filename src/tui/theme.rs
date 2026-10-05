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
pub const CYAN: Color = Color::Rgb(139, 233, 253);
/// Something that just arrived (an event, an error row): first second.
pub const FRESH_BG: Color = Color::Rgb(58, 42, 18);
/// ...and while it fades, up to three seconds.
pub const FADING_BG: Color = Color::Rgb(38, 29, 16);
pub const FADING_FG: Color = Color::Rgb(232, 197, 146);

/// Below this width the screens are tabs on a top line instead of a sidebar,
/// which would take a fifth of an 80-column terminal.
pub const SIDEBAR_MIN_WIDTH: u16 = 140;

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

/// Where the navigation goes and what is left for the screen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Shell {
    pub nav: Rect,
    pub rest: Rect,
    /// Navigation is a line of tabs at the top rather than a sidebar.
    pub tabs: bool,
}

pub fn shell(area: Rect) -> Shell {
    if area.width >= SIDEBAR_MIN_WIDTH {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(10)])
            .split(area);
        Shell {
            nav: cols[0],
            rest: cols[1],
            tabs: false,
        }
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(area);
        Shell {
            nav: rows[0],
            rest: rows[1],
            tabs: true,
        }
    }
}

pub fn render_nav(f: &mut Frame, shell: Shell, current_idx: usize, version: &str) {
    if shell.tabs {
        render_tabs(f, shell.nav, current_idx, version);
    } else {
        render_sidebar(f, shell.nav, current_idx, version);
    }
}

/// The screen a click on the navigation picks, sidebar or tabs.
pub fn nav_hit(shell: Shell, col: u16, row: u16) -> Option<usize> {
    if shell.tabs {
        tab_at(shell.nav, col, row)
    } else {
        nav_at(shell.nav, col, row)
    }
}

/// Columns the tabs line spends before the first tab (" SOLI " + a space).
const TABS_LEFT: u16 = 7;

fn tab_label(i: usize, short: &str) -> String {
    format!(" {} {short} ", i + 1)
}

pub fn render_tabs(f: &mut Frame, area: Rect, current_idx: usize, version: &str) {
    f.render_widget(
        Block::default().style(Style::default().bg(SIDEBAR_BG)),
        area,
    );
    let mut spans = vec![
        Span::styled(
            " SOLI ",
            Style::default()
                .fg(INK)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ", Style::default().bg(SIDEBAR_BG)),
    ];
    for (i, short) in SCREEN_SHORT.iter().enumerate() {
        let style = if i == current_idx {
            Style::default()
                .fg(ACCENT)
                .bg(SELECT_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED).bg(SIDEBAR_BG)
        };
        spans.push(Span::styled(tab_label(i, short), style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    let v = format!("v{version} ");
    let w = v.chars().count() as u16;
    let used = TABS_LEFT
        + SCREEN_SHORT
            .iter()
            .enumerate()
            .map(|(i, s)| tab_label(i, s).chars().count() as u16)
            .sum::<u16>();
    if area.width > used + w {
        f.render_widget(
            Paragraph::new(Span::styled(v, Style::default().fg(MUTED).bg(SIDEBAR_BG))),
            Rect::new(area.x + area.width - w, area.y, w, 1),
        );
    }
}

/// Tab under a click on the tabs line.
pub fn tab_at(area: Rect, col: u16, row: u16) -> Option<usize> {
    if row != area.y || col < area.x + TABS_LEFT {
        return None;
    }
    let mut x = area.x + TABS_LEFT;
    for (i, short) in SCREEN_SHORT.iter().enumerate() {
        let w = tab_label(i, short).chars().count() as u16;
        if col < x + w {
            return Some(i);
        }
        x += w;
    }
    None
}

/// Write `text` at (`x`, `y`) relative to `area`, clipped to it. Returns the
/// columns written. The screens that draw diagrams place every glyph
/// themselves; this keeps them from spilling out of their panel.
pub fn put(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    x: u16,
    y: u16,
    text: &str,
    style: Style,
) -> u16 {
    if y >= area.height || x >= area.width {
        return 0;
    }
    let max = (area.width - x) as usize;
    let (end, _) = buf.set_stringn(area.x + x, area.y + y, text, max, style);
    end.saturating_sub(area.x + x)
}

/// Paint the background of `width` cells from (`x`, `y`) in `area`.
pub fn shade(buf: &mut ratatui::buffer::Buffer, area: Rect, x: u16, y: u16, width: u16, bg: Color) {
    if y >= area.height || x >= area.width {
        return;
    }
    let w = width.min(area.width - x);
    buf.set_style(
        Rect::new(area.x + x, area.y + y, w, 1),
        Style::default().bg(bg),
    );
}

/// `text` cut to `width` characters, with an ellipsis when it was longer,
/// padded with spaces to exactly `width`.
pub fn fit(text: &str, width: usize) -> String {
    let n = text.chars().count();
    if n <= width {
        format!("{text}{}", " ".repeat(width - n))
    } else if width == 0 {
        String::new()
    } else {
        let mut s: String = text.chars().take(width - 1).collect();
        s.push('…');
        s
    }
}

/// Eight-level bars for a sparkline of `values`, scaled to their maximum.
pub fn bars(values: &[f64]) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = values.iter().copied().fold(0.0_f64, f64::max);
    values
        .iter()
        .map(|&v| {
            if max <= 0.0 {
                '▁'
            } else {
                LEVELS[((v / max) * 7.0).round().clamp(0.0, 7.0) as usize]
            }
        })
        .collect()
}

/// Short uptime: `2d01h`, `13h04m`, `4m`, `12s`.
pub fn fmt_age(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d{:02}h", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
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
    fn tab_at_follows_the_labels() {
        let area = Rect::new(0, 0, 80, 1);
        // " SOLI " + " " = 7 columns, then " 1 dash " (8 wide).
        assert_eq!(tab_at(area, 3, 0), None);
        assert_eq!(tab_at(area, 7, 0), Some(0));
        assert_eq!(tab_at(area, 14, 0), Some(0));
        assert_eq!(tab_at(area, 15, 0), Some(1));
        assert_eq!(tab_at(area, 15, 1), None);
        assert_eq!(tab_at(area, 79, 0), None);
    }

    #[test]
    fn the_shell_switches_to_tabs_on_narrow_terminals() {
        assert!(shell(Rect::new(0, 0, 80, 24)).tabs);
        assert!(!shell(Rect::new(0, 0, 160, 45)).tabs);
        let s = shell(Rect::new(0, 0, 80, 24));
        assert_eq!((s.nav.height, s.rest.y, s.rest.height), (1, 1, 23));
    }

    #[test]
    fn fit_and_bars() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(bars(&[0.0, 0.0]), "▁▁");
        assert_eq!(bars(&[1.0, 2.0, 4.0]).chars().last(), Some('█'));
        assert_eq!(fmt_age(90), "1m");
        assert_eq!(fmt_age(2 * 86400 + 3600), "2d01h");
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
