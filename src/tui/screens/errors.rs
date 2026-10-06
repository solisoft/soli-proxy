//! The errors screen: 5xx per app from the daemon's counters (available
//! without any configuration), then the individual failures and 404s from
//! the log, newest first. A row that just arrived lights up and fades. `f`
//! shows all of them, the 5xx only, or the 404s only — with, for those, the
//! missing URLs asked for most.

use std::collections::HashMap;
use std::time::Instant;

use ratatui::{layout::Rect, style::Style, Frame};

use crate::tui::anim::Anim;
use crate::tui::errors::ErrorEntry;
use crate::tui::theme::{self, put};

/// Which rows the errors screen lists; `f` cycles through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ErrorsFilter {
    #[default]
    All,
    ServerErrors,
    NotFound,
}

impl ErrorsFilter {
    pub fn next(self) -> Self {
        match self {
            ErrorsFilter::All => ErrorsFilter::ServerErrors,
            ErrorsFilter::ServerErrors => ErrorsFilter::NotFound,
            ErrorsFilter::NotFound => ErrorsFilter::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ErrorsFilter::All => "5xx and 404",
            ErrorsFilter::ServerErrors => "5xx only",
            ErrorsFilter::NotFound => "404 only",
        }
    }

    pub fn matches(self, e: &ErrorEntry) -> bool {
        match self {
            ErrorsFilter::All => true,
            ErrorsFilter::ServerErrors => e.is_server_error(),
            ErrorsFilter::NotFound => e.status == Some(404),
        }
    }
}

/// The missing URLs asked for most in `entries`, as (host, path, count),
/// most first.
pub fn top_not_found(entries: &[&ErrorEntry], n: usize) -> Vec<(String, String, usize)> {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for e in entries.iter().filter(|e| e.status == Some(404)) {
        let key = (
            e.host.clone().unwrap_or_default(),
            e.path.clone().unwrap_or_default(),
        );
        *counts.entry(key).or_default() += 1;
    }
    let mut v: Vec<_> = counts.into_iter().map(|((h, p), c)| (h, p, c)).collect();
    v.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });
    v.truncate(n);
    v
}

pub struct ErrorsView<'a> {
    /// The rows the filter keeps, newest first.
    pub entries: &'a [&'a ErrorEntry],
    pub filter: ErrorsFilter,
    /// Every 404 in the log, for the top panel in 404 mode.
    pub not_found: &'a [(String, String, usize)],
    pub not_found_total: usize,
    pub selected_index: usize,
    pub scroll_offset: usize,
    /// When each entry (by [`ErrorEntry::key`]) was first seen.
    pub seen: &'a HashMap<String, Instant>,
    /// Apps answering 5xx right now, with their rate per second.
    pub erroring: &'a [(String, f64)],
    /// 5xx counted by the daemon since it started.
    pub total_5xx: Option<u64>,
}

/// Rows of the per-app panel, heading included.
const PER_APP_ROWS: u16 = 5;

/// Where the table starts: the per-app panel plus a blank line.
pub fn table_top() -> u16 {
    PER_APP_ROWS + 2
}

pub fn render(f: &mut Frame, area: Rect, view: &ErrorsView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);

    let chip = Style::default().fg(theme::INK).bg(theme::ACCENT).bold();

    let w = put(buf, area, 0, 0, " errors ", chip) + 2;
    let total = view
        .total_5xx
        .map(|n| {
            format!(
                "{} 5xx since the proxy started · {} 404 in the log",
                theme::fmt_num(anim.tween("errors.total", n as f64).round() as u64),
                view.not_found_total
            )
        })
        .unwrap_or_else(|| "daemon counters unavailable".into());
    let x = w + put(buf, area, w, 0, &total, muted) + 3;
    let x = x + put(
        buf,
        area,
        x,
        0,
        "f",
        Style::default().fg(theme::ACCENT).bold(),
    );
    put(buf, area, x + 1, 0, view.filter.label(), muted);

    if view.filter == ErrorsFilter::NotFound {
        render_top_not_found(buf, area, view);
    } else {
        render_per_app(buf, area, view, anim);
    }
    render_table(buf, area, view, anim);
}

/// 404 mode's top panel: the missing URLs asked for most.
fn render_top_not_found(buf: &mut ratatui::buffer::Buffer, area: Rect, view: &ErrorsView) {
    let head = Style::default().fg(theme::MUTED).bold();
    put(buf, area, 1, 2, "most requested missing URLs", head);
    if view.not_found.is_empty() {
        put(
            buf,
            area,
            30,
            2,
            "none in the log",
            Style::default().fg(theme::SUCCESS),
        );
        return;
    }
    for (i, (host, path, count)) in view
        .not_found
        .iter()
        .take((PER_APP_ROWS - 1) as usize)
        .enumerate()
    {
        let y = 3 + i as u16;
        put(
            buf,
            area,
            1,
            y,
            &format!("{count:>5}×"),
            Style::default().fg(theme::WARN).bold(),
        );
        put(
            buf,
            area,
            9,
            y,
            &theme::fit(host, 26),
            Style::default().fg(theme::FG),
        );
        put(
            buf,
            area,
            36,
            y,
            &theme::fit(path, area.width.saturating_sub(37) as usize),
            Style::default().fg(theme::ACCENT),
        );
    }
}

/// 5xx per minute, per app, from the metrics.
fn render_per_app(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    view: &ErrorsView,
    anim: &mut Anim,
) {
    let head = Style::default().fg(theme::MUTED).bold();
    put(buf, area, 1, 2, "5xx / min", head);
    if view.erroring.is_empty() {
        put(
            buf,
            area,
            12,
            2,
            "none right now",
            Style::default().fg(theme::SUCCESS),
        );
    }
    let max = view
        .erroring
        .iter()
        .map(|(_, e)| e * 60.0)
        .fold(1.0_f64, f64::max);
    let bar_room = area.width.saturating_sub(40).clamp(4, 40) as f64;
    for (i, (app, eps)) in view
        .erroring
        .iter()
        .take((PER_APP_ROWS - 1) as usize)
        .enumerate()
    {
        let y = 3 + i as u16;
        let per_min = anim.tween(&format!("errors.app.{app}"), eps * 60.0);
        put(
            buf,
            area,
            1,
            y,
            &theme::fit(app, 28),
            Style::default().fg(theme::FG),
        );
        let n = ((per_min / max) * bar_room).round().max(1.0) as usize;
        let color = if per_min >= 10.0 {
            theme::DANGER
        } else {
            theme::WARN
        };
        let bw = put(buf, area, 31, y, &"█".repeat(n), Style::default().fg(color));
        put(
            buf,
            area,
            32 + bw,
            y,
            &format!("{per_min:.1}"),
            Style::default().fg(theme::FG),
        );
    }
}

fn render_table(buf: &mut ratatui::buffer::Buffer, area: Rect, view: &ErrorsView, anim: &mut Anim) {
    let muted = Style::default().fg(theme::MUTED);
    let head = Style::default().fg(theme::MUTED).bold();
    let top = table_top();
    if view.entries.is_empty() && view.filter != ErrorsFilter::All {
        put(
            buf,
            area,
            1,
            top,
            &format!("Nothing in the log for {}.", view.filter.label()),
            Style::default().fg(theme::FG),
        );
        return;
    }
    if view.entries.is_empty() {
        put(
            buf,
            area,
            1,
            top,
            "No 5xx and no 404 in the log.",
            Style::default().fg(theme::FG),
        );
        put(
            buf,
            area,
            1,
            top + 2,
            "The list of individual requests (path, cause, duration) needs",
            muted,
        );
        put(
            buf,
            area,
            1,
            top + 3,
            "[logging] log_endpoints = true  in config.toml",
            Style::default().fg(theme::ACCENT),
        );
        put(
            buf,
            area,
            1,
            top + 4,
            "and the log in JSON format (the default). The counts above need nothing.",
            muted,
        );
        return;
    }

    // time 8 | code 5 | method 7 | host | path | cause 18 | took 8
    let fixed: u16 = 1 + 9 + 6 + 8 + 19 + 8;
    let flexible = area.width.saturating_sub(fixed + 2);
    let host_w = (flexible * 2 / 5).clamp(10, 30);
    let path_w = flexible.saturating_sub(host_w + 1).max(8);
    let xs = {
        let mut x = 1u16;
        let mut v = Vec::new();
        for w in [9, 6, 8, host_w + 1, path_w + 1, 19, 8] {
            v.push(x);
            x += w;
        }
        v
    };
    for (i, h) in ["time", "code", "method", "host", "path", "cause", "took"]
        .iter()
        .enumerate()
    {
        put(buf, area, xs[i], top, h, head);
    }

    let rows = area.height.saturating_sub(top + 1) as usize;
    let now = anim.now();
    for (i, e) in view
        .entries
        .iter()
        .enumerate()
        .skip(view.scroll_offset)
        .take(rows)
    {
        let y = top + 1 + (i - view.scroll_offset) as u16;
        let selected = i == view.selected_index;
        let fresh = view
            .seen
            .get(&e.key())
            .and_then(|at| anim.fade(now.duration_since(*at)));
        let (bg, fg) = match (selected, fresh) {
            (true, _) => (Some(theme::SELECT_BG), None),
            (false, Some(0)) => (Some(theme::FRESH_BG), Some(theme::WARN)),
            (false, Some(_)) => (Some(theme::FADING_BG), Some(theme::FADING_FG)),
            (false, None) => (None, None),
        };
        if let Some(bg) = bg {
            theme::shade(buf, area, 0, y, area.width, bg);
        }
        let st = |c| {
            let s = Style::default().fg(fg.unwrap_or(c));
            match bg {
                Some(bg) => s.bg(bg),
                None => s,
            }
        };
        if fresh == Some(0) {
            put(buf, area, 0, y, "▶", st(theme::WARN).bold());
        }
        let code = e.status_label();
        let code_color = if code.starts_with('5') || code == "ERR" {
            theme::DANGER
        } else {
            theme::WARN
        };
        let took = e
            .elapsed_ms
            .map(|ms| {
                if ms >= 1000 {
                    format!("{:.1} s", ms as f64 / 1000.0)
                } else {
                    format!("{ms} ms")
                }
            })
            .unwrap_or_else(|| "—".into());
        let slow = e.elapsed_ms.is_some_and(|ms| ms >= 5000);
        let cells: [(String, ratatui::style::Color); 7] = [
            (e.clock(), theme::MUTED),
            (code, code_color),
            (e.method.clone().unwrap_or_else(|| "—".into()), theme::FG),
            (
                theme::fit(e.host.as_deref().unwrap_or("—"), host_w as usize),
                theme::FG,
            ),
            (
                theme::fit(e.path.as_deref().unwrap_or("—"), path_w as usize),
                theme::ACCENT,
            ),
            (
                theme::fit(e.error.as_deref().unwrap_or("—"), 18),
                theme::MUTED,
            ),
            (took, if slow { theme::WARN } else { theme::FG }),
        ];
        for (j, (text, color)) in cells.iter().enumerate() {
            let style = if j == 1 {
                st(*color).bold()
            } else {
                st(*color)
            };
            put(buf, area, xs[j], y, text, style);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn without_endpoint_logging_it_says_where_to_turn_it_on() {
        let seen = HashMap::new();
        let erroring = vec![("grc.test".to_string(), 0.1)];
        let view = ErrorsView {
            entries: &[],
            filter: ErrorsFilter::All,
            not_found: &[],
            not_found_total: 0,
            selected_index: 0,
            scroll_offset: 0,
            seen: &seen,
            erroring: &erroring,
            total_5xx: Some(520),
        };
        let mut anim = Anim::new(false);
        anim.begin(Instant::now());
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| render(f, f.area(), &view, &mut anim))
            .unwrap();
        let buf = term.backend().buffer();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        assert!(text.contains("520 5xx since the proxy started"), "{text}");
        assert!(text.contains("grc.test"), "{text}");
        assert!(text.contains("6.0"), "0.1/s is 6 a minute: {text}");
        assert!(
            text.contains("log_endpoints = true  in config.toml"),
            "{text}"
        );
        assert!(!text.contains("proxy.conf"), "{text}");
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    fn entry(status: Option<u16>, host: &str, path: &str) -> ErrorEntry {
        ErrorEntry {
            timestamp: "2026-10-06T08:00:00Z".into(),
            method: Some("GET".into()),
            host: Some(host.into()),
            path: Some(path.into()),
            status,
            error: None,
            client_ip: None,
            elapsed_ms: Some(1),
        }
    }

    #[test]
    fn the_filter_splits_5xx_from_404() {
        let rows = [
            entry(Some(502), "a.test", "/x"),
            entry(None, "a.test", "/y"),
            entry(Some(404), "b.test", "/missing"),
        ];
        let count = |f: ErrorsFilter| rows.iter().filter(|e| f.matches(e)).count();
        assert_eq!(count(ErrorsFilter::All), 3);
        assert_eq!(count(ErrorsFilter::ServerErrors), 2);
        assert_eq!(count(ErrorsFilter::NotFound), 1);
        assert_eq!(ErrorsFilter::NotFound.next(), ErrorsFilter::All);
    }

    #[test]
    fn missing_urls_are_ranked_by_how_often_they_are_asked_for() {
        let rows = [
            entry(Some(404), "b.test", "/wp-login.php"),
            entry(Some(404), "b.test", "/old-page"),
            entry(Some(404), "b.test", "/wp-login.php"),
            entry(Some(502), "b.test", "/wp-login.php"),
            entry(Some(404), "c.test", "/wp-login.php"),
        ];
        let refs: Vec<&ErrorEntry> = rows.iter().collect();
        let top = top_not_found(&refs, 2);
        assert_eq!(
            top,
            vec![
                ("b.test".into(), "/wp-login.php".into(), 2),
                ("b.test".into(), "/old-page".into(), 1),
            ]
        );
    }
}
