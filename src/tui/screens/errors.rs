//! The errors screen: 5xx per app from the daemon's counters (available
//! without any configuration), then the individual failures from the log,
//! newest first. A failure that just arrived lights up and fades.

use std::collections::HashMap;
use std::time::Instant;

use ratatui::{layout::Rect, style::Style, Frame};

use crate::tui::anim::Anim;
use crate::tui::errors::ErrorEntry;
use crate::tui::theme::{self, put};

pub struct ErrorsView<'a> {
    /// Newest first.
    pub entries: &'a [ErrorEntry],
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
    let head = Style::default().fg(theme::MUTED).bold();
    let chip = Style::default().fg(theme::INK).bg(theme::ACCENT).bold();

    let w = put(buf, area, 0, 0, " errors ", chip) + 2;
    let total = view
        .total_5xx
        .map(|n| {
            format!(
                "{} 5xx since the proxy started",
                theme::fmt_num(anim.tween("errors.total", n as f64).round() as u64)
            )
        })
        .unwrap_or_else(|| "daemon counters unavailable".into());
    put(buf, area, w, 0, &total, muted);

    // 5xx per minute, per app, from the metrics.
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

    let top = table_top();
    if view.entries.is_empty() {
        put(
            buf,
            area,
            1,
            top,
            "No request failures in the log.",
            Style::default().fg(theme::FG),
        );
        put(
            buf,
            area,
            1,
            top + 2,
            "The list of individual failures (path, cause, duration) needs",
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
