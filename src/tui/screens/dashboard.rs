//! The dashboard: what the proxy is doing right now.
//!
//! A two-line strip of numbers, then the traffic panel — each active app a
//! branch of the proxy, with packets travelling down it as densely as it gets
//! requests, red for 5xx, a still dotted line when it is asleep or stopped, a
//! stepper under it while it deploys — and on the right the HTTP status mix
//! and a journal of what just happened.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use ratatui::{layout::Rect, style::Style, Frame};

use crate::app::AppInfo;
use crate::circuit_breaker::CircuitBreakerInfo;
use crate::metrics::MetricsSnapshot;
use crate::tui::anim::Anim;
use crate::tui::app::{AppStats, DaemonStatus};
use crate::tui::events::{DeployProgress, EventKind, JournalEntry};
use crate::tui::screens::common::{life, link, live_instance, stepper, Life};
use crate::tui::theme::{self, put};
use crate::tui::TuiContext;

/// The daemon's own version and uptime (`/api/v1/status`), not the TUI's.
#[derive(Debug, Clone)]
pub struct DaemonView {
    pub version: String,
    pub uptime: Duration,
}

/// Memory: what the apps hold, and what the host has.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryView {
    /// Resident memory of every app process, and how many apps that covers.
    pub apps: Option<(u64, usize)>,
    pub system: Option<crate::metrics::SystemMemory>,
}

/// `remote_snap` carries traffic counters fetched from the daemon's admin API.
/// The TUI runs in its own process, so its local metrics registry is always
/// empty — `status` is what decides whether the numbers mean anything.
pub struct DashboardView<'a> {
    pub remote_snap: Option<&'a MetricsSnapshot>,
    pub circuits: Option<&'a [(String, CircuitBreakerInfo)]>,
    pub status: DaemonStatus,
    pub rps_history: &'a VecDeque<u64>,
    pub apps: &'a [AppInfo],
    pub app_stats: &'a HashMap<String, AppStats>,
    /// Smoothed traffic per app: the order of the traffic panel.
    pub rank: &'a HashMap<String, f64>,
    pub deploys: &'a HashMap<String, DeployProgress>,
    pub waking: &'a [String],
    /// Oldest first.
    pub journal: &'a [JournalEntry],
    pub stream_connected: bool,
    pub daemon: Option<DaemonView>,
    pub memory: MemoryView,
    /// What the daemon has closed for maintenance; `None` while unknown.
    pub maintenance: Option<&'a crate::tui::app::MaintenanceInfo>,
}

/// Right-hand column width, when the terminal is wide enough for it.
const SIDE: u16 = 28;
/// Below this panel width the right-hand column is dropped.
const SIDE_MIN_TOTAL: u16 = 96;
/// How long an app that just fell asleep stays on the traffic panel.
const RECENTLY_ASLEEP: Duration = Duration::from_secs(120);

pub fn render(f: &mut Frame, area: Rect, ctx: &TuiContext, view: &DashboardView, anim: &mut Anim) {
    if area.height < 4 || area.width < 20 {
        return;
    }
    render_strip(f, Rect::new(area.x, area.y, area.width, 2), ctx, view, anim);
    let body = Rect::new(
        area.x,
        area.y + 2,
        area.width,
        area.height.saturating_sub(2),
    );
    if body.width >= SIDE_MIN_TOTAL {
        let flow = Rect::new(body.x, body.y, body.width - SIDE - 1, body.height);
        let side = Rect::new(body.x + body.width - SIDE, body.y, SIDE, body.height);
        let buf = f.buffer_mut();
        for y in 0..body.height {
            put(
                buf,
                body,
                body.width - SIDE - 1,
                y,
                "│",
                Style::default().fg(theme::ACCENT_DIM),
            );
        }
        render_flow(f, flow, ctx, view, anim);
        render_side(f, side, view, anim);
    } else if body.height >= 16 {
        // No room for the right-hand column: memory and the journal go
        // underneath.
        let journal_h = (body.height / 3).clamp(4, 8);
        let mem_h: u16 = 2;
        let flow = Rect::new(body.x, body.y, body.width, body.height - journal_h - mem_h);
        let mem = Rect::new(
            body.x,
            body.y + body.height - journal_h - mem_h,
            body.width,
            1,
        );
        let below = Rect::new(
            body.x,
            body.y + body.height - journal_h,
            body.width,
            journal_h,
        );
        render_flow(f, flow, ctx, view, anim);
        render_memory_line(f.buffer_mut(), mem, &view.memory, anim);
        render_journal_compact(f, below, view, anim);
    } else {
        render_flow(f, body, ctx, view, anim);
    }
}

/// The journal on one line per event, for terminals too narrow for the
/// right-hand column.
fn render_journal_compact(f: &mut Frame, area: Rect, view: &DashboardView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    put(
        buf,
        area,
        0,
        0,
        " events ",
        Style::default().fg(theme::INK).bg(theme::ACCENT).bold(),
    );
    if view.journal.is_empty() {
        let note = if view.stream_connected {
            "nothing yet"
        } else {
            "nothing yet · event stream offline"
        };
        put(buf, area, 10, 0, note, muted);
        return;
    }
    let now = anim.now();
    let rows = area.height.saturating_sub(1) as usize;
    for (i, e) in view.journal.iter().rev().take(rows).enumerate() {
        let y = 1 + i as u16;
        let fresh = anim.fade(now.duration_since(e.at));
        let bg = match fresh {
            Some(0) => Some(theme::FRESH_BG),
            Some(_) => Some(theme::FADING_BG),
            None => None,
        };
        if let Some(bg) = bg {
            theme::shade(buf, area, 0, y, area.width, bg);
        }
        let st = |c| match bg {
            Some(bg) => Style::default().fg(c).bg(bg),
            None => Style::default().fg(c),
        };
        put(buf, area, 1, y, &e.clock, st(theme::MUTED));
        let app_w = 24usize.min(area.width.saturating_sub(12) as usize);
        put(buf, area, 10, y, &theme::fit(&e.app, app_w), st(theme::FG));
        put(
            buf,
            area,
            11 + app_w as u16,
            y,
            &e.text,
            st(kind_color(e.kind)),
        );
    }
}

fn kind_color(kind: EventKind) -> ratatui::style::Color {
    match kind {
        EventKind::Deploy | EventKind::Waking => theme::WARN,
        EventKind::Traffic => theme::ACCENT,
        EventKind::Done => theme::SUCCESS,
        EventKind::Failed | EventKind::Error => theme::DANGER,
        EventKind::Asleep => theme::MAGENTA,
        EventKind::Maintenance => theme::WARN,
    }
}

fn render_strip(
    f: &mut Frame,
    area: Rect,
    ctx: &TuiContext,
    view: &DashboardView,
    anim: &mut Anim,
) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    put(
        buf,
        area,
        0,
        1,
        &"─".repeat(area.width as usize),
        Style::default().fg(theme::ACCENT_DIM),
    );

    let Some(snap) = view.remote_snap else {
        let why = match view.status.explain() {
            "" => "no metrics",
            other => other,
        };
        let x = 1 + put(buf, area, 1, 0, "— ", muted);
        let x = x + put(
            buf,
            area,
            x,
            0,
            why,
            Style::default().fg(view.status.color()),
        );
        put(
            buf,
            area,
            x,
            0,
            "   traffic numbers come from the daemon's admin API",
            muted,
        );
        return;
    };

    // Groups of (text, style), drawn left to right while a whole group fits:
    // a narrow terminal loses the last figures, never half of one.
    let mut groups: Vec<Vec<(String, Style)>> = Vec::new();
    let req = anim.tween("kpi.req", snap.requests_total as f64);
    groups.push(vec![
        (
            theme::fmt_num(req.round() as u64),
            Style::default().fg(theme::ACCENT).bold(),
        ),
        (" requests".into(), muted),
    ]);
    let rps_now = view.rps_history.back().copied().unwrap_or(0) as f64;
    let rps = anim.tween("kpi.rps", rps_now);
    let hist: Vec<f64> = view
        .rps_history
        .iter()
        .rev()
        .take(16)
        .rev()
        .map(|&v| v as f64)
        .collect();
    let mut g = vec![
        (
            format!("{}", rps.round() as u64),
            Style::default().fg(theme::SUCCESS).bold(),
        ),
        (" req/s ".into(), muted),
    ];
    if !hist.is_empty() {
        g.push((theme::bars(&hist), Style::default().fg(theme::ACCENT)));
    }
    groups.push(g);
    let lat = anim.tween("kpi.lat", snap.avg_response_time_ms);
    groups.push(vec![
        (theme::fmt_ms(lat), Style::default().fg(theme::WARN).bold()),
        (" latency".into(), muted),
    ]);
    // The share of responses that were 5xx: what went wrong on the server
    // side. (`errors_total` also counts the proxy's own refusals — 421s,
    // failed auth — which are not failures of anything.)
    let answered = snap.status_2xx + snap.status_3xx + snap.status_4xx + snap.status_5xx;
    let rate_5xx = if answered > 0 {
        snap.status_5xx as f64 / answered as f64 * 100.0
    } else {
        0.0
    };
    let rate_color = if snap.status_5xx > 0 {
        theme::DANGER
    } else {
        theme::SUCCESS
    };
    groups.push(vec![
        (
            format!("{rate_5xx:.2} %"),
            Style::default().fg(rate_color).bold(),
        ),
        (" 5xx".into(), muted),
    ]);
    if let Some(global) = view.maintenance.and_then(|m| m.global.as_ref()) {
        let until = global
            .until
            .as_deref()
            .map(|u| format!(" until {}", crate::tui::app::fmt_until(u)))
            .unwrap_or_default();
        groups.push(vec![(
            format!("◆ whole proxy in maintenance{until}"),
            Style::default().fg(theme::DANGER).bold(),
        )]);
    }
    if let Some(circuits) = view.circuits {
        let open = circuits.iter().filter(|(_, c)| c.state == "open").count();
        if open > 0 {
            groups.push(vec![(
                format!("⚠ {open} circuit{} open", if open > 1 { "s" } else { "" }),
                Style::default().fg(theme::DANGER).bold(),
            )]);
        }
    }
    if let Some(d) = &view.daemon {
        groups.push(vec![
            ("up ".into(), muted),
            (
                theme::fmt_age(d.uptime.as_secs()),
                Style::default().fg(theme::FG),
            ),
        ]);
    }
    let running = view
        .apps
        .iter()
        .filter(|a| live_instance(a).pid.is_some())
        .count();
    groups.push(vec![
        (
            format!("{running}/{}", view.apps.len()),
            Style::default().fg(theme::FG),
        ),
        (" apps".into(), muted),
    ]);
    if let Some((bytes, _)) = view.memory.apps {
        let shown = anim.tween("kpi.apps_mem", bytes as f64);
        groups.push(vec![
            (
                theme::fmt_bytes(shown as u64),
                Style::default().fg(theme::MAGENTA).bold(),
            ),
            (" in apps".into(), muted),
        ]);
    }
    if let Some(sys) = view.memory.system {
        groups.push(vec![
            (
                theme::fmt_bytes(sys.available_bytes),
                Style::default().fg(available_color(sys)).bold(),
            ),
            (" free".into(), muted),
        ]);
    }
    groups.push(vec![
        (
            ctx.config_manager.get_config().rules.len().to_string(),
            Style::default().fg(theme::FG),
        ),
        (" routes".into(), muted),
    ]);

    let mut x = 1u16;
    for group in groups {
        let w: u16 = group.iter().map(|(t, _)| t.chars().count() as u16).sum();
        if x + w > area.width {
            break;
        }
        for (text, style) in &group {
            x += put(buf, area, x, 0, text, *style);
        }
        x += 3;
    }
}

/// One app row of the traffic panel.
struct Branch<'a> {
    app: &'a AppInfo,
    /// Until when it is closed for maintenance, when it is and that is set.
    closed_until: Option<String>,
    life: Life,
    rps: f64,
    eps: f64,
    deploy: Option<&'a DeployProgress>,
}

fn render_flow(f: &mut Frame, area: Rect, ctx: &TuiContext, view: &DashboardView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    let dim = Style::default().fg(theme::ACCENT_DIM);
    put(
        buf,
        area,
        0,
        0,
        " traffic ",
        Style::default().fg(theme::INK).bg(theme::ACCENT).bold(),
    );

    let total_rps = view.rps_history.back().copied().unwrap_or(0) as f64;
    put(buf, area, 1, 2, "clients", Style::default().fg(theme::FG));
    link(
        buf,
        area,
        9,
        2,
        16,
        total_rps,
        0.0,
        view.remote_snap.is_none(),
        anim,
    );
    put(buf, area, 25, 2, "▶", Style::default().fg(theme::ACCENT));
    // It spins while requests flow; an idle proxy is a still dot, so an
    // idle dashboard costs no redraws.
    let spin = if !view.status.is_ok() {
        '○'
    } else if total_rps > 0.0 {
        anim.spinner()
    } else {
        '●'
    };
    let mut x = 27;
    x += put(
        buf,
        area,
        x,
        2,
        &format!("{spin} soli-proxy"),
        Style::default().fg(theme::ACCENT).bold(),
    );
    let cfg = ctx.config_manager.get_config();
    let version = view
        .daemon
        .as_ref()
        .map(|d| format!(" · v{}", d.version))
        .unwrap_or_default();
    put(
        buf,
        area,
        x + 1,
        2,
        &format!(":{}{version}", cfg.server.https_port),
        muted,
    );

    let now = anim.now();
    let recently_asleep: Vec<&str> = view
        .journal
        .iter()
        .filter(|e| e.kind == EventKind::Asleep && now.duration_since(e.at) < RECENTLY_ASLEEP)
        .map(|e| e.app.as_str())
        .collect();

    let mut branches: Vec<Branch> = Vec::new();
    let (mut quiet, mut asleep) = (0usize, 0usize);
    for app in view.apps {
        let name = app.config.name.as_str();
        let stats = view.app_stats.get(name);
        let deploy = view.deploys.get(name);
        let waking = view.waking.iter().any(|w| w == name);
        let closed = view.maintenance.and_then(|m| m.closed(name));
        let l = life(app, stats, deploy, waking, closed.is_some());
        let closed_until = closed
            .as_ref()
            .and_then(|c| c.window())
            .and_then(|w| w.until.as_deref())
            .map(crate::tui::app::fmt_until);
        let rps = stats.map_or(0.0, |s| s.rps);
        let eps = stats.map_or(0.0, |s| s.eps);
        // Smoothed traffic keeps an app on the panel for a while after its
        // last request (a still line), instead of blinking in and out.
        let recent = view.rank.get(name).copied().unwrap_or(0.0) > 0.02;
        let shown = rps > 0.05
            || recent
            || eps > 0.0
            || deploy.is_some()
            || matches!(
                l,
                Life::Waking | Life::Failed | Life::Unhealthy | Life::Maintenance
            )
            || (l == Life::Asleep && recently_asleep.contains(&name));
        if shown {
            branches.push(Branch {
                app,
                closed_until,
                life: l,
                rps,
                eps,
                deploy,
            });
        } else if l == Life::Asleep {
            asleep += 1;
        } else {
            quiet += 1;
        }
    }
    // Problems first, then by smoothed traffic (it changes slowly, so rows
    // do not trade places every second), then by name.
    let urgency = |l: Life| matches!(l, Life::Failed | Life::Unhealthy) as u8;
    branches.sort_by(|a, b| {
        urgency(b.life)
            .cmp(&urgency(a.life))
            .then_with(|| {
                let ra = view.rank.get(&a.app.config.name).copied().unwrap_or(0.0);
                let rb = view.rank.get(&b.app.config.name).copied().unwrap_or(0.0);
                rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.app.config.name.cmp(&b.app.config.name))
    });

    let tx: u16 = 28; // trunk column, under the proxy
    put(buf, area, tx, 3, "│", dim);
    let link_len: u16 = 14;
    let l1 = tx + 1 + link_len;
    // name | rate (8) | marker
    let name_w = area.width.saturating_sub(l1 + 4 + 10).clamp(10, 30) as usize;
    let rate_x = l1 + 4 + name_w as u16 + 1;

    // Rows left after the header (y 0..=3) and the summary line.
    let max_y = area.height.saturating_sub(1);
    let mut y: u16 = 4;
    let rows_needed = |b: &Branch| 1 + u16::from(b.deploy.is_some());
    let mut hidden = 0usize;
    let count = branches.len();
    for (i, b) in branches.iter().enumerate() {
        let need = rows_needed(b);
        // Keep the last row for "+N more" when everything will not fit.
        let room_left = max_y.saturating_sub(y);
        let more_after = count - i - 1;
        if need > room_left || (more_after > 0 && need + 1 > room_left) {
            hidden = count - i;
            break;
        }
        let last = i + 1 == count;
        put(buf, area, tx, y, if last { "└" } else { "├" }, dim);
        let name = b.app.config.name.as_str();
        link(
            buf,
            area,
            tx + 1,
            y,
            link_len,
            b.rps,
            ratio(b.eps, b.rps),
            b.life.idle_link(),
            anim,
        );
        if b.life == Life::Waking {
            // The request that woke it, on its way down the dotted line.
            let wake_age = view
                .deploys
                .get(name)
                .map(|d| now.duration_since(d.started).as_secs_f64())
                .unwrap_or(0.0);
            let p = ((wake_age / 0.8).min(1.0) * (link_len - 1) as f64) as u16;
            if wake_age < 0.8 {
                anim.moving();
                put(
                    buf,
                    area,
                    tx + 1 + p,
                    y,
                    "o",
                    Style::default().fg(theme::ACCENT).bold(),
                );
            }
        }
        let arrow = if b.life.idle_link() && b.life != Life::Waking {
            " "
        } else {
            "▶"
        };
        put(buf, area, l1, y, arrow, Style::default().fg(theme::ACCENT));
        let (glyph, color) = b.life.glyph(anim);
        put(buf, area, l1 + 2, y, &glyph, Style::default().fg(color));
        let name_style = if matches!(b.life, Life::Asleep | Life::Stopped) {
            muted
        } else {
            Style::default().fg(theme::FG)
        };
        put(buf, area, l1 + 4, y, &theme::fit(name, name_w), name_style);
        match b.life {
            Life::Maintenance => {
                let text = match &b.closed_until {
                    Some(u) => format!("maintenance → {u}"),
                    None => "maintenance".to_string(),
                };
                put(
                    buf,
                    area,
                    rate_x,
                    y,
                    &text,
                    Style::default().fg(theme::WARN),
                );
            }
            Life::Asleep => {
                let z = anim.snore();
                put(buf, area, rate_x, y, z, Style::default().fg(theme::MAGENTA));
            }
            Life::Waking => {
                put(
                    buf,
                    area,
                    rate_x,
                    y,
                    "waking",
                    Style::default().fg(theme::WARN),
                );
            }
            Life::Failed | Life::Unhealthy | Life::Stopped => {
                put(
                    buf,
                    area,
                    rate_x,
                    y,
                    b.life.word(),
                    Style::default().fg(color),
                );
            }
            _ => {
                let r = anim.tween(&format!("flow.{name}"), b.rps);
                let style = if b.eps > 0.0 {
                    Style::default().fg(theme::DANGER)
                } else {
                    Style::default().fg(theme::FG)
                };
                if b.eps > 0.0 {
                    put(
                        buf,
                        area,
                        rate_x.saturating_sub(2),
                        y,
                        "▲",
                        Style::default().fg(theme::DANGER).bold(),
                    );
                }
                put(
                    buf,
                    area,
                    rate_x,
                    y,
                    &format!("{:>5}/s", fmt_rate(r)),
                    style,
                );
            }
        }
        y += 1;
        if let Some(d) = b.deploy {
            put(buf, area, tx, y, if last { " " } else { "│" }, dim);
            let sx = tx + 3;
            match d.finished {
                Some((at, ok)) => {
                    let took = at.duration_since(d.started).as_secs_f64();
                    let (text, color) = if ok {
                        let what = if d.wake {
                            "awake".to_string()
                        } else {
                            format!("live on {}", d.slot)
                        };
                        (format!("✓ {what} in {took:.1} s"), theme::SUCCESS)
                    } else {
                        (
                            format!(
                                "✕ deploy failed: {}",
                                d.detail.as_deref().unwrap_or("see the app's log")
                            ),
                            theme::DANGER,
                        )
                    };
                    put(buf, area, sx, y, &text, Style::default().fg(color));
                }
                None => {
                    let lead = if d.wake {
                        "waking ".to_string()
                    } else {
                        format!("→ {} ", d.slot)
                    };
                    let w = put(buf, area, sx, y, &lead, Style::default().fg(theme::WARN));
                    stepper(buf, area, sx + w, y, d, anim, false);
                }
            }
            y += 1;
        }
    }

    if branches.is_empty() && !view.apps.is_empty() {
        put(buf, area, tx, y, "╵", dim);
        put(
            buf,
            area,
            tx + 3,
            y,
            "no request in the last minute",
            Style::default().fg(theme::FG),
        );
        y += 1;
    }

    // Summary of what is not drawn.
    let mut parts = Vec::new();
    if hidden > 0 {
        parts.push(format!("+{hidden} more active"));
    }
    if quiet > 0 {
        parts.push(format!("{quiet} without traffic"));
    }
    if asleep > 0 {
        parts.push(format!("{asleep} asleep"));
    }
    if branches.is_empty() && view.apps.is_empty() {
        parts.push("no apps in sites/".into());
    }
    if !parts.is_empty() {
        put(
            buf,
            area,
            tx + 1,
            y.min(max_y),
            &format!(" · {}", parts.join(" · ")),
            muted,
        );
    }
}

fn render_side(f: &mut Frame, area: Rect, view: &DashboardView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let chip = Style::default().fg(theme::INK).bg(theme::ACCENT).bold();
    let muted = Style::default().fg(theme::MUTED);
    put(buf, area, 1, 0, " http ", chip);
    match view.remote_snap {
        Some(snap) => {
            let codes = [
                ("2xx", snap.status_2xx, theme::SUCCESS),
                ("3xx", snap.status_3xx, theme::CYAN),
                ("4xx", snap.status_4xx, theme::WARN),
                ("5xx", snap.status_5xx, theme::DANGER),
            ];
            let total: u64 = codes.iter().map(|c| c.1).sum();
            let bar_w = area.width.saturating_sub(13) as f64;
            for (i, (label, n, color)) in codes.iter().enumerate() {
                let y = 2 + i as u16;
                put(buf, area, 1, y, label, Style::default().fg(*color).bold());
                let shown = anim.tween(&format!("http.{label}"), *n as f64);
                put(
                    buf,
                    area,
                    5,
                    y,
                    &format!("{:>6}", theme::fmt_num(shown.round() as u64)),
                    Style::default().fg(theme::FG),
                );
                if total > 0 && *n > 0 {
                    let w = ((*n as f64 / total as f64) * bar_w).round().max(1.0) as usize;
                    put(
                        buf,
                        area,
                        12,
                        y,
                        &"█".repeat(w),
                        Style::default().fg(*color),
                    );
                }
            }
        }
        None => {
            put(buf, area, 1, 2, "no traffic numbers", muted);
        }
    }

    let top = render_memory(buf, area, 7, &view.memory, anim);

    put(buf, area, 1, top, " events ", chip);
    let now = anim.now();
    let first = top + 2;
    let rows = area.height.saturating_sub(first) / 2;
    if view.journal.is_empty() {
        put(buf, area, 1, first, "nothing yet", muted);
        if !view.stream_connected {
            put(buf, area, 1, first + 1, "event stream offline", muted);
        }
        return;
    }
    for (i, e) in view.journal.iter().rev().take(rows as usize).enumerate() {
        let y = first + (i as u16) * 2;
        let fresh = anim.fade(now.duration_since(e.at));
        let (bg, fg_override) = match fresh {
            Some(0) => (Some(theme::FRESH_BG), Some(theme::WARN)),
            Some(_) => (Some(theme::FADING_BG), Some(theme::FADING_FG)),
            None => (None, None),
        };
        if let Some(bg) = bg {
            theme::shade(buf, area, 0, y, area.width, bg);
            theme::shade(buf, area, 0, y + 1, area.width, bg);
        }
        let color = fg_override.unwrap_or(kind_color(e.kind));
        let base = |c| match bg {
            Some(bg) => Style::default().fg(c).bg(bg),
            None => Style::default().fg(c),
        };
        put(
            buf,
            area,
            1,
            y,
            &e.clock,
            base(fg_override.unwrap_or(theme::MUTED)),
        );
        put(
            buf,
            area,
            10,
            y,
            &theme::fit(&e.app, area.width.saturating_sub(11) as usize),
            base(fg_override.unwrap_or(theme::FG)),
        );
        put(
            buf,
            area,
            3,
            y + 1,
            &theme::fit(&e.text, area.width.saturating_sub(4) as usize),
            base(color),
        );
    }
}

/// The memory panel of the right-hand column, from row `y`: a bar of the
/// host's memory — the apps, the rest of what is used, what is available —
/// then the figures. Returns the row after it.
fn render_memory(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    y: u16,
    mem: &MemoryView,
    anim: &mut Anim,
) -> u16 {
    let chip = Style::default().fg(theme::INK).bg(theme::ACCENT).bold();
    let muted = Style::default().fg(theme::MUTED);
    put(buf, area, 1, y, " memory ", chip);
    let apps = mem
        .apps
        .map(|(b, n)| (anim.tween("mem.apps", b as f64) as u64, n));
    let label = |t: &str| format!("{t:<6}");
    let Some(sys) = mem.system else {
        match apps {
            Some((b, n)) => {
                let x = 1 + put(buf, area, 1, y + 2, &label("apps"), muted);
                let x = x + put(
                    buf,
                    area,
                    x,
                    y + 2,
                    &theme::fmt_bytes(b),
                    Style::default().fg(theme::MAGENTA).bold(),
                );
                put(buf, area, x, y + 2, &format!(" · {n}"), muted);
            }
            None => {
                put(buf, area, 1, y + 2, "no app process to read", muted);
            }
        }
        return y + 4;
    };
    let total = sys.total_bytes.max(1);
    let used = sys.total_bytes.saturating_sub(sys.available_bytes);
    let apps_b = apps.map_or(0, |(b, _)| b).min(used);
    let w = area.width.saturating_sub(2) as usize;
    let cells = |b: u64| ((b as f64 / total as f64) * w as f64).round() as usize;
    let a = cells(apps_b).min(w);
    let u = cells(used).clamp(a, w);
    let bar_y = y + 2;
    put(
        buf,
        area,
        1,
        bar_y,
        &"█".repeat(a),
        Style::default().fg(theme::MAGENTA),
    );
    put(
        buf,
        area,
        1 + a as u16,
        bar_y,
        &"▓".repeat(u - a),
        Style::default().fg(theme::MUTED),
    );
    put(
        buf,
        area,
        1 + u as u16,
        bar_y,
        &"·".repeat(w - u),
        Style::default().fg(theme::ACCENT_DIM),
    );

    if let Some((b, n)) = apps {
        let x = 1 + put(buf, area, 1, y + 3, &label("apps"), muted);
        let x = x + put(
            buf,
            area,
            x,
            y + 3,
            &theme::fmt_bytes(b),
            Style::default().fg(theme::MAGENTA).bold(),
        );
        put(buf, area, x, y + 3, &format!(" · {n} apps"), muted);
    }
    let x = 1 + put(buf, area, 1, y + 4, &label("used"), muted);
    let x = x + put(
        buf,
        area,
        x,
        y + 4,
        &theme::fmt_bytes(used),
        Style::default().fg(theme::FG),
    );
    put(
        buf,
        area,
        x,
        y + 4,
        &format!(" / {}", theme::fmt_bytes(sys.total_bytes)),
        muted,
    );
    let x = 1 + put(buf, area, 1, y + 5, &label("free"), muted);
    let pct = sys.available_bytes as f64 / total as f64 * 100.0;
    let x = x + put(
        buf,
        area,
        x,
        y + 5,
        &theme::fmt_bytes(sys.available_bytes),
        Style::default().fg(available_color(sys)).bold(),
    );
    put(buf, area, x, y + 5, &format!(" · {pct:.0} %"), muted);
    y + 7
}

/// Memory on one line, for narrow terminals: a short bar, then what the apps
/// hold, what is used of the total and what is free.
fn render_memory_line(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    mem: &MemoryView,
    anim: &mut Anim,
) {
    let muted = Style::default().fg(theme::MUTED);
    let mut x = put(
        buf,
        area,
        0,
        0,
        " memory ",
        Style::default().fg(theme::INK).bg(theme::ACCENT).bold(),
    ) + 2;
    let apps = mem
        .apps
        .map(|(b, _)| anim.tween("mem.apps", b as f64) as u64);
    if let Some(sys) = mem.system {
        let total = sys.total_bytes.max(1);
        let used = sys.total_bytes.saturating_sub(sys.available_bytes);
        const W: usize = 12;
        let cells = |b: u64| ((b as f64 / total as f64) * W as f64).round() as usize;
        let a = cells(apps.unwrap_or(0).min(used)).min(W);
        let u = cells(used).clamp(a, W);
        x += put(
            buf,
            area,
            x,
            0,
            &"█".repeat(a),
            Style::default().fg(theme::MAGENTA),
        );
        x += put(buf, area, x, 0, &"▓".repeat(u - a), muted);
        x += put(
            buf,
            area,
            x,
            0,
            &"·".repeat(W - u),
            Style::default().fg(theme::ACCENT_DIM),
        );
        x += 2;
    }
    if let Some(b) = apps {
        x += put(
            buf,
            area,
            x,
            0,
            &theme::fmt_bytes(b),
            Style::default().fg(theme::MAGENTA).bold(),
        );
        x += put(buf, area, x, 0, " apps   ", muted);
    }
    if let Some(sys) = mem.system {
        let used = sys.total_bytes.saturating_sub(sys.available_bytes);
        x += put(
            buf,
            area,
            x,
            0,
            &theme::fmt_bytes(used),
            Style::default().fg(theme::FG),
        );
        x += put(
            buf,
            area,
            x,
            0,
            &format!("/{} used   ", theme::fmt_bytes(sys.total_bytes)),
            muted,
        );
        x += put(
            buf,
            area,
            x,
            0,
            &theme::fmt_bytes(sys.available_bytes),
            Style::default().fg(available_color(sys)).bold(),
        );
        put(buf, area, x, 0, " free", muted);
    }
}

/// Green while a fifth of the memory is available, amber under it, red
/// under a tenth.
fn available_color(sys: crate::metrics::SystemMemory) -> ratatui::style::Color {
    let share = sys.available_bytes as f64 / sys.total_bytes.max(1) as f64;
    if share < 0.10 {
        theme::DANGER
    } else if share < 0.20 {
        theme::WARN
    } else {
        theme::SUCCESS
    }
}

fn ratio(eps: f64, rps: f64) -> f64 {
    if rps > 0.0 {
        (eps / rps).min(1.0)
    } else if eps > 0.0 {
        1.0
    } else {
        0.0
    }
}

fn fmt_rate(r: f64) -> String {
    if r >= 100.0 {
        format!("{:.0}", r)
    } else {
        format!("{:.1}", r)
    }
}
