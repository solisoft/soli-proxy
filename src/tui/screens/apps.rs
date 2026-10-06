//! The apps screen: every app, sorted (by traffic unless `s` says otherwise),
//! with its state as an animated glyph, a minute of traffic as a sparkline,
//! and below the list the selected app's two slots — packets flowing to the
//! one that serves, a stepper while it deploys, CPU and memory gliding.

use std::collections::HashMap;

use ratatui::{layout::Rect, style::Style, Frame};

use crate::app::{AppInfo, AppInstance, InstanceStatus};
use crate::tui::anim::Anim;
use crate::tui::app::{AppHistory, AppStats};
use crate::tui::events::{DeployProgress, Stage};
use crate::tui::screens::common::{life, link, live_instance, stepper, Life};
use crate::tui::theme::{self, put};

/// How the list is ordered; `s` cycles through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppSort {
    #[default]
    Traffic,
    Name,
    Memory,
    Errors,
}

impl AppSort {
    pub fn next(self) -> Self {
        match self {
            AppSort::Traffic => AppSort::Name,
            AppSort::Name => AppSort::Memory,
            AppSort::Memory => AppSort::Errors,
            AppSort::Errors => AppSort::Traffic,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            AppSort::Traffic => "traffic",
            AppSort::Name => "name",
            AppSort::Memory => "memory",
            AppSort::Errors => "errors",
        }
    }
}

/// Order `apps` for the list. `rank` is smoothed traffic, so the traffic
/// order does not reshuffle with every second's jitter.
pub fn sort_apps(
    apps: &mut [AppInfo],
    sort: AppSort,
    stats: &HashMap<String, AppStats>,
    rank: &HashMap<String, f64>,
) {
    let num = |m: &HashMap<String, f64>, a: &AppInfo| m.get(&a.config.name).copied().unwrap_or(0.0);
    let mem = |a: &AppInfo| {
        stats
            .get(&a.config.name)
            .and_then(|s| s.memory_bytes)
            .unwrap_or(0)
    };
    let errs = |a: &AppInfo| {
        stats
            .get(&a.config.name)
            .map_or((0.0, 0), |s| (s.eps, s.errors))
    };
    let by_name = |a: &AppInfo, b: &AppInfo| {
        a.config
            .name
            .to_lowercase()
            .cmp(&b.config.name.to_lowercase())
    };
    match sort {
        AppSort::Name => apps.sort_by(by_name),
        AppSort::Traffic => apps.sort_by(|a, b| {
            num(rank, b)
                .partial_cmp(&num(rank, a))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| by_name(a, b))
        }),
        AppSort::Memory => apps.sort_by(|a, b| mem(b).cmp(&mem(a)).then_with(|| by_name(a, b))),
        AppSort::Errors => apps.sort_by(|a, b| {
            let (ea, ta) = errs(a);
            let (eb, tb) = errs(b);
            eb.partial_cmp(&ea)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(tb.cmp(&ta))
                .then_with(|| by_name(a, b))
        }),
    }
}

pub struct AppsView<'a> {
    /// Already filtered by the search and sorted.
    pub apps: &'a [AppInfo],
    pub total: usize,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub search_query: &'a str,
    pub sort: AppSort,
    pub app_stats: &'a HashMap<String, AppStats>,
    pub app_history: &'a HashMap<String, AppHistory>,
    pub deploys: &'a HashMap<String, DeployProgress>,
    pub waking: &'a [String],
    /// Resident memory of all the apps together.
    pub memory_total: Option<u64>,
}

/// Rows the detail panel takes under the list.
pub const DETAIL_HEIGHT: u16 = 9;

pub fn render(f: &mut Frame, area: Rect, view: &AppsView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    let chip = Style::default().fg(theme::INK).bg(theme::ACCENT).bold();

    let mut x = put(buf, area, 0, 0, " apps ", chip) + 2;
    let mem = view
        .memory_total
        .map(|b| format!(" · {} in memory", theme::fmt_bytes(b)))
        .unwrap_or_default();
    let summary = if view.search_query.is_empty() {
        format!("sorted by {} · {}{mem}", view.sort.label(), view.total)
    } else {
        format!(
            "“{}” · {} of {} · sorted by {}",
            view.search_query,
            view.apps.len(),
            view.total,
            view.sort.label()
        )
    };
    x += put(buf, area, x, 0, &summary, muted) + 3;
    x += put(
        buf,
        area,
        x,
        0,
        "s",
        Style::default().fg(theme::ACCENT).bold(),
    );
    put(buf, area, x + 1, 0, "sort", muted);

    if view.apps.is_empty() {
        let msg = if view.total == 0 {
            "No apps discovered: apps are found in the sites/ directory."
        } else {
            "No app matches the search."
        };
        put(buf, area, 1, 2, msg, muted);
        return;
    }

    let has_detail = view.selected_index < view.apps.len() && area.height > DETAIL_HEIGHT + 5;
    let list_h = if has_detail {
        area.height - DETAIL_HEIGHT
    } else {
        area.height
    };
    let list = Rect::new(area.x, area.y, area.width, list_h);
    render_list(f, list, view, anim);
    if has_detail {
        let detail = Rect::new(area.x, area.y + list_h, area.width, DETAIL_HEIGHT);
        let app = &view.apps[view.selected_index];
        render_detail(f, detail, app, view, anim);
    }
}

struct Cols {
    name: u16,
    name_w: usize,
    spark: Option<u16>,
    rps: u16,
    mem: u16,
    soli: u16,
    up: u16,
    last: u16,
}

fn columns(width: u16) -> Cols {
    // glyph 2 | name | spark 12+2 | req/s 7+2 | memory 10 | soli 17 | up 6 | last 7
    let spark = width >= 76;
    let fixed: u16 = 2 + if spark { 14 } else { 0 } + 9 + 10 + 17 + 6 + 7;
    let name_w = width.saturating_sub(fixed + 1).clamp(14, 34);
    let mut x = 2 + name_w + 1;
    let spark_x = if spark {
        let s = x;
        x += 14;
        Some(s)
    } else {
        None
    };
    let rps = x;
    x += 9;
    let mem = x;
    x += 10;
    let soli = x;
    x += 17;
    Cols {
        name: 2,
        name_w: name_w as usize,
        spark: spark_x,
        rps,
        mem,
        soli,
        up: x,
        last: x + 7,
    }
}

fn render_list(f: &mut Frame, area: Rect, view: &AppsView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    let head = Style::default().fg(theme::MUTED).bold();
    let c = columns(area.width);
    put(buf, area, c.name, 1, "app", head);
    if let Some(sx) = c.spark {
        put(buf, area, sx, 1, "last minute", head);
    }
    put(buf, area, c.rps + 2, 1, "req/s", head);
    put(buf, area, c.mem, 1, "memory", head);
    put(buf, area, c.soli, 1, "soli", head);
    put(buf, area, c.up + 4, 1, "up", head);
    put(buf, area, c.last + 2, 1, "last", head);

    let rows = area.height.saturating_sub(2) as usize;
    for (i, app) in view
        .apps
        .iter()
        .enumerate()
        .skip(view.scroll_offset)
        .take(rows)
    {
        let y = 2 + (i - view.scroll_offset) as u16;
        let selected = i == view.selected_index;
        let bg = selected.then_some(theme::SELECT_BG);
        if let Some(bg) = bg {
            theme::shade(buf, area, 0, y, area.width, bg);
        }
        let st = |color| match bg {
            Some(bg) => Style::default().fg(color).bg(bg),
            None => Style::default().fg(color),
        };
        let name = app.config.name.as_str();
        let stats = view.app_stats.get(name);
        let deploy = view.deploys.get(name);
        let waking = view.waking.iter().any(|w| w == name);
        let l = life(app, stats, deploy, waking);
        let (glyph, gcolor) = l.glyph(anim);
        put(buf, area, 0, y, &glyph, st(gcolor));
        let quiet = matches!(l, Life::Asleep | Life::Stopped);
        put(
            buf,
            area,
            c.name,
            y,
            &theme::fit(name, c.name_w),
            if selected {
                st(theme::FG).bold()
            } else if quiet {
                st(theme::MUTED)
            } else {
                st(theme::FG)
            },
        );

        if let Some(sx) = c.spark {
            let hist: Vec<f64> = view
                .app_history
                .get(name)
                .map(|h| minute_buckets(&h.rps, 12))
                .unwrap_or_default();
            let any = hist.iter().any(|v| *v > 0.0);
            let text = if any {
                theme::bars(&hist)
            } else {
                "·".repeat(12)
            };
            put(
                buf,
                area,
                sx,
                y,
                &text,
                st(if any { theme::ACCENT } else { theme::MUTED }),
            );
        }

        match l {
            Life::Asleep => {
                put(
                    buf,
                    area,
                    c.rps,
                    y,
                    &format!("{:>7}", "—"),
                    st(theme::MUTED),
                );
                put(buf, area, c.mem, y, "asleep", st(theme::MAGENTA));
            }
            Life::Stopped | Life::Failed => {
                put(
                    buf,
                    area,
                    c.rps,
                    y,
                    &format!("{:>7}", "—"),
                    st(theme::MUTED),
                );
                put(buf, area, c.mem, y, l.word(), st(gcolor));
            }
            _ => {
                let rps = stats.map_or(0.0, |s| s.rps);
                let shown = anim.tween(&format!("apps.rps.{name}"), rps);
                let color = if stats.is_some_and(|s| s.eps > 0.0) {
                    theme::DANGER
                } else {
                    theme::FG
                };
                let color = if shown < 0.05 && color == theme::FG {
                    theme::MUTED
                } else {
                    color
                };
                put(
                    buf,
                    area,
                    c.rps,
                    y,
                    &format!("{:>7}", fmt_rate(shown)),
                    st(color),
                );
                let mem = stats.and_then(|s| s.memory_bytes);
                let text = match mem {
                    Some(b) => {
                        let v = anim.tween(&format!("apps.mem.{name}"), b as f64);
                        theme::fmt_bytes(v as u64)
                    }
                    None => "—".into(),
                };
                put(buf, area, c.mem, y, &text, st(theme::FG));
            }
        }

        let runtime = stats.map(|s| &s.runtime);
        if let Some(v) = runtime.and_then(|r| r.version.as_deref()) {
            let replaced = runtime.is_some_and(|r| r.replaced);
            let w = put(
                buf,
                area,
                c.soli,
                y,
                v,
                st(if replaced { theme::WARN } else { theme::FG }),
            );
            if replaced {
                put(buf, area, c.soli + w + 1, y, "↻ restart", st(theme::WARN));
            }
        } else {
            put(buf, area, c.soli, y, "—", st(theme::MUTED));
        }
        let up = runtime
            .and_then(|r| r.started_at)
            .and_then(|t| std::time::SystemTime::now().duration_since(t).ok())
            .map(|d| theme::fmt_age(d.as_secs()))
            .unwrap_or_else(|| "—".into());
        put(buf, area, c.up, y, &format!("{up:>6}"), st(theme::MUTED));
        // Time since the app's last request: what keeps it awake, or how
        // long it has gone without one.
        let (last, recent) = match stats.and_then(|s| s.last_request_ms).and_then(since) {
            Some(secs) => (theme::fmt_age(secs), secs < 60),
            None => ("—".to_string(), false),
        };
        put(
            buf,
            area,
            c.last,
            y,
            &format!("{last:>6}"),
            st(if recent { theme::SUCCESS } else { theme::MUTED }),
        );
    }
    if view.apps.len() > view.scroll_offset + rows {
        // On the title line, where it covers nothing.
        let more = format!("↓ {} more", view.apps.len() - view.scroll_offset - rows);
        let w = more.chars().count() as u16;
        put(buf, area, area.width.saturating_sub(w + 1), 0, &more, muted);
    }
}

fn render_detail(f: &mut Frame, area: Rect, app: &AppInfo, view: &AppsView, anim: &mut Anim) {
    let buf = f.buffer_mut();
    let muted = Style::default().fg(theme::MUTED);
    let name = app.config.name.as_str();
    let stats = view.app_stats.get(name);
    let deploy = view.deploys.get(name);
    let waking = view.waking.iter().any(|w| w == name);
    let l = life(app, stats, deploy, waking);

    put(
        buf,
        area,
        0,
        0,
        &"─".repeat(area.width as usize),
        Style::default().fg(theme::ACCENT_DIM),
    );
    let w = put(
        buf,
        area,
        0,
        1,
        &format!(" {name} "),
        Style::default().fg(theme::INK).bg(theme::ACCENT).bold(),
    );
    let (headline, color) = headline(app, l, deploy);
    let mut x = w + 2;
    x += put(
        buf,
        area,
        x,
        1,
        &headline,
        Style::default().fg(color).bold(),
    );
    if app.config.domain != app.config.name {
        put(buf, area, x + 3, 1, &app.config.domain, muted);
    }

    // Row 3: the stepper while deploying, else the essentials.
    match deploy {
        Some(d) => {
            stepper(buf, area, 1, 3, d, anim, true);
        }
        None => {
            let inst = live_instance(app);
            let mut parts = vec![format!("slot {}", app.current_slot)];
            if inst.port > 0 {
                parts.push(format!("port :{}", inst.port));
            }
            if let Some(pid) = inst.pid {
                parts.push(format!("pid {pid}"));
            }
            if let Some(s) = stats {
                parts.push(format!("{} requests", theme::fmt_num(s.requests)));
                if let Some(secs) = s.last_request_ms.and_then(since) {
                    parts.push(format!("last {} ago", theme::fmt_age(secs)));
                }
                if s.errors > 0 {
                    parts.push(format!("{} errors", theme::fmt_num(s.errors)));
                }
                if s.avg_response_time_ms > 0.0 {
                    parts.push(format!("{} avg", theme::fmt_ms(s.avg_response_time_ms)));
                }
            }
            put(buf, area, 1, 3, &parts.join(" · "), muted);
        }
    }

    // Rows 5-6: the two slots.
    let rps = stats.map_or(0.0, |s| s.rps);
    let eps = stats.map_or(0.0, |s| s.eps);
    put(buf, area, 1, 5, "proxy", Style::default().fg(theme::FG));
    put(
        buf,
        area,
        7,
        5,
        "─┬",
        Style::default().fg(theme::ACCENT_DIM),
    );
    put(buf, area, 8, 6, "└", Style::default().fg(theme::ACCENT_DIM));
    for (row, slot_name, inst) in [(5u16, "blue", &app.blue), (6u16, "green", &app.green)] {
        let serving =
            app.current_slot == slot_name && inst.pid.is_some() && !matches!(l, Life::Asleep);
        let (state, scolor) = slot_state(slot_name, inst, app, deploy, serving, anim);
        let alive = inst.pid.is_some() || state.contains("starting") || state.contains("health");
        link(
            buf,
            area,
            9,
            row,
            19,
            if serving { rps } else { 0.0 },
            ratio(eps, rps),
            !serving,
            anim,
        );
        put(
            buf,
            area,
            28,
            row,
            "▶",
            Style::default().fg(if alive { theme::ACCENT } else { theme::MUTED }),
        );
        let port = if inst.port > 0 {
            format!(":{}", inst.port)
        } else {
            "-".into()
        };
        put(
            buf,
            area,
            30,
            row,
            &format!("{slot_name:<5} {port:<6}"),
            Style::default().fg(if alive { theme::FG } else { theme::MUTED }),
        );
        put(buf, area, 44, row, &state, Style::default().fg(scolor));
    }

    // Resources on the right, when there is room.
    if area.width >= 96 {
        let rx = area.width - 30;
        let cpu = stats.and_then(|s| s.cpu_percent);
        let mem = stats.and_then(|s| s.memory_bytes);
        let both = app.blue.pid.is_some() && app.green.pid.is_some();
        let cpu_v = anim.tween(&format!("detail.cpu.{name}"), cpu.unwrap_or(0.0));
        let mem_v = anim.tween(&format!("detail.mem.{name}"), mem.unwrap_or(0) as f64);
        let mem_max = view
            .app_history
            .get(name)
            .and_then(|h| h.mem.iter().copied().max())
            .unwrap_or(0)
            .max(mem.unwrap_or(0))
            .max(64 * 1024 * 1024) as f64;
        meter(
            buf,
            area,
            rx,
            5,
            "cpu",
            cpu.map(|_| cpu_v / 100.0),
            &cpu.map(|_| format!("{:.0}%", cpu_v)).unwrap_or("—".into()),
            if cpu_v > 50.0 {
                theme::WARN
            } else {
                theme::ACCENT
            },
        );
        meter(
            buf,
            area,
            rx,
            6,
            "mem",
            mem.map(|_| mem_v / mem_max),
            &mem.map(|_| theme::fmt_bytes(mem_v as u64))
                .unwrap_or("—".into()),
            theme::ACCENT,
        );
        if both {
            put(buf, area, rx, 7, "2 slots in memory", muted);
        }
    }

    // Row 8: runtime.
    let runtime = stats.map(|s| &s.runtime);
    let mut parts = Vec::new();
    if let Some(v) = runtime.and_then(|r| r.version.as_deref()) {
        if runtime.is_some_and(|r| r.replaced) {
            parts.push(format!(
                "Soli {v}, binary replaced since: restart to run the new one"
            ));
        } else {
            parts.push(format!("Soli {v}"));
        }
    }
    if let Some(t) = runtime.and_then(|r| r.started_at) {
        parts.push(format!(
            "since {} ({})",
            crate::tui::runtime::fmt_started(t),
            crate::tui::runtime::fmt_uptime(t, std::time::SystemTime::now())
        ));
    }
    if !parts.is_empty() {
        let replaced = runtime.is_some_and(|r| r.replaced);
        put(
            buf,
            area,
            1,
            8,
            &parts.join(" · "),
            Style::default().fg(if replaced { theme::WARN } else { theme::MUTED }),
        );
    }
}

fn headline(
    app: &AppInfo,
    l: Life,
    deploy: Option<&DeployProgress>,
) -> (String, ratatui::style::Color) {
    if let Some(d) = deploy {
        return match d.finished {
            Some((at, true)) => {
                let took = at.duration_since(d.started).as_secs_f64();
                if d.wake {
                    (format!("awake in {took:.1} s"), theme::SUCCESS)
                } else {
                    (format!("live on {} in {took:.1} s", d.slot), theme::SUCCESS)
                }
            }
            Some((_, false)) => (
                format!(
                    "deploy failed: {}",
                    d.detail.as_deref().unwrap_or("see the logs")
                ),
                theme::DANGER,
            ),
            None if d.wake => ("waking up for a request".into(), theme::WARN),
            None => (format!("deploying → {}", d.slot), theme::WARN),
        };
    }
    match l {
        Life::Running => (
            format!("{} serves the traffic", app.current_slot),
            theme::SUCCESS,
        ),
        Life::Erroring => (
            format!("{} serves, with 5xx", app.current_slot),
            theme::WARN,
        ),
        Life::Asleep => ("asleep · the next request wakes it".into(), theme::MAGENTA),
        Life::Stopped => ("stopped".into(), theme::MUTED),
        Life::Failed => ("failed to start · see its log".into(), theme::DANGER),
        Life::Unhealthy => ("unhealthy".into(), theme::DANGER),
        Life::Starting => ("starting".into(), theme::WARN),
        Life::Waking => ("waking up for a request".into(), theme::WARN),
        Life::Deploying => ("deploying".into(), theme::WARN),
    }
}

fn slot_state(
    slot: &str,
    inst: &AppInstance,
    app: &AppInfo,
    deploy: Option<&DeployProgress>,
    serving: bool,
    anim: &mut Anim,
) -> (String, ratatui::style::Color) {
    if let Some(d) = deploy.filter(|d| d.finished.is_none()) {
        if d.slot == slot {
            return match d.stage {
                Stage::Start => (format!("{} starting…", anim.spinner()), theme::WARN),
                Stage::Health => (format!("{} health check…", anim.spinner()), theme::WARN),
                Stage::Switch | Stage::Drain if serving => {
                    ("● serves the traffic".into(), theme::SUCCESS)
                }
                Stage::Switch | Stage::Drain => ("● ready".into(), theme::SUCCESS),
            };
        }
        if d.from == slot && d.stage == Stage::Drain {
            let left = d
                .drain_secs
                .map(|s| s.saturating_sub(anim.now().duration_since(d.stage_since).as_secs()));
            anim.moving();
            return match left {
                Some(n) if n > 0 => (format!("◌ draining {n}s"), theme::WARN),
                _ => ("◌ stopping".into(), theme::WARN),
            };
        }
    }
    if serving {
        return ("● serves the traffic".into(), theme::SUCCESS);
    }
    match inst.status {
        InstanceStatus::Failed => ("✕ failed".into(), theme::DANGER),
        InstanceStatus::Unhealthy => ("● unhealthy".into(), theme::DANGER),
        InstanceStatus::Starting => (format!("{} starting", anim.spinner()), theme::WARN),
        _ if inst.pid.is_some() => ("● running, not serving".into(), theme::MUTED),
        _ if app.current_slot == slot => ("○ stopped".into(), theme::MUTED),
        _ => ("○ free".into(), theme::MUTED),
    }
}

#[allow(clippy::too_many_arguments)]
fn meter(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    x: u16,
    y: u16,
    label: &str,
    fraction: Option<f64>,
    value: &str,
    color: ratatui::style::Color,
) {
    const W: usize = 16;
    put(buf, area, x, y, label, Style::default().fg(theme::MUTED));
    let filled = fraction.map_or(0, |f| (f.clamp(0.0, 1.0) * W as f64).round() as usize);
    put(
        buf,
        area,
        x + 4,
        y,
        &"█".repeat(filled),
        Style::default().fg(color),
    );
    put(
        buf,
        area,
        x + 4 + filled as u16,
        y,
        &"·".repeat(W - filled),
        Style::default().fg(theme::MUTED),
    );
    put(
        buf,
        area,
        x + 5 + W as u16,
        y,
        &format!("{value:>8}"),
        Style::default().fg(theme::FG),
    );
}

/// `n` buckets over the history (one sample a second), each the mean of its
/// slice, so a minute fits in a few cells.
pub fn minute_buckets(hist: &std::collections::VecDeque<f64>, n: usize) -> Vec<f64> {
    if hist.is_empty() || n == 0 {
        return Vec::new();
    }
    let per = hist.len().div_ceil(n).max(1);
    let v: Vec<f64> = hist.iter().copied().collect();
    let mut out: Vec<f64> = v
        .chunks(per)
        .map(|c| c.iter().sum::<f64>() / c.len() as f64)
        .collect();
    // Right-align: the newest bucket is the last cell.
    while out.len() < n {
        out.insert(0, 0.0);
    }
    out
}

/// Seconds from the Unix time `ms` to now; `None` for a time in the future.
fn since(ms: u64) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    now.checked_sub(ms).map(|d| d / 1000)
}

fn ratio(eps: f64, rps: f64) -> f64 {
    if rps > 0.0 {
        (eps / rps).min(1.0)
    } else {
        0.0
    }
}

fn fmt_rate(r: f64) -> String {
    if r <= 0.0 {
        "0".into()
    } else if r >= 100.0 {
        format!("{r:.0}")
    } else {
        format!("{r:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minute_fits_in_twelve_cells() {
        let hist: std::collections::VecDeque<f64> = (0..60).map(|i| i as f64).collect();
        let b = minute_buckets(&hist, 12);
        assert_eq!(b.len(), 12);
        assert_eq!(b[0], 2.0); // mean of 0..5
        assert_eq!(b[11], 57.0);
        let short: std::collections::VecDeque<f64> = [5.0, 5.0].into_iter().collect();
        let b = minute_buckets(&short, 12);
        assert_eq!(b.len(), 12);
        assert_eq!(b[11], 5.0);
        assert_eq!(b[0], 0.0);
    }

    #[test]
    fn columns_fit_an_80_column_terminal() {
        let c = columns(80);
        assert!(c.last + 6 <= 80, "last ends at {}", c.last + 6);
        assert_eq!(c.last, c.up + 7);
        assert!(c.name_w >= 14);
        assert!(columns(60).spark.is_none());
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::app::{AppConfig, AppInstance};
    use ratatui::{backend::TestBackend, Terminal};
    use std::time::{Duration, Instant};

    fn instance(slot: &str, port: u16, pid: Option<u32>, status: InstanceStatus) -> AppInstance {
        AppInstance {
            name: "shop.test".into(),
            slot: slot.into(),
            port,
            pid,
            status,
            last_started: None,
        }
    }

    fn app() -> AppInfo {
        AppInfo {
            config: AppConfig {
                name: "shop.test".into(),
                domain: "shop.test".into(),
                ..AppConfig::default()
            },
            path: "/tmp/shop.test".into(),
            blue: instance("blue", 31000, Some(4242), InstanceStatus::Running),
            green: instance("green", 31001, Some(4343), InstanceStatus::Running),
            current_slot: "blue".into(),
            quarantined: false,
            maintenance: false,
            error_pages: None,
        }
    }

    fn screen(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_deploy_shows_its_stepper_and_both_slots() {
        let apps = vec![app()];
        let mut stats = HashMap::new();
        stats.insert(
            "shop.test".to_string(),
            AppStats {
                rps: 12.0,
                requests: 900,
                ..AppStats::default()
            },
        );
        let now = Instant::now();
        let mut deploys = HashMap::new();
        deploys.insert(
            "shop.test".to_string(),
            DeployProgress {
                slot: "green".into(),
                from: "blue".into(),
                stage: Stage::Health,
                started: now - Duration::from_secs(2),
                stage_since: now - Duration::from_secs(1),
                drain_secs: None,
                finished: None,
                detail: None,
                wake: false,
            },
        );
        let history = HashMap::new();
        let view = AppsView {
            apps: &apps,
            total: 1,
            selected_index: 0,
            scroll_offset: 0,
            search_query: "",
            sort: AppSort::Traffic,
            app_stats: &stats,
            app_history: &history,
            deploys: &deploys,
            waking: &[],
            memory_total: None,
        };
        let mut anim = Anim::new(false);
        anim.begin(now);
        let mut term = Terminal::new(TestBackend::new(110, 24)).unwrap();
        term.draw(|f| render(f, f.area(), &view, &mut anim))
            .unwrap();
        let text = screen(&term);
        assert!(text.contains("sorted by traffic · 1"), "{text}");
        assert!(text.contains("deploying → green"), "{text}");
        assert!(text.contains("✓ start"), "{text}");
        assert!(text.contains("health check…"), "{text}");
        assert!(text.contains("blue  :31000"), "{text}");
        assert!(text.contains("● serves the traffic"), "{text}");
    }
}
