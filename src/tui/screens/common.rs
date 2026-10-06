//! What the dashboard and the apps screen both draw: an app's state as one
//! glyph, and a link carrying packets.

use ratatui::{buffer::Buffer, layout::Rect, style::Style};

use crate::app::{AppInfo, AppInstance, InstanceStatus};
use crate::tui::anim::{is_error_packet, Anim};
use crate::tui::app::AppStats;
use crate::tui::events::DeployProgress;
use crate::tui::theme;

/// An app's situation, most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Life {
    /// Closed for maintenance: visitors get the maintenance page.
    Maintenance,
    Failed,
    Unhealthy,
    /// A request is starting it from sleep.
    Waking,
    /// A deploy is under way; the old slot may still serve.
    Deploying,
    Starting,
    /// Running and answering some requests with 5xx.
    Erroring,
    Running,
    Asleep,
    Stopped,
}

pub fn live_instance(app: &AppInfo) -> &AppInstance {
    if app.current_slot == "blue" {
        &app.blue
    } else {
        &app.green
    }
}

pub fn life(
    app: &AppInfo,
    stats: Option<&AppStats>,
    deploy: Option<&DeployProgress>,
    waking: bool,
    closed: bool,
) -> Life {
    let inst = live_instance(app);
    if closed {
        return Life::Maintenance;
    }
    if waking {
        return Life::Waking;
    }
    if deploy.is_some_and(|d| d.finished.is_none()) {
        return if d_wake(deploy) {
            Life::Waking
        } else {
            Life::Deploying
        };
    }
    match inst.status {
        InstanceStatus::Failed => Life::Failed,
        InstanceStatus::Unhealthy => Life::Unhealthy,
        InstanceStatus::Starting => Life::Starting,
        InstanceStatus::Stopped if stats.is_some_and(|s| s.asleep) => Life::Asleep,
        InstanceStatus::Stopped => Life::Stopped,
        InstanceStatus::Running if stats.is_some_and(|s| s.eps > 0.0) => Life::Erroring,
        InstanceStatus::Running => Life::Running,
    }
}

fn d_wake(deploy: Option<&DeployProgress>) -> bool {
    deploy.is_some_and(|d| d.wake)
}

impl Life {
    /// The glyph and its colour; spinners and the like ask `anim` to keep
    /// the frame moving.
    pub fn glyph(self, anim: &mut Anim) -> (String, ratatui::style::Color) {
        match self {
            Life::Maintenance => ("◆".into(), theme::WARN),
            Life::Failed => ("✕".into(), theme::DANGER),
            Life::Unhealthy => ("●".into(), theme::DANGER),
            Life::Waking | Life::Deploying | Life::Starting => {
                (anim.spinner().to_string(), theme::WARN)
            }
            Life::Erroring => ("●".into(), theme::WARN),
            Life::Running => ("●".into(), theme::SUCCESS),
            Life::Asleep => ("◐".into(), theme::MAGENTA),
            Life::Stopped => ("○".into(), theme::MUTED),
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Life::Maintenance => "maintenance",
            Life::Failed => "failed",
            Life::Unhealthy => "unhealthy",
            Life::Waking => "waking",
            Life::Deploying => "deploying",
            Life::Starting => "starting",
            Life::Erroring => "5xx",
            Life::Running => "running",
            Life::Asleep => "asleep",
            Life::Stopped => "stopped",
        }
    }

    /// No traffic can reach it: drawn as a dotted, still link.
    pub fn idle_link(self) -> bool {
        matches!(
            self,
            Life::Asleep | Life::Stopped | Life::Failed | Life::Waking | Life::Maintenance
        )
    }
}

/// A link of `len` cells from (`x`, `y`): a line with packets for `rate`
/// requests a second, every k-th one red for a share `err` of failures, or
/// a still dotted line when `dotted`.
#[allow(clippy::too_many_arguments)]
pub fn link(
    buf: &mut Buffer,
    area: Rect,
    x: u16,
    y: u16,
    len: u16,
    rate: f64,
    err: f64,
    dotted: bool,
    anim: &mut Anim,
) {
    if dotted {
        let s: String = (0..len)
            .map(|i| if i % 2 == 0 { '·' } else { ' ' })
            .collect();
        theme::put(buf, area, x, y, &s, Style::default().fg(theme::MUTED));
        return;
    }
    theme::put(
        buf,
        area,
        x,
        y,
        &"─".repeat(len as usize),
        Style::default().fg(theme::ACCENT_DIM),
    );
    for (i, p) in anim.packets(len as usize, rate).into_iter().enumerate() {
        let (ch, color) = if is_error_packet(i, err) {
            ("x", theme::DANGER)
        } else {
            ("o", theme::ACCENT)
        };
        theme::put(
            buf,
            area,
            x + p as u16,
            y,
            ch,
            Style::default().fg(color).bold(),
        );
    }
}

/// The deploy stepper, `✓start › ✓health › ⠋switch › drain`, from (`x`,
/// `y`). Returns the columns used.
pub fn stepper(
    buf: &mut Buffer,
    area: Rect,
    x: u16,
    y: u16,
    deploy: &DeployProgress,
    anim: &mut Anim,
    spaced: bool,
) -> u16 {
    use crate::tui::events::Stage;
    let mut cx = x;
    let sep = if spaced { "  ›  " } else { " › " };
    for (i, stage) in Stage::ALL.iter().enumerate() {
        let current = deploy.finished.is_none() && deploy.stage == *stage;
        let done = deploy.passed(*stage);
        let gap = if spaced { " " } else { "" };
        let label = if current {
            let mut l = format!("{}{gap}{}", anim.spinner(), stage.label());
            if *stage == Stage::Drain {
                if let Some(secs) = deploy.drain_secs {
                    let left = secs
                        .saturating_sub(anim.now().duration_since(deploy.stage_since).as_secs());
                    l.push_str(&format!(" {left}s"));
                }
            }
            l
        } else if done {
            format!("✓{gap}{}", stage.label())
        } else {
            format!(" {gap}{}", stage.label())
        };
        let style = if current {
            Style::default().fg(theme::INK).bg(theme::WARN).bold()
        } else if done {
            Style::default().fg(theme::SUCCESS)
        } else {
            Style::default().fg(theme::MUTED)
        };
        cx += theme::put(buf, area, cx, y, &label, style);
        if i + 1 < Stage::ALL.len() {
            cx += theme::put(buf, area, cx, y, sep, Style::default().fg(theme::MUTED));
        }
    }
    cx - x
}
