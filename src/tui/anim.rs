//! Motion for the TUI: packets travelling along links, spinners, numbers that
//! glide to their next value instead of jumping, rows that light up when they
//! arrive and fade.
//!
//! Everything is a function of wall-clock time, not of a frame counter, so a
//! dropped frame changes nothing but smoothness. Rendering marks the frame as
//! *animated* whenever it draws something that moves; the event loop then
//! repaints at [`FRAME_INTERVAL`] while that is true and not at all otherwise,
//! so an idle screen costs no CPU. With motion off (`m`, or `NO_MOTION=1`)
//! time stands still at zero and values land at once: every frame is the same
//! complete, readable still.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Repaint interval while something moves: ~15 frames a second.
pub const FRAME_INTERVAL: Duration = Duration::from_millis(66);

/// How long a number takes to glide to a new value.
const TWEEN: Duration = Duration::from_millis(450);

/// Braille spinner, ten frames a second.
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

#[derive(Clone, Copy)]
struct Tween {
    from: f64,
    to: f64,
    since: Instant,
}

pub struct Anim {
    enabled: bool,
    start: Instant,
    now: Instant,
    tweens: HashMap<String, Tween>,
    /// Something moving was drawn in the current frame.
    animated: bool,
}

impl Anim {
    pub fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            start: now,
            now,
            tweens: HashMap::new(),
            animated: false,
        }
    }

    /// Motion is on unless `NO_MOTION` is set (to anything but `0` or empty).
    pub fn from_env() -> Self {
        let off = std::env::var("NO_MOTION").is_ok_and(|v| !v.is_empty() && v != "0");
        Self::new(!off)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Start a frame at `now`.
    pub fn begin(&mut self, now: Instant) {
        self.now = now;
        self.animated = false;
    }

    /// Whether the last frame drew something that moves: the loop should
    /// repaint again after [`FRAME_INTERVAL`].
    pub fn wants_frame(&self) -> bool {
        self.enabled && self.animated
    }

    /// Mark the frame as animated (something drawn depends on time).
    pub fn moving(&mut self) {
        self.animated = true;
    }

    /// Seconds since the TUI started, the clock every motion reads; frozen at
    /// zero with motion off.
    pub fn t(&self) -> f64 {
        if self.enabled {
            self.now.duration_since(self.start).as_secs_f64()
        } else {
            0.0
        }
    }

    pub fn now(&self) -> Instant {
        self.now
    }

    /// The displayed value for `key`, gliding toward `target`.
    pub fn tween(&mut self, key: &str, target: f64) -> f64 {
        let now = self.now;
        if !self.enabled {
            self.tweens.insert(
                key.to_string(),
                Tween {
                    from: target,
                    to: target,
                    since: now,
                },
            );
            return target;
        }
        let tw = self.tweens.entry(key.to_string()).or_insert(Tween {
            from: target,
            to: target,
            since: now,
        });
        if tw.to != target {
            let current = value_at(*tw, now);
            *tw = Tween {
                from: current,
                to: target,
                since: now,
            };
        }
        let v = value_at(*tw, now);
        if now.duration_since(tw.since) < TWEEN && tw.from != tw.to {
            self.animated = true;
        }
        v
    }

    pub fn spinner(&mut self) -> char {
        self.moving();
        spinner_at(self.t())
    }

    /// `z  `, `zZ `, `zZz`, over and over: a sleeping app.
    pub fn snore(&mut self) -> &'static str {
        self.moving();
        snore_at(self.t())
    }

    /// How fresh something that appeared `age` ago still looks: `Some(0)`
    /// for the first second, `Some(1)` until three, then `None`.
    pub fn fade(&mut self, age: Duration) -> Option<u8> {
        if !self.enabled {
            return None;
        }
        let level = fade_level(age);
        if level.is_some() {
            self.animated = true;
        }
        level
    }

    /// Packets on a link of `len` cells carrying `rate` requests a second.
    pub fn packets(&mut self, len: usize, rate: f64) -> Vec<usize> {
        if rate > 0.0 {
            self.moving();
        }
        packet_positions(len, rate, self.t())
    }
}

fn value_at(tw: Tween, now: Instant) -> f64 {
    let x = (now.duration_since(tw.since).as_secs_f64() / TWEEN.as_secs_f64()).min(1.0);
    let eased = 1.0 - (1.0 - x).powi(3);
    tw.from + (tw.to - tw.from) * eased
}

pub fn spinner_at(t: f64) -> char {
    SPINNER[((t * 10.0) as usize) % SPINNER.len()]
}

pub fn snore_at(t: f64) -> &'static str {
    ["z  ", "zZ ", "zZz"][((t * 1.6) as usize) % 3]
}

pub fn fade_level(age: Duration) -> Option<u8> {
    if age < Duration::from_secs(1) {
        Some(0)
    } else if age < Duration::from_secs(3) {
        Some(1)
    } else {
        None
    }
}

/// Where the packets are on a link of `len` cells at time `t`. More traffic
/// means more packets (logarithmically, so one busy app does not paint its
/// whole line) moving faster; no traffic means none. Positions are spread
/// evenly and wrap, so the line looks continuous.
pub fn packet_positions(len: usize, rate: f64, t: f64) -> Vec<usize> {
    if len == 0 || rate <= 0.0 {
        return Vec::new();
    }
    let max = (len / 3).max(1);
    let n = ((1.0 + (1.0 + rate).log2() * 1.4).round() as usize).clamp(1, max);
    let speed = 9.0 + (rate * 0.6).min(14.0);
    (0..n)
        .map(|i| {
            let p = t * speed + (i * len) as f64 / n as f64;
            (p.rem_euclid(len as f64)) as usize % len
        })
        .collect()
}

/// Which of `n` packets are drawn as errors when a share `ratio` of the
/// traffic fails: every k-th one, k = 1/ratio.
pub fn is_error_packet(i: usize, ratio: f64) -> bool {
    if ratio <= 0.0 {
        return false;
    }
    let every = (1.0 / ratio.min(1.0)).round().max(1.0) as usize;
    i.is_multiple_of(every)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_traffic_no_packets() {
        assert!(packet_positions(20, 0.0, 3.0).is_empty());
        assert!(packet_positions(0, 50.0, 3.0).is_empty());
    }

    #[test]
    fn packets_stay_on_the_link_and_grow_with_traffic() {
        for t in [0.0, 0.33, 7.9, 1234.5] {
            for rate in [0.1, 1.0, 10.0, 500.0] {
                let p = packet_positions(20, rate, t);
                assert!(!p.is_empty());
                assert!(p.iter().all(|&x| x < 20), "{p:?}");
                assert!(p.len() <= 20 / 3);
            }
        }
        assert!(packet_positions(30, 0.2, 0.0).len() < packet_positions(30, 80.0, 0.0).len());
    }

    #[test]
    fn packets_move() {
        assert_ne!(
            packet_positions(20, 5.0, 0.0),
            packet_positions(20, 5.0, 0.25)
        );
    }

    #[test]
    fn error_packets_follow_the_failure_ratio() {
        assert!(!is_error_packet(0, 0.0));
        assert!((0..4).all(|i| is_error_packet(i, 1.0)));
        let red = (0..12).filter(|&i| is_error_packet(i, 0.25)).count();
        assert_eq!(red, 3);
    }

    #[test]
    fn fades_out_after_three_seconds() {
        assert_eq!(fade_level(Duration::from_millis(200)), Some(0));
        assert_eq!(fade_level(Duration::from_millis(1500)), Some(1));
        assert_eq!(fade_level(Duration::from_secs(4)), None);
    }

    #[test]
    fn tweens_glide_then_land_and_land_at_once_without_motion() {
        let mut a = Anim::new(true);
        let t0 = Instant::now();
        a.begin(t0);
        assert_eq!(a.tween("x", 10.0), 10.0);
        a.begin(t0 + Duration::from_millis(10));
        let mid = a.tween("x", 20.0);
        assert!((10.0..20.0).contains(&mid) || mid == 10.0);
        a.begin(t0 + Duration::from_millis(200));
        let later = a.tween("x", 20.0);
        assert!(later > 10.0 && later < 20.0, "{later}");
        assert!(a.wants_frame());
        a.begin(t0 + Duration::from_secs(2));
        assert_eq!(a.tween("x", 20.0), 20.0);
        assert!(
            !a.wants_frame(),
            "a settled value does not keep the loop busy"
        );

        let mut still = Anim::new(false);
        still.begin(t0);
        still.tween("x", 1.0);
        assert_eq!(still.tween("x", 5.0), 5.0);
        assert_eq!(still.t(), 0.0);
        let _ = still.spinner();
        assert!(!still.wants_frame());
    }
}
