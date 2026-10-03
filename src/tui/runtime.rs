//! What an app's process runs, and since when: the Soli version of its
//! binary, and the moment the process started.
//!
//! Both are read from `/proc/<pid>`, which is why this only works where the
//! TUI runs beside the proxy (it already reads CPU and memory there). The
//! version is asked of the binary itself (`<exe> --version`) once per binary
//! file, not per tick: a dozen apps sharing one `soli` cost one exec.
//!
//! A process keeps running the binary it started with. When `soli` is
//! upgraded in place, the file it started from is deleted (the kernel shows
//! `/usr/local/bin/soli (deleted)`), and the app goes on running the old
//! version until it restarts — which is exactly what an operator wants to
//! see at a glance. `AppRuntime::replaced` says so.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The runtime of one app process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppRuntime {
    /// The Soli version of the binary the process runs (`"2.15.0"`), or
    /// `None` for a binary that is not `soli*` or does not say.
    pub version: Option<String>,
    /// The binary's path, without the kernel's ` (deleted)` suffix.
    pub binary: Option<String>,
    /// The binary was deleted or replaced after the process started: it
    /// still runs the old one.
    pub replaced: bool,
    /// When the process started.
    pub started_at: Option<SystemTime>,
}

/// Probes processes, remembering each binary's version by file identity.
#[derive(Default)]
pub struct RuntimeProbe {
    versions: HashMap<(u64, u64), Option<String>>,
}

impl RuntimeProbe {
    /// The runtime of process `pid`; empty fields where `/proc` says nothing.
    #[cfg(target_os = "linux")]
    pub fn probe(&mut self, pid: u32) -> AppRuntime {
        use std::os::unix::fs::MetadataExt;

        let exe = format!("/proc/{pid}/exe");
        let link = std::fs::read_link(&exe)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let (binary, replaced) = match link.as_deref() {
            Some(path) => match path.strip_suffix(" (deleted)") {
                Some(original) => (Some(original.to_string()), true),
                None => (Some(path.to_string()), false),
            },
            None => (None, false),
        };

        // Following /proc/<pid>/exe reaches the file the process runs, even
        // deleted, so the identity is that of the running binary.
        let version = match (std::fs::metadata(&exe), binary.as_deref()) {
            (Ok(meta), Some(path)) if is_soli_binary(path) => self
                .versions
                .entry((meta.dev(), meta.ino()))
                .or_insert_with(|| ask_version(&exe))
                .clone(),
            _ => None,
        };

        AppRuntime {
            version,
            binary,
            replaced,
            started_at: started_at(pid),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn probe(&mut self, _pid: u32) -> AppRuntime {
        AppRuntime::default()
    }
}

/// Only a `soli*` executable is asked for `--version` (never `soli-proxy`):
/// running an arbitrary program with an argument it may not expect is not
/// something a dashboard should do.
fn is_soli_binary(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.starts_with("soli") && !name.starts_with("soli-proxy")
}

/// `<exe> --version`, bounded: a binary that does not answer within two
/// seconds is killed and reported as unknown.
#[cfg(target_os = "linux")]
fn ask_version(exe: &str) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(exe)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    parse_version(&out)
}

/// `"Soli 2.15.0\n"` → `"2.15.0"`.
pub fn parse_version(output: &str) -> Option<String> {
    let line = output.lines().next()?.trim();
    let version = line.strip_prefix("Soli ")?.split_whitespace().next()?;
    version
        .chars()
        .next()
        .filter(char::is_ascii_digit)
        .map(|_| version.to_string())
}

/// When process `pid` started: the boot time plus its start, in clock ticks.
#[cfg(target_os = "linux")]
fn started_at(pid: u32) -> Option<SystemTime> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let ticks = parse_start_ticks(&stat)?;
    let boot = parse_boot_time(&std::fs::read_to_string("/proc/stat").ok()?)?;
    let hz = crate::metrics::clock_ticks_per_second();
    Some(UNIX_EPOCH + Duration::from_secs(boot) + Duration::from_secs_f64(ticks as f64 / hz))
}

/// Field 22 of `/proc/<pid>/stat`, `starttime`: clock ticks after boot.
/// Counted from the last `)`, since the command name may contain one.
pub fn parse_start_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 2..];
    // `after` starts at field 3, so field 22 is index 19.
    after.split_whitespace().nth(19)?.parse().ok()
}

/// The `btime` line of `/proc/stat`: the boot time, in seconds since the epoch.
pub fn parse_boot_time(proc_stat: &str) -> Option<u64> {
    proc_stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

/// How long ago `started` was, in at most two units: `45s`, `12m`, `3h05m`,
/// `4d02h`.
pub fn fmt_uptime(started: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(started).unwrap_or_default().as_secs();
    let (d, h, m) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    if d > 0 {
        format!("{d}d{h:02}h")
    } else if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

/// `started` as local `YYYY-MM-DD HH:MM:SS`.
pub fn fmt_started(started: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(started)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_from_soli_output() {
        assert_eq!(parse_version("Soli 2.15.0\n").as_deref(), Some("2.15.0"));
        assert_eq!(
            parse_version("Soli 2.14.1 (abc)\n").as_deref(),
            Some("2.14.1")
        );
        assert_eq!(parse_version("node v20\n"), None);
        assert_eq!(parse_version("Soli dev\n"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn only_a_soli_binary_is_asked() {
        assert!(is_soli_binary("/usr/local/bin/soli"));
        assert!(is_soli_binary("/usr/local/bin/soli.backup"));
        assert!(!is_soli_binary("/usr/local/bin/soli-proxy"));
        assert!(!is_soli_binary("/usr/bin/node"));
    }

    #[test]
    fn the_start_time_is_field_22_counted_after_the_command_name() {
        // A command name holding ") (" must not shift the fields.
        let stat = "1234 (so) (li) S 1 1234 1234 0 -1 4194560 2 0 0 0 5 3 0 0 20 0 9 0 \
                    987654 123456 789 18446744073709551615";
        assert_eq!(parse_start_ticks(stat), Some(987654));
    }

    #[test]
    fn the_boot_time_is_the_btime_line() {
        let proc_stat = "cpu  1 2 3\nintr 5\nctxt 9\nbtime 1790000000\nprocesses 42\n";
        assert_eq!(parse_boot_time(proc_stat), Some(1_790_000_000));
        assert_eq!(parse_boot_time("cpu 1\n"), None);
    }

    #[test]
    fn uptime_reads_in_two_units() {
        let start = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let at = |s: u64| start + Duration::from_secs(s);
        assert_eq!(fmt_uptime(start, at(45)), "45s");
        assert_eq!(fmt_uptime(start, at(12 * 60 + 5)), "12m");
        assert_eq!(fmt_uptime(start, at(3 * 3600 + 5 * 60)), "3h05m");
        assert_eq!(fmt_uptime(start, at(4 * 86_400 + 2 * 3600 + 7)), "4d02h");
        // A clock that went backwards reads as zero, not a panic.
        assert_eq!(fmt_uptime(at(10), start), "0s");
    }

    /// The case the column exists for: the binary a process started from is
    /// deleted (an upgrade installed a new file), and the process runs on.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_whose_binary_was_deleted_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("soli");
        std::fs::copy("/bin/sleep", &copy).unwrap();
        let mut child = std::process::Command::new(&copy).arg("30").spawn().unwrap();
        // `spawn` returns once the child is forked, not once it has exec'd:
        // until then /proc/<pid>/exe is still this test binary. Wait for the
        // copy to be what runs before deleting it.
        let exe = format!("/proc/{}/exe", child.id());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(&exe).ok().as_deref() != Some(copy.as_path()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never exec'd"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_file(&copy).unwrap();

        let runtime = RuntimeProbe::default().probe(child.id());
        let _ = child.kill();
        let _ = child.wait();

        assert!(runtime.replaced, "{runtime:?}");
        assert_eq!(runtime.binary.as_deref(), copy.to_str());
        // `sleep --version` is not Soli's answer: no version, no guess.
        assert_eq!(runtime.version, None);
        assert!(runtime.started_at.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_running_test_process_has_a_start_time_in_the_past() {
        let started = started_at(std::process::id()).expect("a start time");
        let now = SystemTime::now();
        assert!(started <= now);
        assert!(now.duration_since(started).unwrap() < Duration::from_secs(3600));
    }
}
