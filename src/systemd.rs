//! Is a proxy already running under systemd?
//!
//! The listeners use `SO_REUSEPORT`, so a second proxy started by hand on a
//! host where systemd runs one does not fail to bind: it silently shares :80
//! and :443 with it, the kernel splitting connections between two processes
//! with possibly different binaries and configs, and both supervise the same
//! apps — two health checkers, two failovers, two deploys fighting over the
//! same ports. `soli-proxy -d` was worse: it stops whatever `proxy.pid`
//! names, then starts a daemon systemd knows nothing about.
//!
//! So a hand-started server refuses to run when a systemd unit's main process
//! is a soli-proxy **and** one of the ports it would listen on is already
//! taken. The port is what makes it a conflict: a proxy on other ports (a
//! test suite on a host that runs one, a second instance with its own
//! config) shares nothing with the managed one. "Main process" is the test,
//! not "in a `.service` cgroup": desktop sessions launch terminals as services too (uwsm's
//! `app-…@….service`), and a proxy started from such a terminal sits in one
//! without systemd running it. systemd itself says which process is a
//! unit's main one (`MainPID`).

/// A soli-proxy that is the main process of a systemd unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedInstance {
    pub pid: u32,
    /// The unit, e.g. `soli-proxy.service`.
    pub unit: String,
    /// A unit of a user manager (`systemctl --user`), not of the system one.
    pub user_unit: bool,
    /// The listener ports this start wanted that were already taken.
    pub busy_ports: Vec<u16>,
}

impl ManagedInstance {
    /// What to tell someone who tried to start a proxy by hand.
    pub fn refusal(&self) -> String {
        let (ctl, journal) = if self.user_unit {
            ("systemctl --user", "journalctl --user")
        } else {
            ("sudo systemctl", "journalctl")
        };
        let unit = &self.unit;
        format!(
            "soli-proxy is already running under systemd ({unit}, PID {pid}), and {ports} \
             already taken.\n\
             A second proxy started by hand would share its ports (SO_REUSEPORT) and fight it \
             over the apps, so it is not started.\n\
             \n\
             Manage it through systemd instead:\n\
             \x20 {ctl} restart {unit}   # apply a new binary or a changed config\n\
             \x20 {ctl} reload {unit}    # re-read proxy.conf and config.toml\n\
             \x20 {status} status {unit}\n\
             \x20 {journal} -u {unit} -f\n\
             \n\
             To run it by hand anyway, stop the unit first: {ctl} stop {unit}",
            pid = self.pid,
            ports = match self.busy_ports.as_slice() {
                [one] => format!("port {one} is"),
                many => format!(
                    "ports {} are",
                    many.iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(" and ")
                ),
            },
            status = ctl.trim_start_matches("sudo "),
        )
    }
}

/// The systemd unit a process's cgroup file places it in, and whether it is
/// a user manager's: `0::/system.slice/soli-proxy.service` →
/// `("soli-proxy.service", false)`. Reads the unified (v2) line, or the
/// `name=systemd` hierarchy on a hybrid v1 host. `None` outside a service
/// (a session scope, a slice).
pub fn unit_from_cgroup(content: &str) -> Option<(String, bool)> {
    let path = content.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let (_, controllers, path) = (fields.next()?, fields.next()?, fields.next()?);
        (controllers.is_empty() || controllers == "name=systemd").then_some(path)
    })?;
    let unit = path.rsplit('/').next()?;
    if !unit.ends_with(".service") || unit.len() == ".service".len() {
        return None;
    }
    // A user manager's units live under user@<uid>.service; the manager
    // itself is a system unit of that name.
    let user_unit = path
        .split('/')
        .any(|c| c.starts_with("user@") && c.ends_with(".service") && c != unit);
    Some((unit.to_string(), user_unit))
}

/// The systemd-run proxy a server about to listen on `ports` must not run
/// next to: `None` when none of `ports` is taken, when this process is itself
/// a unit's main process (systemd started it, so it is the managed one), or
/// when no other soli-proxy is.
///
/// Best effort: anything unreadable or unconfirmed counts as "no", so a start
/// is refused only when systemd itself confirmed the other instance. Not
/// `INVOCATION_ID`, which a shell inherits from a terminal launched as a unit.
#[cfg(target_os = "linux")]
pub fn conflicting_instance(ports: &[u16]) -> Option<ManagedInstance> {
    let listening = listening_ports();
    let busy_ports: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|p| listening.contains(p))
        .collect();
    if busy_ports.is_empty() {
        return None;
    }
    let me = std::process::id();
    if managed(me).is_some() {
        return None;
    }
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let is_proxy = std::fs::read_to_string(entry.path().join("comm"))
            .is_ok_and(|comm| comm.trim_end() == "soli-proxy");
        if is_proxy {
            if let Some(instance) = managed(pid) {
                return Some(ManagedInstance {
                    busy_ports,
                    ..instance
                });
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn conflicting_instance(_ports: &[u16]) -> Option<ManagedInstance> {
    None
}

/// Every TCP port something listens on, IPv4 or IPv6, from `/proc/net`
/// (world-readable, so a root-owned proxy's ports show up for anyone).
#[cfg(target_os = "linux")]
fn listening_ports() -> std::collections::HashSet<u16> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|table| parse_listening(&table))
        .collect()
}

/// The local ports of the `LISTEN` (state `0A`) rows of a `/proc/net/tcp`
/// or `tcp6` table.
pub fn parse_listening(table: &str) -> Vec<u16> {
    table
        .lines()
        .skip(1)
        .filter_map(|row| {
            let mut fields = row.split_whitespace();
            let local = fields.nth(1)?;
            let state = fields.nth(1)?;
            if state != "0A" {
                return None;
            }
            u16::from_str_radix(local.rsplit(':').next()?, 16).ok()
        })
        .collect()
}

/// `pid` as the main process of the systemd unit its cgroup names, if
/// systemd confirms it is.
#[cfg(target_os = "linux")]
fn managed(pid: u32) -> Option<ManagedInstance> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let (unit, user_unit) = unit_from_cgroup(&cgroup)?;
    (main_pid(&unit, user_unit) == Some(pid)).then_some(ManagedInstance {
        pid,
        unit,
        user_unit,
        busy_ports: Vec::new(),
    })
}

/// `MainPID` of `unit`, as systemd reports it; `None` when systemctl is
/// missing, fails, or reports no main process (0).
#[cfg(target_os = "linux")]
fn main_pid(unit: &str, user_unit: bool) -> Option<u32> {
    let mut cmd = std::process::Command::new("systemctl");
    if user_unit {
        cmd.arg("--user");
    }
    let out = cmd
        .args(["show", "--property=MainPID", "--value", unit])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    (pid != 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_from_cgroup_files() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/soli-proxy.service\n"),
            Some(("soli-proxy.service".into(), false))
        );
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/proxy.service\n"
            ),
            Some(("proxy.service".into(), true))
        );
        // A desktop terminal launched as a service: in a .service, which is
        // why the caller still asks systemd for the unit's main PID.
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-kitty@3f.service\n"
            ),
            Some(("app-Hyprland-kitty@3f.service".into(), true))
        );
        // Hybrid v1: the name=systemd hierarchy carries the unit.
        assert_eq!(
            unit_from_cgroup(
                "12:cpu,cpuacct:/system.slice/x.service\n1:name=systemd:/system.slice/soli-proxy.service\n0::/\n"
            ),
            Some(("soli-proxy.service".into(), false))
        );
        // A shell's session scope, a slice, the root: no unit.
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-1000.slice/session-10.scope\n"),
            None
        );
        assert_eq!(unit_from_cgroup("0::/system.slice\n"), None);
        assert_eq!(unit_from_cgroup("0::/\n"), None);
        assert_eq!(unit_from_cgroup(""), None);
    }

    #[test]
    fn listening_ports_from_proc_net_tcp() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 100 0 0 10 0
   2: 1E01A8C0:0050 2801A8C0:EB2E 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1
";
        // :80 and :9090 listen; the established connection to :80 is not a listener.
        assert_eq!(parse_listening(table), vec![80, 9090]);
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
";
        assert_eq!(parse_listening(v6), vec![443]);
        assert!(parse_listening("").is_empty());
    }

    #[test]
    fn the_refusal_names_the_unit_and_the_way_out() {
        let system = ManagedInstance {
            pid: 2093935,
            unit: "soli-proxy.service".into(),
            user_unit: false,
            busy_ports: vec![80, 443],
        }
        .refusal();
        assert!(system.contains("soli-proxy.service, PID 2093935), and ports 80 and 443 are"));
        assert!(system.contains("sudo systemctl restart soli-proxy.service"));
        assert!(system.contains("  systemctl status soli-proxy.service"));
        assert!(system.contains("journalctl -u soli-proxy.service -f"));

        let user = ManagedInstance {
            pid: 42,
            unit: "proxy.service".into(),
            user_unit: true,
            busy_ports: vec![8080],
        }
        .refusal();
        assert!(user.contains("and port 8080 is already taken"));
        assert!(user.contains("systemctl --user restart proxy.service"));
        assert!(!user.contains("sudo"));
        assert!(user.contains("journalctl --user -u proxy.service -f"));
    }
}
