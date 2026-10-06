//! End to end: a proxy restart leaves its apps running and the next proxy
//! adopts them; `soli-proxy stop --all` stops them; `soli-proxy check`
//! validates without starting anything.
//!
//! Runs the real binary against a temporary installation on loopback ports.
//! The app is `python3 -m http.server`; the test is skipped where there is no
//! python3.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_soli-proxy");
const APP: &str = "app.example.test";

struct Installation {
    dir: tempfile::TempDir,
    http: u16,
    admin: u16,
}

impl Installation {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let http = portpicker::pick_unused_port().unwrap();
        let https = portpicker::pick_unused_port().unwrap();
        let admin = portpicker::pick_unused_port().unwrap();
        // Slot ports, clear of the proxy's own listeners and of every other
        // installation in this binary: the tests run in parallel, and two
        // proxies given the same range would each find the other's app on
        // its port.
        static NEXT_RANGE: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        let mut range =
            46000u16 + 200 * NEXT_RANGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        while [http, https, admin]
            .iter()
            .any(|p| (range..range + 100).contains(p))
        {
            range += 100;
        }
        let root = dir.path();
        std::fs::write(root.join("proxy.conf"), "").unwrap();
        std::fs::write(
            root.join("config.toml"),
            format!(
                "[server]\nbind = \"127.0.0.1:{http}\"\nhttps_port = {https}\n\
                 shutdown_grace_period = 5\n\
                 [tls]\nmode = \"auto\"\ncache_dir = \"./certs\"\nforce_https = false\n\
                 [admin]\nenabled = true\nbind = \"127.0.0.1:{admin}\"\n\
                 [apps]\nport_range_start = {range}\nport_range_end = {end}\n\
                 [rate_limiting]\nenabled = false\n\
                 [logging]\nformat = \"text\"\noutput = \"file:{log}\"\n",
                log = root.join("proxy.log").display(),
                end = range + 99,
            ),
        )
        .unwrap();
        let site = root.join("sites").join(APP);
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(
            site.join("app.infos"),
            "domain = \"app.example.test\"\n\
             start_script = \"python3 -m http.server $PORT --bind 127.0.0.1\"\n\
             health_check = \"/\"\ngraceful_timeout = 4\n",
        )
        .unwrap();
        std::fs::write(
            site.join("app.infos"),
            format!(
                "{}port_range_start = {range}\nport_range_end = {}\n",
                std::fs::read_to_string(site.join("app.infos")).unwrap(),
                range + 99
            ),
        )
        .unwrap();
        Self { dir, http, admin }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn conf(&self) -> PathBuf {
        self.root().join("proxy.conf")
    }

    fn start(&self) -> Child {
        Command::new(BIN)
            .arg("--conf")
            .arg(self.conf())
            .arg("--sites-dir")
            .arg(self.root().join("sites"))
            .current_dir(self.root())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.root().join("stderr.log"))
                    .unwrap(),
            ))
            .spawn()
            .unwrap()
    }

    /// The proxy's log, and its stderr.
    fn log(&self) -> String {
        let read = |name: &str| std::fs::read_to_string(self.root().join(name)).unwrap_or_default();
        format!("{}{}", read("proxy.log"), read("stderr.log"))
    }

    /// The app's live slot `(pid, port)` per the admin API, once it runs.
    async fn running_app(&self, within: Duration) -> Option<(u32, u16)> {
        let client = reqwest::Client::new();
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Ok(resp) = client
                .get(format!("http://127.0.0.1:{}/api/v1/apps", self.admin))
                .send()
                .await
            {
                let body: serde_json::Value =
                    serde_json::from_str(&resp.text().await.unwrap_or_default())
                        .unwrap_or_default();
                if let Some(app) = body["data"]
                    .as_array()
                    .and_then(|apps| apps.iter().find(|a| a["config"]["name"] == APP))
                {
                    let slot = app["current_slot"].as_str().unwrap_or("blue");
                    let instance = &app[slot];
                    if instance["status"] == "Running" {
                        if let (Some(pid), Some(port)) =
                            (instance["pid"].as_u64(), instance["port"].as_u64())
                        {
                            return Some((pid as u32, port as u16));
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    }

    /// Whether the app answers through the proxy within a few seconds.
    ///
    /// "Running" is reported from the spawn, before the app listens: a slow
    /// runner can ask before `http.server` has bound its port, so a single
    /// attempt is a race, not a check.
    async fn served_through_proxy(&self) -> bool {
        let client = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let ok = client
                .get(format!("http://127.0.0.1:{}/", self.http))
                .header("Host", APP)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if ok {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }
}

fn alive(pid: u32) -> bool {
    // A zombie still answers kill(0); /proc's state field does not lie.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rfind(')')
                .and_then(|i| s.get(i + 2..))
                .map(|r| !r.starts_with('Z'))
        })
        .unwrap_or(false)
}

async fn wait_exit(child: &mut Child, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn sigterm(child: &Child) {
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
}

/// Kills whatever the test leaves behind, pass or fail.
struct Cleanup(Vec<u32>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for pid in &self.0 {
            unsafe {
                libc::kill(-(*pid as i32), libc::SIGKILL);
                libc::kill(*pid as i32, libc::SIGKILL);
            }
        }
    }
}

#[tokio::test]
async fn apps_survive_a_proxy_restart_and_are_adopted() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let install = Installation::new();
    let mut cleanup = Cleanup(Vec::new());

    let mut proxy = install.start();
    cleanup.0.push(proxy.id());
    // Nothing runs it yet: a fresh proxy leaves a sleep-capable app asleep,
    // and its first request starts it.
    assert!(
        install.running_app(Duration::from_secs(3)).await.is_none(),
        "started before any request; log:\n{}",
        install.log()
    );
    assert!(install
        .log()
        .contains("left asleep until their first request"));
    assert!(install.served_through_proxy().await, "{}", install.log());
    let (pid, port) = install
        .running_app(Duration::from_secs(30))
        .await
        .unwrap_or_else(|| panic!("app never started; log:\n{}", install.log()));
    cleanup.0.push(pid);

    // Restart: the proxy drains and exits, the app keeps running.
    sigterm(&proxy);
    assert!(
        wait_exit(&mut proxy, Duration::from_secs(15)).await,
        "proxy did not exit; log:\n{}",
        install.log()
    );
    assert!(alive(pid), "the app died with the proxy");
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());

    // The next proxy adopts it: same process, no restart.
    let mut proxy = install.start();
    cleanup.0.push(proxy.id());
    let (adopted, _) = install
        .running_app(Duration::from_secs(30))
        .await
        .unwrap_or_else(|| panic!("app not running after restart; log:\n{}", install.log()));
    assert_eq!(
        adopted,
        pid,
        "restarted instead of adopted; log:\n{}",
        install.log()
    );
    assert!(install.log().contains("Adopting"), "{}", install.log());
    assert!(install.served_through_proxy().await);

    // `stop --all` goes through the daemon and stops it.
    let out = Command::new(BIN)
        .args(["stop", "--all", "--conf"])
        .arg(install.conf())
        .current_dir(install.root())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!alive(pid), "stop --all left the app running");

    sigterm(&proxy);
    assert!(wait_exit(&mut proxy, Duration::from_secs(15)).await);
}

#[test]
fn check_reports_problems_with_their_line_and_fails() {
    let install = Installation::new();
    let ok = Command::new(BIN)
        .arg("check")
        .arg("--conf")
        .arg(install.conf())
        .arg("--sites-dir")
        .arg(install.root().join("sites"))
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}{}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );

    std::fs::write(
        install.conf(),
        "example.com -> http://127.0.0.1:3000\nnot a rule\n",
    )
    .unwrap();
    let bad = Command::new(BIN)
        .arg("check")
        .arg("--conf")
        .arg(install.conf())
        .arg("--sites-dir")
        .arg(install.root().join("sites"))
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(
        stdout.contains("proxy.conf:2: error:"),
        "{stdout}{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    // Nothing was started or written.
    assert!(!install.root().join("run").exists());
    assert!(!install.root().join("certs").exists());
}

/// Upgrading from 0.35: its apps are still running, but 0.35 kept no spawn
/// registry, so nothing proves they are this proxy's. 1.0.0 refused to touch
/// them and quarantined every such app ("port already in use by another
/// process"). The leftover is recognised by its directory, user and program,
/// stopped, and the app starts afresh under the new proxy.
#[tokio::test]
async fn an_app_left_running_by_a_pre_registry_proxy_is_restarted_not_quarantined() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let install = Installation::new();
    let mut cleanup = Cleanup(Vec::new());

    // A proxy starts the app (on its first request) and stops, leaving it
    // running...
    let mut first = install.start();
    cleanup.0.push(first.id());
    assert!(install.served_through_proxy().await, "{}", install.log());
    let (old_pid, port) = install
        .running_app(Duration::from_secs(30))
        .await
        .unwrap_or_else(|| panic!("app never ran:\n{}", install.log()));
    cleanup.0.push(old_pid);
    sigterm(&first);
    assert!(wait_exit(&mut first, Duration::from_secs(15)).await);
    assert!(alive(old_pid), "the app must outlive the proxy");

    // ...and, like 0.35, it kept no record of it.
    std::fs::remove_file(install.root().join("run/spawned.json")).unwrap();

    let mut second = install.start();
    cleanup.0.push(second.id());
    // Not adoptable, so left asleep: the next request starts it afresh.
    assert!(install.served_through_proxy().await, "{}", install.log());
    let (new_pid, new_port) = install
        .running_app(Duration::from_secs(40))
        .await
        .unwrap_or_else(|| panic!("app not running after the upgrade:\n{}", install.log()));
    cleanup.0.push(new_pid);

    let log = install.log();
    assert!(!log.contains("quarantined"), "{log}");
    assert_ne!(new_pid, old_pid, "the leftover is replaced, not adopted");
    assert!(!alive(old_pid), "the leftover must be stopped:\n{log}");
    assert_eq!(new_port, port);
    assert!(install.served_through_proxy().await, "{log}");

    sigterm(&second);
    let _ = wait_exit(&mut second, Duration::from_secs(15)).await;
}
