//! Socket activation: the proxy serves on listening sockets systemd passed
//! (`LISTEN_FDS`) instead of binding its own, so a connection that arrives
//! before it is ready waits in the kernel's queue rather than being refused —
//! what makes a `systemctl restart` invisible behind `soli-proxy.socket`.
//!
//! `systemd-socket-activate` stands in for systemd: it binds the ports, then
//! execs the proxy with the sockets as fd 3 and 4. Skipped where it is absent.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_soli-proxy");

fn activator() -> Option<&'static str> {
    [
        "/usr/bin/systemd-socket-activate",
        "/bin/systemd-socket-activate",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).is_file())
}

/// One plain HTTP/1.1 request on a fresh connection, waiting up to `within`
/// for the status line.
fn status_of(port: u16, within: Duration) -> Option<u16> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(within)).ok()?;
    stream
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).ok()?;
    let line = String::from_utf8_lossy(&buf[..n]);
    line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn the_proxy_serves_on_sockets_systemd_passed() {
    let Some(activator) = activator() else {
        eprintln!("systemd-socket-activate not available; skipping");
        return;
    };
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    let http = portpicker::pick_unused_port().unwrap();
    let https = portpicker::pick_unused_port().unwrap();
    let admin = portpicker::pick_unused_port().unwrap();
    std::fs::write(root.join("proxy.conf"), "").unwrap();
    std::fs::create_dir_all(root.join("sites")).unwrap();
    std::fs::write(
        root.join("config.toml"),
        format!(
            "[server]\nbind = \"127.0.0.1:{http}\"\nhttps_port = {https}\n\
             [tls]\nmode = \"auto\"\ncache_dir = \"./certs\"\nforce_https = false\n\
             [admin]\nenabled = true\nbind = \"127.0.0.1:{admin}\"\n\
             [logging]\nformat = \"text\"\noutput = \"file:{log}\"\n",
            log = root.join("proxy.log").display(),
        ),
    )
    .unwrap();

    let mut proxy = Command::new(activator)
        .arg(format!("--listen=127.0.0.1:{http}"))
        .arg(format!("--listen=127.0.0.1:{https}"))
        .arg(BIN)
        .arg("--conf")
        .arg(root.join("proxy.conf"))
        .arg("--sites-dir")
        .arg(root.join("sites"))
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(root.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let log = || {
        let read = |n: &str| std::fs::read_to_string(root.join(n)).unwrap_or_default();
        format!("{}{}", read("proxy.log"), read("stderr.log"))
    };

    // The activator binds before it execs the proxy: wait for the port, then
    // ask at once — before the proxy has read its configuration. The
    // connection is queued, not refused, and answered once it is up.
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", http)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the activator never bound :{http}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = status_of(http, Duration::from_secs(20));

    let _ = unsafe { libc::kill(proxy.id() as i32, libc::SIGTERM) };
    let _ = proxy.wait();

    assert_eq!(status, Some(200), "log:\n{}", log());
    let log = log();
    assert!(
        log.contains("through the socket systemd holds"),
        "the proxy bound its own sockets instead:\n{log}"
    );
    assert!(!log.contains("does not listen on"), "{log}");
}
