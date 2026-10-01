//! The proxy's own log: `[logging]` in config.toml.
//!
//! ```toml
//! [logging]
//! level = "info"            # or a filter: "info,soli_proxy::server=debug"
//! format = "json"           # or "text"
//! output = "stdout"         # "stderr", or "file:/var/log/soli-proxy/proxy.log"
//! max_size = "100MB"        # file output: rotate past this size ("0" = never)
//! max_files = 5             # file output: rotated files kept (proxy.log.1 … .5)
//! ```
//!
//! These keys used to be ignored: the proxy always logged JSON at INFO, to
//! stdout or (with `-d`) to `proxy.log`, synchronously from the request path,
//! and that file grew forever. Now every write goes through
//! `tracing_appender::non_blocking` — a dedicated thread does the I/O, and the
//! request path only queues a formatted line — and file output rotates by
//! size, creating new files `0640`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::config::{parse_size, LoggingConfig};

/// Default rotation threshold for file output.
pub const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;
/// Default number of rotated files kept next to the live one.
pub const DEFAULT_MAX_FILES: usize = 5;

/// Where the daemon (`-d`) writes when `[logging] output` names no file:
/// `${SOLI_LOG_DIR:-.}/proxy.log`, as it always has.
pub fn default_daemon_log_path() -> PathBuf {
    let dir = std::env::var("SOLI_LOG_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&dir).join("proxy.log")
}

/// Where the proxy's log goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File(PathBuf),
}

impl LogOutput {
    /// Resolve `[logging] output`. A daemon has no terminal — its stdout and
    /// stderr are `/dev/null` — so there `stdout`/`stderr` mean the default
    /// `proxy.log`.
    pub fn resolve(output: Option<&str>, daemon: bool) -> Result<Self> {
        let out = match output.map(str::trim) {
            None | Some("") | Some("stdout") => LogOutput::Stdout,
            Some("stderr") => LogOutput::Stderr,
            Some(other) => match other.strip_prefix("file:") {
                Some(path) if !path.trim().is_empty() => {
                    LogOutput::File(PathBuf::from(path.trim()))
                }
                _ => anyhow::bail!(
                    "invalid [logging] output {:?} (expected \"stdout\", \"stderr\" or \
                     \"file:/path/to/proxy.log\")",
                    other
                ),
            },
        };
        Ok(match out {
            LogOutput::Stdout | LogOutput::Stderr if daemon => {
                LogOutput::File(default_daemon_log_path())
            }
            out => out,
        })
    }
}

/// The file the proxy logs to under `cfg`, if any — what `soli-proxy tui`
/// tails for its error screen.
pub fn log_file_path(cfg: &LoggingConfig, daemon: bool) -> Option<PathBuf> {
    match LogOutput::resolve(cfg.output.as_deref(), daemon) {
        Ok(LogOutput::File(path)) => Some(path),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Json,
    Text,
}

fn log_format(format: Option<&str>) -> Result<LogFormat> {
    match format.map(str::trim) {
        None | Some("") | Some("json") => Ok(LogFormat::Json),
        Some("text") | Some("pretty") | Some("plain") => Ok(LogFormat::Text),
        Some(other) => anyhow::bail!(
            "invalid [logging] format {:?} (expected \"json\" or \"text\")",
            other
        ),
    }
}

/// The level filter: `[logging] level` when set, else `RUST_LOG`, else `info`.
/// Either may be a bare level or a full `tracing` filter directive.
fn log_filter(level: Option<&str>) -> Result<EnvFilter> {
    let directive = match level.map(str::trim).filter(|l| !l.is_empty()) {
        Some(level) => level.to_string(),
        None => std::env::var("RUST_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "info".to_string()),
    };
    // `EnvFilter` reads a bare word as a target name, so a typo such as
    // "verbose" would quietly mean "log only the `verbose` module" — nothing.
    const LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "off"];
    let single = directive.trim();
    if !single.contains(['=', ',', ':', '['])
        && !LEVELS.contains(&single.to_ascii_lowercase().as_str())
    {
        anyhow::bail!(
            "invalid [logging] level {:?} (expected one of {}, or a filter such as \
             \"info,soli_proxy::server=debug\")",
            directive,
            LEVELS.join(", ")
        );
    }
    EnvFilter::try_new(&directive)
        .map_err(|e| anyhow::anyhow!("invalid [logging] level {:?}: {}", directive, e))
}

/// Keeps the background writer alive; dropping it flushes what is queued.
static GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

/// Install the global subscriber described by `cfg`.
pub fn init(cfg: &LoggingConfig, daemon: bool) -> Result<()> {
    let filter = log_filter(cfg.level.as_deref())?;
    let format = log_format(cfg.format.as_deref())?;
    let output = LogOutput::resolve(cfg.output.as_deref(), daemon)?;
    let max_size = match cfg.max_size.as_deref() {
        Some(s) => parse_size(s)
            .ok_or_else(|| anyhow::anyhow!("invalid [logging] max_size {:?}", s))?
            as u64,
        None => DEFAULT_MAX_SIZE,
    };
    let max_files = cfg.max_files.map_or(DEFAULT_MAX_FILES, |n| n as usize);

    let (ansi, (writer, guard)) = match &output {
        LogOutput::Stdout => {
            use std::io::IsTerminal;
            (
                io::stdout().is_terminal(),
                tracing_appender::non_blocking(io::stdout()),
            )
        }
        LogOutput::Stderr => {
            use std::io::IsTerminal;
            (
                io::stderr().is_terminal(),
                tracing_appender::non_blocking(io::stderr()),
            )
        }
        LogOutput::File(path) => {
            let file = RotatingFile::open(path, max_size, max_files)
                .map_err(|e| anyhow::anyhow!("cannot open log file {}: {}", path.display(), e))?;
            (false, tracing_appender::non_blocking(file))
        }
    };

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(ansi);
    let installed = match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Text => builder.try_init(),
    };
    installed.map_err(|e| anyhow::anyhow!("cannot install the logger: {}", e))?;
    *GUARD.lock().unwrap_or_else(|e| e.into_inner()) = Some(guard);
    Ok(())
}

/// Flush and stop the background writer. Call before `process::exit`, which
/// skips destructors and would drop whatever is still queued.
pub fn flush() {
    let guard = GUARD.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(guard);
}

/// A log file that rotates by size: past `max_bytes`, `proxy.log` becomes
/// `proxy.log.1`, `.1` becomes `.2`, … and the oldest beyond `max_files` is
/// deleted. Rotation happens between two writes, and the non-blocking writer
/// hands over one formatted event per write, so a line is never split across
/// files. New files are created `0640`: logs carry client IPs and paths.
pub struct RotatingFile {
    path: PathBuf,
    /// 0 disables rotation.
    max_bytes: u64,
    max_files: usize,
    file: File,
    written: u64,
}

fn open_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o640);
    }
    options.open(path)
}

impl RotatingFile {
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let file = open_log_file(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            max_files: max_files.max(1),
            file,
            written,
        })
    }

    fn numbered(&self, n: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{}", n));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        for n in (1..self.max_files).rev() {
            let from = self.numbered(n);
            if from.exists() {
                std::fs::rename(&from, self.numbered(n + 1))?;
            }
        }
        std::fs::rename(&self.path, self.numbered(1))?;
        self.file = open_log_file(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.max_bytes > 0
            && self.written > 0
            && self.written + buf.len() as u64 > self.max_bytes
        {
            // A failed rotation (a full disk, a permissions change) must not
            // lose the line: keep appending to the current file.
            if let Err(e) = self.rotate() {
                eprintln!("soli-proxy: cannot rotate {}: {}", self.path.display(), e);
            }
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_resolution() {
        assert_eq!(LogOutput::resolve(None, false).unwrap(), LogOutput::Stdout);
        assert_eq!(
            LogOutput::resolve(Some("stderr"), false).unwrap(),
            LogOutput::Stderr
        );
        assert_eq!(
            LogOutput::resolve(Some("file:/var/log/p.log"), false).unwrap(),
            LogOutput::File("/var/log/p.log".into())
        );
        // A daemon has no terminal: stdout means the default proxy.log.
        assert!(matches!(
            LogOutput::resolve(Some("stdout"), true).unwrap(),
            LogOutput::File(p) if p.ends_with("proxy.log")
        ));
        assert_eq!(
            LogOutput::resolve(Some("file:/x.log"), true).unwrap(),
            LogOutput::File("/x.log".into())
        );
        for bad in ["file:", "syslog", "/var/log/p.log"] {
            assert!(LogOutput::resolve(Some(bad), false).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn format_and_level_are_validated() {
        assert_eq!(log_format(None).unwrap(), LogFormat::Json);
        assert_eq!(log_format(Some("text")).unwrap(), LogFormat::Text);
        assert!(log_format(Some("xml")).is_err());
        assert!(log_filter(Some("debug")).is_ok());
        assert!(log_filter(Some("info,soli_proxy::server=trace")).is_ok());
        // A bare word that is not a level would be read as a *target* name,
        // silencing everything else: `level = "verbose"` must be refused.
        assert!(log_filter(Some("verbose")).is_err());
        assert!(log_filter(Some("WARN")).is_ok());
    }

    #[test]
    fn rotating_file_rotates_by_size_and_keeps_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs/proxy.log");
        let mut f = RotatingFile::open(&path, 100, 2).unwrap();
        for i in 0..10 {
            f.write_all(format!("{:039}\n", i).as_bytes()).unwrap(); // 40 bytes
        }
        f.flush().unwrap();
        let read = |p: &Path| std::fs::read_to_string(p).unwrap();
        // 10 lines of 40 bytes, 2 per file: the live file holds the last two.
        assert_eq!(read(&path).lines().count(), 2);
        assert!(read(&path).contains(&format!("{:039}", 9)));
        assert!(dir.path().join("logs/proxy.log.1").exists());
        assert!(dir.path().join("logs/proxy.log.2").exists());
        assert!(!dir.path().join("logs/proxy.log.3").exists());
        // Lines are never split across files.
        for name in ["proxy.log", "proxy.log.1", "proxy.log.2"] {
            assert!(read(&dir.path().join("logs").join(name))
                .lines()
                .all(|l| l.len() == 39));
        }
    }

    #[cfg(unix)]
    #[test]
    fn log_files_are_created_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut f = RotatingFile::open(&path, 10, 1).unwrap();
        f.write_all(b"0123456789\n").unwrap();
        f.write_all(b"rotated\n").unwrap();
        for p in [path.clone(), dir.path().join("proxy.log.1")] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            // The process umask can only take bits away.
            assert_eq!(mode & !0o640, 0, "{} is {:o}", p.display(), mode);
        }
    }

    #[test]
    fn a_zero_max_size_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut f = RotatingFile::open(&path, 0, 3).unwrap();
        for _ in 0..100 {
            f.write_all(b"line\n").unwrap();
        }
        assert!(!dir.path().join("proxy.log.1").exists());
    }
}
