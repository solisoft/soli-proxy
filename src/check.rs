//! Configuration validation without side effects: `soli-proxy check` and
//! `POST /api/v1/config/validate`.
//!
//! Everything here runs the loaders a start would — the strict `proxy.conf`
//! parser, `config.toml` deserialisation and assembly, `AppInfo::from_path`
//! for every site, the `docker run` / native launch builders — and then the
//! checks a start would only make later, or only log: listener and admin
//! addresses, port ranges, Lua script files, the multi-tenant rules. Nothing
//! is started, no port is bound, no file is written.

use crate::app::{AppInfo, DeploymentManager};
use crate::config::{ConfigManager, ProxyRule, TomlConfig};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// How bad a [`Problem`] is: an error stops a start (or a part of it — an
/// app, the admin API, scripting); a warning is something the proxy works
/// around, usually not the way the file's author meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

/// One finding, located as precisely as the loader allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub file: String,
    pub line: Option<usize>,
    pub severity: Severity,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        match self.line {
            Some(line) => write!(f, "{}:{}: {}: {}", self.file, line, level, self.message),
            None => write!(f, "{}: {}: {}", self.file, level, self.message),
        }
    }
}

/// Everything a check found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub problems: Vec<Problem>,
    /// Site directories examined.
    pub sites_checked: usize,
}

impl Report {
    pub fn has_errors(&self) -> bool {
        self.problems.iter().any(|p| p.severity == Severity::Error)
    }

    pub fn errors(&self) -> usize {
        self.count(Severity::Error)
    }

    pub fn warnings(&self) -> usize {
        self.count(Severity::Warning)
    }

    fn count(&self, severity: Severity) -> usize {
        self.problems
            .iter()
            .filter(|p| p.severity == severity)
            .count()
    }

    fn push(
        &mut self,
        severity: Severity,
        file: &str,
        line: Option<usize>,
        message: impl Into<String>,
    ) {
        self.problems.push(Problem {
            file: file.to_string(),
            line,
            severity,
            message: message.into(),
        });
    }

    fn error(&mut self, file: &str, line: Option<usize>, message: impl Into<String>) {
        self.push(Severity::Error, file, line, message);
    }

    fn warn(&mut self, file: &str, line: Option<usize>, message: impl Into<String>) {
        self.push(Severity::Warning, file, line, message);
    }
}

/// Most errors a single `proxy.conf` holds. Past that, the file is not worth
/// reading line by line.
const MAX_PROXY_CONF_ERRORS: usize = 100;

/// Parse `proxy.conf` with the real (strict) parser and report every line it
/// refuses, not only the first: after each error the offending logical line
/// — continuation lines and, for a `headers {` line, its whole block
/// included — is commented out and the file parsed again. Returns the parsed
/// rules when the file is clean.
pub fn check_proxy_conf(
    file: &str,
    content: &str,
    report: &mut Report,
) -> Option<(Vec<ProxyRule>, Vec<String>)> {
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let mut clean = true;
    for _ in 0..MAX_PROXY_CONF_ERRORS {
        let attempt = lines.join("\n");
        match crate::config::parse_proxy_config(&attempt) {
            Ok(parsed) => return clean.then_some(parsed),
            Err(e) => {
                clean = false;
                let message = format!("{:#}", e);
                let Some((line, rest)) = split_line_prefix(&message) else {
                    report.error(file, None, message);
                    return None;
                };
                report.error(file, Some(line), rest);
                if !blank_logical_line(&mut lines, line) {
                    return None;
                }
            }
        }
    }
    report.error(
        file,
        None,
        format!("more than {MAX_PROXY_CONF_ERRORS} errors; stopped"),
    );
    None
}

/// `"line 12: message"` → `(12, "message")`.
fn split_line_prefix(message: &str) -> Option<(usize, String)> {
    let rest = message.strip_prefix("line ")?;
    let (number, rest) = rest.split_once(": ")?;
    Some((number.parse().ok()?, rest.to_string()))
}

/// Comment out the logical line starting at 1-based `line`, so the next
/// parse moves past it. Returns false when there is nothing to blank (the
/// parser would report the same line again).
fn blank_logical_line(lines: &mut [String], line: usize) -> bool {
    let Some(start) = line.checked_sub(1).filter(|i| *i < lines.len()) else {
        return false;
    };
    if lines[start].trim_start().starts_with('#') {
        return false;
    }
    let opens_block = lines[start]
        .trim()
        .strip_prefix("headers")
        .is_some_and(|rest| rest.trim() == "{");
    let mut i = start;
    loop {
        let continues = lines[i].trim_end().ends_with('\\');
        let closes = lines[i].trim() == "}";
        lines[i] = "#".to_string();
        i += 1;
        if i >= lines.len() || (opens_block && closes) || (!opens_block && !continues) {
            break;
        }
    }
    true
}

/// Parse `config.toml`. A TOML or type error is reported at its line.
pub fn check_config_toml(file: &str, content: &str, report: &mut Report) -> Option<TomlConfig> {
    match toml::from_str::<TomlConfig>(content) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            let (line, message) = toml_error_location(&e);
            report.error(file, line, message);
            None
        }
    }
}

/// `(line, message)` of a TOML error: the line from its rendered position
/// (`"TOML parse error at line 3, column 7"`), the message without the
/// source excerpt that follows it.
fn toml_error_location(e: &toml::de::Error) -> (Option<usize>, String) {
    let rendered = e.to_string();
    let line = rendered
        .lines()
        .next()
        .and_then(|first| first.split("at line ").nth(1))
        .and_then(|rest| {
            rest.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
        });
    (line, e.message().trim().to_string())
}

/// The checks on an assembled configuration that a start makes after
/// loading it, or only logs.
fn check_config(
    file: &str,
    toml: &TomlConfig,
    cfg: &crate::config::Config,
    config_dir: &Path,
    report: &mut Report,
) {
    if let Err(e) = cfg.server.https_addr() {
        report.error(file, None, format!("{:#}", e));
    }
    if let Some(grace) = cfg.server.shutdown_grace_period {
        if grace > crate::config::MAX_SHUTDOWN_GRACE_SECS {
            report.warn(
                file,
                None,
                format!(
                    "[server] shutdown_grace_period = {} is above the {} s ceiling and will be \
                     clamped",
                    grace,
                    crate::config::MAX_SHUTDOWN_GRACE_SECS
                ),
            );
        }
    }

    if let Err(e) = cfg.tls.min_version() {
        report.error(file, None, format!("{:#}", e));
    }
    if cfg.tls.mode == "letsencrypt" && cfg.letsencrypt.is_none() {
        report.warn(
            file,
            None,
            "[tls] mode is \"letsencrypt\" but there is no [letsencrypt] section: no \
             certificate will be ordered",
        );
    }

    if let Err(e) = crate::logging::validate(&cfg.logging) {
        report.error(file, None, format!("{:#}", e));
    }

    if let Some(size) = toml
        .limits
        .as_ref()
        .and_then(|l| l.max_request_size.as_deref())
    {
        if crate::config::parse_size(size).is_none() {
            report.warn(
                file,
                None,
                format!("[limits] max_request_size {size:?} is not a size; it is ignored"),
            );
        }
    }

    if cfg.admin.enabled.unwrap_or(true) {
        match cfg.admin.bind.parse::<std::net::SocketAddr>() {
            Err(e) => report.error(
                file,
                None,
                format!(
                    "[admin] bind {:?}: {} — the admin API will not start",
                    cfg.admin.bind, e
                ),
            ),
            Ok(addr)
                if !addr.ip().is_loopback()
                    && !crate::admin::admin_auth_configured(
                        &cfg.admin.api_key,
                        &cfg.admin.username,
                        &cfg.admin.password_hash,
                    ) =>
            {
                report.error(
                    file,
                    None,
                    format!(
                        "[admin] bind {} is not loopback and no credential is configured \
                         (api_key, or ADMIN_USER + ADMIN_PASSWORD_HASH): the admin API refuses \
                         to start",
                        addr
                    ),
                )
            }
            Ok(_) => {}
        }
        if let Some(ref hash) = cfg.admin.password_hash {
            if let Err(e) = crate::auth::validate_hash(hash) {
                report.error(
                    file,
                    None,
                    format!("admin password hash (ADMIN_PASSWORD_HASH): {}", e),
                );
            }
        }
    }

    if cfg.apps.multi_tenant() {
        let reachable = cfg.server.edge.trusted_proxies.tenant_reachable();
        if !reachable.is_empty() {
            report.warn(
                file,
                None,
                format!(
                    "[server] trusted_proxies {} cover(s) addresses tenants connect from in                      multi_tenant mode (loopback for a native app, Docker's 172.16.0.0/12 and                      192.168.0.0/16 pools for a container): a tenant could send forwarding                      headers the proxy believes and pose as any client — to rate limits,                      [maintenance] allow_ips and backends. List the balancer's own addresses                      instead",
                    reachable.join(", ")
                ),
            );
        }
    }

    let (start, end) = cfg.apps.app_port_range();
    let reserved = crate::app::proxy_listener_ports(cfg);
    if let Some(problem) = crate::app::port_range_problem(start, end, &reserved) {
        report.error(
            file,
            None,
            format!("[apps] port range unusable ({problem}); the default would be used"),
        );
    }

    if cfg.scripting.enabled {
        let scripts_dir = cfg
            .scripting
            .scripts_dir
            .as_deref()
            .unwrap_or("./scripts/lua");
        // Relative to the working directory, as at runtime; the config
        // directory is the better guess when the two differ.
        let dir = if Path::new(scripts_dir).is_absolute() || Path::new(scripts_dir).is_dir() {
            PathBuf::from(scripts_dir)
        } else {
            config_dir.join(scripts_dir)
        };
        if !dir.is_dir() {
            report.error(
                file,
                None,
                format!(
                    "[scripting] scripts_dir {} is not a directory: scripting would be disabled",
                    scripts_dir
                ),
            );
        } else {
            let mut named: Vec<&String> = cfg.global_scripts.iter().collect();
            named.extend(cfg.rules.iter().flat_map(|r| r.scripts.iter()));
            let mut seen = HashSet::new();
            for script in named {
                if seen.insert(script) && !dir.join(script).is_file() {
                    report.error(
                        file,
                        None,
                        format!(
                            "Lua script {} (named in proxy.conf) is not in {}",
                            script,
                            dir.display()
                        ),
                    );
                }
            }
        }
    }
}

/// Parse and check `proxy.conf` + `config.toml` given as text. `config_dir`
/// is where `.env` (admin credentials) and relative script paths are read
/// from. Returns the assembled configuration when both parse.
pub fn check_sources(
    proxy_conf: (&str, &str),
    config_toml: (&str, &str),
    config_dir: &Path,
    report: &mut Report,
) -> Option<crate::config::Config> {
    let (conf_file, conf_text) = proxy_conf;
    let (toml_file, toml_text) = config_toml;
    let parsed = check_proxy_conf(conf_file, conf_text, report);
    let toml = check_config_toml(toml_file, toml_text, report)?;
    let (rules, global_scripts) = parsed?;
    match ConfigManager::assemble(toml.clone(), rules, global_scripts, config_dir) {
        Ok(cfg) => {
            check_config(toml_file, &toml, &cfg, config_dir, report);
            Some(cfg)
        }
        Err(e) => {
            // Assembly reads three sources; name the one at fault. Every
            // error used to be filed under `.env` — a route's unreadable
            // `@tls_ca` included.
            let dotenv = config_dir.join(".env").display().to_string();
            let message = format!("{:#}", e);
            let file = if message.starts_with("route #") {
                conf_file.to_string()
            } else if message.contains(&dotenv) {
                dotenv
            } else {
                toml_file.to_string()
            };
            report.error(&file, None, message);
            None
        }
    }
}

/// Check every site under `sites_dir` the way discovery loads it.
pub fn check_sites(
    sites_dir: &Path,
    cfg: &crate::config::Config,
    dev_mode: bool,
    report: &mut Report,
) {
    let shown = sites_dir.display().to_string();
    if !sites_dir.is_dir() {
        report.warn(
            &shown,
            None,
            "not a directory (it is created empty at startup)",
        );
        return;
    }
    let multi_tenant = cfg.apps.multi_tenant();
    let scanned = match crate::app::scan_sites(sites_dir, dev_mode, multi_tenant) {
        Ok(scanned) => scanned,
        Err(e) => {
            report.error(&shown, None, format!("cannot read: {}", e));
            return;
        }
    };

    let (exit_tx, _exit_rx) = tokio::sync::mpsc::unbounded_channel();
    let launcher = DeploymentManager::new(
        dev_mode,
        cfg.apps.default_user.clone(),
        cfg.apps.default_group.clone(),
        exit_tx,
    )
    .with_tenant_isolation(multi_tenant, cfg.apps.mandatory_docker_args())
    .with_tenant_env(
        cfg.apps.tenant_proxy_env(),
        cfg.apps.tenant_proxy_env_credentials(),
    );
    let reserved = crate::app::proxy_listener_ports(cfg);
    let platform_range = cfg.apps.app_port_range();

    let mut names: HashMap<String, PathBuf> = HashMap::new();
    let mut domains: HashMap<String, String> = HashMap::new();
    for (path, result) in scanned {
        report.sites_checked += 1;
        let manifest = path.join("app.infos").display().to_string();
        let app: AppInfo = match result {
            Ok(app) => app,
            Err(e) => {
                let line = e
                    .chain()
                    .find_map(|c| c.downcast_ref::<toml::de::Error>())
                    .and_then(|t| toml_error_location(t).0);
                report.error(
                    &manifest,
                    line,
                    format!("{:#} — the site is skipped", e)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                );
                continue;
            }
        };
        let name = app.config.name.clone();
        if let Some(first) = names.get(&name) {
            report.error(
                &manifest,
                None,
                format!(
                    "app name {:?} is already taken by {}; this site is skipped",
                    name,
                    first.display()
                ),
            );
            continue;
        }
        names.insert(name.clone(), path.clone());
        // `domain`, `domains` and `redirect_from` are all the app's own
        // hosts: a second app listing one of them loses it.
        let own_hosts = std::iter::once(&app.config.domain)
            .filter(|d| !d.is_empty())
            .chain(&app.config.domains)
            .chain(&app.config.redirect_from);
        for host in own_hosts {
            if let Some(owner) = domains.get(host) {
                report.warn(
                    &manifest,
                    None,
                    format!(
                        "domain {} is also declared by {}, which keeps it",
                        host, owner
                    ),
                );
            } else {
                domains.insert(host.clone(), name.clone());
            }
        }

        let declared = (app.config.port_range_start, app.config.port_range_end);
        if !multi_tenant && declared != platform_range {
            if let Some(problem) = crate::app::port_range_problem(declared.0, declared.1, &reserved)
            {
                report.warn(
                    &manifest,
                    None,
                    format!(
                        "port range unusable ({problem}); the [apps] range {}-{} is used",
                        platform_range.0, platform_range.1
                    ),
                );
            }
        }

        // Only apps the proxy starts: the same test discovery applies.
        if app.config.start_script.is_some() {
            if let Err(e) = launcher.check_launch(&app) {
                report.error(&manifest, None, format!("cannot be started: {:#}", e));
            }
        }
    }
}

/// `soli-proxy check`: `proxy.conf` at `conf_path`, the `config.toml` (and
/// `.env`) beside it, and every site under `sites_dir`.
pub fn check_installation(conf_path: &Path, sites_dir: &Path, dev_mode: bool) -> Report {
    let mut report = Report::default();
    let conf_file = conf_path.display().to_string();
    let conf_text = match std::fs::read_to_string(conf_path) {
        Ok(text) => text,
        Err(e) => {
            report.error(&conf_file, None, format!("cannot read: {}", e));
            String::new()
        }
    };
    let config_dir = conf_path.parent().unwrap_or(Path::new("."));
    let config_dir = if config_dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        config_dir
    };
    let toml_path = config_dir.join("config.toml");
    let toml_file = toml_path.display().to_string();
    let toml_text = match std::fs::read_to_string(&toml_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            report.warn(
                &toml_file,
                None,
                "missing: a default one is written at first start (checked as empty here)",
            );
            String::new()
        }
        Err(e) => {
            report.error(&toml_file, None, format!("cannot read: {}", e));
            return report;
        }
    };

    if let Some(cfg) = check_sources(
        (&conf_file, &conf_text),
        (&toml_file, &toml_text),
        config_dir,
        &mut report,
    ) {
        check_sites(sites_dir, &cfg, dev_mode, &mut report);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const HASH: &str = "$2b$04$C6UzMDM.H6dfI/f/IKcEeO5yXJlWmEYoc/CzGu8NHSHFCiLq8dE/2";

    fn check_conf(text: &str) -> Report {
        let mut report = Report::default();
        check_proxy_conf("proxy.conf", text, &mut report);
        report
    }

    #[test]
    fn every_bad_proxy_conf_line_is_reported_with_its_number() {
        let report = check_conf(
            "# rules\n\
             example.com -> http://127.0.0.1:3000\n\
             this line has no arrow\n\
             api.example.com -> http://127.0.0.1:3001 @frobnicate\n\
             ok.example.com -> http://127.0.0.1:3002\n",
        );
        let lines: Vec<Option<usize>> = report.problems.iter().map(|p| p.line).collect();
        assert_eq!(lines, vec![Some(3), Some(4)], "{:#?}", report.problems);
        assert!(report.has_errors());
        assert!(report.problems[0]
            .to_string()
            .starts_with("proxy.conf:3: error: "));
    }

    #[test]
    fn a_clean_proxy_conf_has_no_problems() {
        let mut report = Report::default();
        let parsed = check_proxy_conf(
            "proxy.conf",
            &format!("example.com -> http://127.0.0.1:3000 @auth:admin:{HASH}\n"),
            &mut report,
        );
        assert!(report.problems.is_empty(), "{:#?}", report.problems);
        assert_eq!(parsed.unwrap().0.len(), 1);
    }

    #[test]
    fn an_auth_hash_bcrypt_would_choke_on_is_an_error() {
        // Cost 31: every login would run for days.
        let report = check_conf(
            "example.com -> http://127.0.0.1:3000 \
             @auth:admin:$2b$31$C6UzMDM.H6dfI/f/IKcEeO5yXJlWmEYoc/CzGu8NHSHFCiLq8dE/2\n",
        );
        assert_eq!(report.errors(), 1, "{:#?}", report.problems);
        assert_eq!(report.problems[0].line, Some(1));
    }

    #[test]
    fn a_continued_line_is_skipped_whole_after_its_error() {
        // Line 1 is bad and continues onto line 2: one error, not two.
        let report = check_conf(
            "example.com -> http://127.0.0.1:3000 @nope \\\n  @lb:round-robin\n\
             good.example.com -> http://127.0.0.1:3001\n",
        );
        assert_eq!(report.errors(), 1, "{:#?}", report.problems);
    }

    #[test]
    fn config_toml_errors_carry_their_line() {
        let mut report = Report::default();
        let parsed = check_config_toml(
            "config.toml",
            "[server]\nbind = \"0.0.0.0:80\"\nhttps_port = \"not a port\"\n",
            &mut report,
        );
        assert!(parsed.is_none());
        assert_eq!(report.problems[0].line, Some(3), "{:#?}", report.problems);
    }

    #[test]
    fn semantic_config_errors_are_found_without_binding_anything() {
        let dir = TempDir::new().unwrap();
        let mut report = Report::default();
        let cfg = check_sources(
            ("proxy.conf", "example.com -> http://127.0.0.1:3000\n"),
            (
                "config.toml",
                "[server]\nbind = \"nonsense\"\nhttps_port = 443\n\
                 [admin]\nbind = \"0.0.0.0:9090\"\n\
                 [apps]\nport_range_start = 80\nport_range_end = 90\n\
                 [logging]\nlevel = \"verbose\"\n",
            ),
            dir.path(),
            &mut report,
        );
        assert!(cfg.is_some());
        let text: Vec<String> = report.problems.iter().map(|p| p.to_string()).collect();
        let has = |needle: &str| text.iter().any(|t| t.contains(needle));
        assert!(has("invalid [server] bind"), "{text:#?}");
        assert!(has("admin API refuses to start"), "{text:#?}");
        assert!(has("[apps] port range unusable"), "{text:#?}");
        assert!(has("[logging] level"), "{text:#?}");
    }

    /// In multi_tenant mode a `trusted_proxies` entry covering loopback or
    /// Docker's pools trusts the tenants' own forwarding headers: a warning
    /// naming it. A single-tenant install, or a balancer's own range, is fine.
    #[test]
    fn multi_tenant_trust_of_tenant_networks_is_a_warning() {
        let warned = |toml: &str| {
            let dir = TempDir::new().unwrap();
            let mut report = Report::default();
            check_sources(
                ("proxy.conf", ""),
                ("config.toml", toml),
                dir.path(),
                &mut report,
            )
            .unwrap();
            report
                .problems
                .iter()
                .find(|p| p.message.contains("trusted_proxies"))
                .map(|p| (p.severity, p.message.clone()))
        };
        let (severity, message) = warned(
            "[server]\nbind = \"127.0.0.1:80\"\nhttps_port = 443\ntrusted_proxies = [\"private\", \"10.0.0.0/8\"]\n\
             [apps]\nmulti_tenant = true\n",
        )
        .expect("warned");
        assert_eq!(severity, Severity::Warning);
        assert!(
            message.contains("private") && !message.contains("10.0.0.0/8"),
            "{message}"
        );
        assert!(warned(
            "[server]\nbind = \"127.0.0.1:80\"\nhttps_port = 443\ntrusted_proxies = [\"loopback\"]\n[apps]\nmulti_tenant = true\n"
        )
        .is_some());
        assert!(warned("[server]\nbind = \"127.0.0.1:80\"\nhttps_port = 443\ntrusted_proxies = [\"private\"]\n").is_none());
        assert!(warned(
            "[server]\nbind = \"127.0.0.1:80\"\nhttps_port = 443\ntrusted_proxies = [\"cloudflare\", \"10.0.0.0/8\"]\n\
             [apps]\nmulti_tenant = true\n"
        )
        .is_none());
    }

    /// A route's TLS file that cannot be loaded is a `proxy.conf` problem,
    /// not a `.env` one.
    #[test]
    fn assembly_errors_name_the_file_at_fault() {
        let dir = TempDir::new().unwrap();
        let mut report = Report::default();
        let cfg = check_sources(
            (
                "proxy.conf",
                "/a/* -> https://127.0.0.1:1/ @tls_ca:/nonexistent/soli-proxy-check-ca.pem\n",
            ),
            ("config.toml", ""),
            dir.path(),
            &mut report,
        );
        assert!(cfg.is_none());
        let problem = report
            .problems
            .iter()
            .find(|p| p.message.contains("soli-proxy-check-ca.pem"))
            .expect("reported");
        assert_eq!(problem.file, "proxy.conf", "{problem}");
    }

    fn site(sites: &Path, name: &str, manifest: &str) {
        let dir = sites.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.infos"), manifest).unwrap();
    }

    fn sites_report(sites: &Path, config_toml: &str) -> Report {
        let dir = TempDir::new().unwrap();
        let mut report = Report::default();
        let cfg = check_sources(
            ("proxy.conf", ""),
            ("config.toml", config_toml),
            dir.path(),
            &mut report,
        )
        .unwrap();
        check_sites(sites, &cfg, false, &mut report);
        report
    }

    #[test]
    fn site_manifests_are_checked_with_the_discovery_rules() {
        let sites = TempDir::new().unwrap();
        site(
            sites.path(),
            "good.example.com",
            "start_script = \"./server --port $PORT\"\n",
        );
        site(
            sites.path(),
            "broken.example.com",
            "name = \"x\"\nworkers = \"many\"\n",
        );
        site(
            sites.path(),
            "auth.example.com",
            "[auth.users]\nadmin = \"$2b$31$C6UzMDM.H6dfI/f/IKcEeO5yXJlWmEYoc/CzGu8NHSHFCiLq8dE/2\"\n",
        );
        let report = sites_report(sites.path(), "");
        assert_eq!(report.sites_checked, 3);
        let broken: Vec<&Problem> = report
            .problems
            .iter()
            .filter(|p| p.file.contains("broken.example.com"))
            .collect();
        assert_eq!(broken.len(), 1, "{:#?}", report.problems);
        assert_eq!(broken[0].line, Some(2), "{:#?}", broken);
        assert!(report
            .problems
            .iter()
            .any(|p| p.file.contains("auth.example.com") && p.severity == Severity::Error));
        assert!(!report
            .problems
            .iter()
            .any(|p| p.file.contains("good.example.com")));
    }

    #[test]
    fn multi_tenant_rules_apply_to_site_manifests() {
        let sites = TempDir::new().unwrap();
        // Native in multi-tenant mode: refused.
        site(
            sites.path(),
            "native.example.com",
            "start_script = \"./server\"\n",
        );
        // A domain the directory does not own.
        site(
            sites.path(),
            "tenant.example.com",
            "domain = \"bank.example.com\"\ndocker_image = \"nginx:1.27\"\n\
             start_script = \"nginx\"\n",
        );
        // A tenant docker option outside the allowlist.
        site(
            sites.path(),
            "priv.example.com",
            "docker_image = \"nginx:1.27\"\nstart_script = \"nginx\"\n\
             docker_options = \"--privileged\"\n",
        );
        let report = sites_report(sites.path(), "[apps]\nmulti_tenant = true\n");
        for site in ["native", "tenant", "priv"] {
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.file.contains(&format!("{site}.example.com"))
                        && p.severity == Severity::Error),
                "{site}: {:#?}",
                report.problems
            );
        }
    }

    #[test]
    fn check_installation_reads_nothing_but_its_inputs() {
        let dir = TempDir::new().unwrap();
        let conf = dir.path().join("proxy.conf");
        std::fs::write(&conf, "example.com -> http://127.0.0.1:3000\n").unwrap();
        let report = check_installation(&conf, &dir.path().join("sites"), false);
        // config.toml is missing: a warning, and — unlike a start — not
        // written.
        assert!(!report.has_errors(), "{:#?}", report.problems);
        assert_eq!(report.warnings(), 2, "{:#?}", report.problems);
        assert!(!dir.path().join("config.toml").exists());
        assert!(!dir.path().join("sites").exists());
    }
}
