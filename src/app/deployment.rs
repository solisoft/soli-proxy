use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use super::AppInfo;

/// Notification sent when a managed process exits unexpectedly.
#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub app_name: String,
    pub slot: String,
    pub pid: u32,
}

/// Validate `docker_options` and return the argv tokens to hand to
/// `docker run`.
///
/// Single-tenant (the default): the operator wrote `app.infos`, so this is
/// defense-in-depth against a compromised/misconfigured app — a denylist of
/// flags that break container isolation outright. Tokens are read the way
/// docker reads them (`--flag=value`, `--flag value`, and attached shorthand
/// such as `-v/:/host`), and bind-mount sources are extracted from both the
/// `-v SRC:DST` and `--mount type=bind,source=SRC` spellings, so how a host
/// mount is written does not decide whether it is caught. The tokens are
/// returned as written.
///
/// Multi-tenant: `app.infos` is tenant input and a denylist cannot keep up
/// with docker's surface. Only the allowlist in
/// `validate_tenant_docker_options` is accepted, and the returned tokens are
/// a sanitised rewrite (bind-mount sources canonicalised) rather than the
/// tenant's spelling; `site_dir` is the app's own directory, the only thing
/// its bind mounts may reference.
fn validate_docker_options(
    options: &str,
    multi_tenant: bool,
    site_dir: &Path,
) -> Result<Vec<String>> {
    if multi_tenant {
        return validate_tenant_docker_options(options, site_dir);
    }

    let tokens: Vec<&str> = options.split_whitespace().collect();

    // Flags that grant host access / capabilities outright — disallowed with
    // any value.
    const DENIED_FLAGS: &[&str] = &[
        "--privileged",
        "--cap-add",
        "--device",
        "--device-cgroup-rule",
        "--security-opt",
        "--userns",
        "--cgroupns",
        "--pid-mode",
        // Another container's mounts, an arbitrary host file as env source,
        // and supplementary host gids are host access by other names.
        "--volumes-from",
        "--env-file",
        "--group-add",
    ];
    // Namespace flags that are only dangerous when joined to the host or to
    // another container.
    const NS_FLAGS: &[&str] = &["--pid", "--ipc", "--uts", "--network", "--net"];

    for (i, token) in tokens.iter().enumerate() {
        if !token.starts_with('-') {
            continue;
        }
        let (flag, attached) = split_docker_flag(token)?;
        let flag = flag.to_ascii_lowercase();
        // Peek rather than consume: for a denylist it does not matter whether
        // the next token really is this flag's value, only that a dangerous
        // value is never overlooked.
        let value = attached.or_else(|| tokens.get(i + 1).copied());

        if DENIED_FLAGS.contains(&flag.as_str()) {
            anyhow::bail!("docker_options contains disallowed flag: {}", flag);
        }
        if NS_FLAGS.contains(&flag.as_str()) {
            let value = value.unwrap_or_default().to_ascii_lowercase();
            if value == "host" || value.starts_with("container:") {
                anyhow::bail!(
                    "docker_options joins the {} namespace of {}, which is disallowed",
                    flag,
                    value
                );
            }
        }
        let source = match flag.as_str() {
            "-v" | "--volume" => value.and_then(|v| v.split(':').next()),
            "--mount" => value.and_then(mount_source),
            _ => None,
        };
        if let Some(source) = source {
            if let Some(reason) = host_mount_denied(source) {
                anyhow::bail!(
                    "docker_options contains a disallowed host mount {:?}: {}",
                    source,
                    reason
                );
            }
        }
    }

    // Belt-and-braces: the docker socket must never appear anywhere, even in
    // a form the per-token parse above does not understand.
    if options.to_ascii_lowercase().contains("docker.sock") {
        anyhow::bail!("docker_options mounts the docker socket, which is disallowed");
    }

    Ok(tokens.iter().map(|t| t.to_string()).collect())
}

/// The `source=`/`src=` value of a `--mount` spec, if any.
fn mount_source(spec: &str) -> Option<&str> {
    spec.split(',').find_map(|pair| {
        let (key, val) = pair.split_once('=')?;
        matches!(key, "source" | "src").then_some(val)
    })
}

/// Why a single-tenant bind-mount source is refused: the host root or the
/// docker socket, in any spelling. The path is normalised textually (`//`,
/// `/./`, `..`, trailing `/`) and, when it exists, canonicalised, so `/./`,
/// `/etc/..` and a symlink to `/` are all caught. A relative source is a
/// named volume and carries no host path.
fn host_mount_denied(source: &str) -> Option<&'static str> {
    if !source.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in source.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let textual = PathBuf::from(format!("/{}", parts.join("/")));
    let resolved = std::fs::canonicalize(&textual).unwrap_or(textual);
    if resolved == Path::new("/") {
        return Some("the host root filesystem");
    }
    if resolved
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("docker.sock")
    {
        return Some("the docker socket");
    }
    None
}

/// `docker_network` goes straight to `docker run --network` (and to
/// `docker network create` when it does not exist yet), so it gets the same
/// treatment as the namespace flags in `docker_options`: joining the host
/// network or another container's is refused in every mode, and the name
/// must be one docker would accept as a network name so it cannot be read
/// as a flag or a namespace spec.
fn validate_docker_network(name: &str) -> Result<()> {
    let lower = name.to_ascii_lowercase();
    if lower == "host" || lower.starts_with("container:") {
        anyhow::bail!(
            "docker_network {:?} joins a foreign network namespace, which is disallowed",
            name
        );
    }
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid {
        anyhow::bail!(
            "docker_network {:?} is not a valid network name ([A-Za-z0-9][A-Za-z0-9_.-]*)",
            name
        );
    }
    Ok(())
}

/// Allowlist validation of tenant-supplied `docker_options`, returning the
/// argv tokens to pass — always as `flag value` pairs, with bind-mount
/// sources replaced by their canonical path (see
/// `validate_tenant_bind_source` for why the tenant's spelling is never
/// echoed).
///
/// Tokens are parsed exactly as `start_docker_instance` would have passed
/// them (whitespace-split, no shell), including docker's attached shorthand
/// (`-eK=V`, `-mN`, `--env=K=V`). Every flag is required to take a value, so
/// a bare or trailing flag is rejected outright: a value-taking flag in last
/// position would otherwise swallow the first mandatory hardening flag
/// (`--read-only`) as its argument. Everything not listed is rejected with
/// the offending token named.
fn validate_tenant_docker_options(options: &str, site_dir: &Path) -> Result<Vec<String>> {
    let tokens: Vec<&str> = options.split_whitespace().collect();

    // A flag in last position with no attached value (`--memory`, `--init`)
    // would take the next argv token — the first mandatory hardening flag —
    // as its value. `--env=K=V` / `-v/src:/dst` forms are complete tokens
    // and are fine; the loop below still checks their values.
    if let Some(last) = tokens.last() {
        if last.starts_with('-') && matches!(split_docker_flag(last), Ok((_, None))) {
            anyhow::bail!(
                "docker_options ends with flag {:?} without a value, which would consume the \
                 platform's hardening flags",
                last
            );
        }
    }

    let mut argv = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        let (flag, attached) = split_docker_flag(token)?;
        let value = match attached {
            Some(v) => v,
            None => {
                i += 1;
                match tokens.get(i) {
                    Some(v) if !v.starts_with('-') => *v,
                    _ => anyhow::bail!("docker_options flag {} is missing its value", flag),
                }
            }
        };
        i += 1;
        if value.is_empty() || value.starts_with('-') {
            anyhow::bail!("docker_options flag {} has invalid value {:?}", flag, value);
        }
        let value = validate_tenant_docker_flag(flag, value, site_dir)
            .with_context(|| format!("docker_options token {:?} rejected", token))?;
        argv.push(flag.to_string());
        argv.push(value);
    }

    Ok(argv)
}

/// Split one argv token into `(flag, attached value)`: `--env=K=V` gives
/// `("--env", Some("K=V"))`, `-eK=V` and `-e=K=V` give `("-e", Some("K=V"))`,
/// `-e` gives `("-e", None)`. A token that is not a flag is an error — a
/// value can only follow the flag that takes it.
fn split_docker_flag(token: &str) -> Result<(&str, Option<&str>)> {
    if let Some(rest) = token.strip_prefix("--") {
        if rest.is_empty() {
            anyhow::bail!("docker_options contains a bare `--`");
        }
        return Ok(match rest.split_once('=') {
            Some((name, value)) => (&token[..name.len() + 2], Some(value)),
            None => (token, None),
        });
    }
    if token.starts_with('-') && token.len() >= 2 {
        let (flag, rest) = token.split_at(2);
        let rest = rest.strip_prefix('=').unwrap_or(rest);
        return Ok((flag, (!rest.is_empty()).then_some(rest)));
    }
    anyhow::bail!(
        "docker_options contains unexpected token {:?} (expected a flag)",
        token
    )
}

/// The flags a tenant may pass, with per-flag value checks. Returns the
/// value to emit, which for bind mounts is a rewrite of the tenant's.
fn validate_tenant_docker_flag(flag: &str, value: &str, site_dir: &Path) -> Result<String> {
    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    // docker byte sizes: `512m`, `1g`, `1048576`.
    let is_size = |s: &str| {
        let digits = s.trim_end_matches(|c: char| "bkmgBKMG".contains(c));
        is_digits(digits) && s.len() - digits.len() <= 1
    };

    match flag {
        "-e" | "--env" => {
            let (key, _) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("env must be KEY=VALUE, got {:?}", value))?;
            let valid_key = key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid_key {
                anyhow::bail!("invalid environment variable name {:?}", key);
            }
        }
        "-m" | "--memory" | "--shm-size" => {
            if !is_size(value) {
                anyhow::bail!("invalid size {:?} for {}", value, flag);
            }
        }
        "--cpus" => {
            let (int, frac) = value.split_once('.').unwrap_or((value, "0"));
            if !is_digits(int) || !is_digits(frac) {
                anyhow::bail!("invalid value {:?} for --cpus", value);
            }
        }
        "--cpu-shares" | "--pids-limit" | "--stop-timeout" => {
            if !is_digits(value) {
                anyhow::bail!("invalid value {:?} for {}", value, flag);
            }
        }
        "-l" | "--label" => {}
        "--restart" => {
            let policy = value.split_once(':').map_or(value, |(p, _)| p);
            if !matches!(policy, "no" | "always" | "unless-stopped" | "on-failure") {
                anyhow::bail!("invalid restart policy {:?}", value);
            }
        }
        f if f.starts_with("--health-") => {}
        // The platform publishes the allocated slot port itself (see
        // `docker_run_args`); a tenant-chosen host port could sit on another
        // tenant's idle slot and answer its next health check.
        "-p" | "--publish" => anyhow::bail!(
            "docker_options may not publish ports in multi_tenant mode: the proxy publishes 127.0.0.1:$PORT for you"
        ),
        "-v" | "--volume" => return validate_tenant_volume(value, site_dir),
        "--mount" => return validate_tenant_mount(value, site_dir),
        other => anyhow::bail!(
            "docker_options flag {} is not allowed in multi_tenant mode",
            other
        ),
    }
    Ok(value.to_string())
}

/// A bind-mount source may only be the app's own site directory, and the
/// canonical path of that directory is what gets emitted.
///
/// Why exactly the site directory, and why not the tenant's spelling: the
/// check here and docker's own path resolution at mount time are two separate
/// walks. Everything *under* the site directory is writable by the tenant's
/// running container (the previous slot keeps serving during a blue/green
/// deploy), so a sub-path such as `<site>/data` could be a directory when
/// this check canonicalises it and a symlink to `/` a few milliseconds later
/// when `mount(2)` follows it. The site directory itself sits under the
/// operator-owned sites root, so no component of its canonical path can be
/// swapped out from inside a container. The source is still canonicalised
/// (symlinks, `/./`, `//`, `..`) before comparison and must exist.
fn validate_tenant_bind_source(source: &str, site_dir: &Path) -> Result<PathBuf> {
    if !source.starts_with('/') {
        anyhow::bail!(
            "bind mount source must be the absolute path of the app directory, got {:?}",
            source
        );
    }
    let site = std::fs::canonicalize(site_dir)
        .with_context(|| format!("cannot resolve app directory {}", site_dir.display()))?;
    let resolved = std::fs::canonicalize(source)
        .with_context(|| format!("bind mount source {:?} does not exist", source))?;
    if resolved != site {
        anyhow::bail!(
            "bind mount source {:?} resolves to {}; only the app directory itself ({}) may be \
             mounted",
            source,
            resolved.display(),
            site.display()
        );
    }
    Ok(site)
}

/// `-v SRC:DST[:ro|rw]`. Named and anonymous volumes (no absolute source)
/// are rejected along with propagation/relabel options. Returns the spec
/// with the canonical source.
fn validate_tenant_volume(value: &str, site_dir: &Path) -> Result<String> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        anyhow::bail!("volume must be SRC:DST[:ro|rw], got {:?}", value);
    }
    let source = validate_tenant_bind_source(parts[0], site_dir)?;
    if !parts[1].starts_with('/') {
        anyhow::bail!("volume target must be an absolute path, got {:?}", parts[1]);
    }
    let mut spec = format!("{}:{}", source.display(), parts[1]);
    if let Some(opts) = parts.get(2) {
        for opt in opts.split(',') {
            if !matches!(opt, "ro" | "rw") {
                anyhow::bail!("volume option {:?} is not allowed", opt);
            }
        }
        spec.push(':');
        spec.push_str(opts);
    }
    Ok(spec)
}

/// `--mount type=bind,source=SRC,target=DST[,readonly]`. Only bind mounts
/// of the site directory; `volume`/`tmpfs` types, propagation and driver
/// options are rejected. Returns a rebuilt spec with the canonical source.
fn validate_tenant_mount(value: &str, site_dir: &Path) -> Result<String> {
    let mut mount_type = None;
    let mut source = None;
    let mut target = None;
    let mut readonly = false;
    for pair in value.split(',') {
        let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "type" => mount_type = Some(val),
            "source" | "src" => source = Some(val),
            "target" | "dst" | "destination" => target = Some(val),
            "readonly" | "ro" => {
                readonly = match val {
                    "" | "true" | "1" => true,
                    "false" | "0" => false,
                    _ => anyhow::bail!("invalid mount option {:?}", pair),
                }
            }
            _ => anyhow::bail!("mount option {:?} is not allowed", pair),
        }
    }
    if mount_type != Some("bind") {
        anyhow::bail!("only type=bind mounts are allowed, got {:?}", value);
    }
    let source = source.ok_or_else(|| anyhow::anyhow!("mount {:?} has no source", value))?;
    let source = validate_tenant_bind_source(source, site_dir)?;
    let target = match target {
        Some(t) if t.starts_with('/') => t,
        _ => anyhow::bail!("mount {:?} needs an absolute target", value),
    };
    let mut spec = format!("type=bind,source={},target={}", source.display(), target);
    if readonly {
        spec.push_str(",readonly");
    }
    Ok(spec)
}

/// Validate `docker_image` against docker's image reference grammar:
/// `[host[:port]/]name(/name)*[:tag][@sha256:hex64]`, where a name component
/// is lowercase `[a-z0-9]` runs joined by `.`, `_`, `__` or one or more `-`.
///
/// The image sits in argv right where docker stops parsing flags, so a value
/// such as `--user=0:0` would be taken as a flag — overriding the mandatory
/// non-root uid — and the start script's first token would become the image.
/// `start_docker_instance` also emits `--` before the image; this check makes
/// the reference well-formed regardless.
fn validate_docker_image(image: &str) -> Result<()> {
    if image.is_empty() {
        anyhow::bail!("docker_image cannot be empty");
    }
    if image.starts_with('-') {
        anyhow::bail!(
            "docker_image {:?} looks like a flag, not an image reference",
            image
        );
    }

    let is_alnum_lower = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();

    let (name_and_tag, digest) = match image.rsplit_once('@') {
        Some((rest, digest)) => (rest, Some(digest)),
        None => (image, None),
    };
    if let Some(digest) = digest {
        let hex = digest.strip_prefix("sha256:").unwrap_or("");
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("docker_image {:?} has an invalid digest", image);
        }
    }

    // A `:` after the last `/` introduces the tag; before it, a registry port.
    let last_slash = name_and_tag.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match name_and_tag[last_slash..].split_once(':') {
        Some((_, tag)) => (
            &name_and_tag[..last_slash + name_and_tag[last_slash..].len() - tag.len() - 1],
            Some(tag),
        ),
        None => (name_and_tag, None),
    };
    if let Some(tag) = tag {
        let valid_tag = tag.len() <= 128
            && tag
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            && tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if !valid_tag {
            anyhow::bail!("docker_image {:?} has an invalid tag", image);
        }
    }

    let valid_component = |component: &str| {
        // Runs of [a-z0-9] joined by a single `.`, `_`, `__`, or `-`+.
        if component.is_empty()
            || !component.starts_with(is_alnum_lower)
            || !component.ends_with(is_alnum_lower)
        {
            return false;
        }
        let mut separator = String::new();
        for c in component.chars() {
            if is_alnum_lower(c) {
                if !(separator.is_empty()
                    || separator == "."
                    || separator == "_"
                    || separator == "__"
                    || separator.bytes().all(|b| b == b'-'))
                {
                    return false;
                }
                separator.clear();
            } else if matches!(c, '.' | '_' | '-') {
                separator.push(c);
            } else {
                return false;
            }
        }
        true
    };
    let valid_host = |host: &str| {
        let (labels, port) = match host.rsplit_once(':') {
            Some((labels, port)) => (labels, Some(port)),
            None => (host, None),
        };
        port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            && !labels.is_empty()
            && labels.split('.').all(|label| {
                !label.is_empty()
                    && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
    };

    let components: Vec<&str> = name.split('/').collect();
    for (i, component) in components.iter().enumerate() {
        let is_registry = i == 0 && components.len() > 1 && valid_host(component);
        if !is_registry && !valid_component(component) {
            anyhow::bail!(
                "docker_image {:?} is not a valid image reference (component {:?})",
                image,
                component
            );
        }
    }

    Ok(())
}

/// Rejects empty strings, path separators, "..", and control characters.
fn validate_path_component(name: &str, label: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{} cannot be empty", label);
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        anyhow::bail!("{} contains invalid path characters: {:?}", label, name);
    }
    if name == "." || name == ".." || name.contains("..") {
        anyhow::bail!("{} contains path traversal: {:?}", label, name);
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("{} contains control characters: {:?}", label, name);
    }
    Ok(())
}

async fn ensure_docker_network(network_name: &str) -> Result<()> {
    let output = tokio::process::Command::new("docker")
        .args(["network", "inspect", network_name])
        .output()
        .await?;

    if !output.status.success() {
        tracing::info!("Creating Docker network: {}", network_name);
        let output = tokio::process::Command::new("docker")
            .args(["network", "create", "--driver", "bridge", network_name])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Failed to create Docker network {}: {}",
                network_name,
                stderr
            );
        }
        tracing::info!("Docker network {} created", network_name);
    }

    Ok(())
}

/// Parse a start script into a program and arguments without using a shell.
/// Performs variable substitution for $PORT and $WORKERS.
/// This avoids shell injection by never passing the script through `sh -c`.
fn parse_start_command(script: &str, port: u16, workers: u16) -> Result<(String, Vec<String>)> {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    if tokens.is_empty() {
        anyhow::bail!("Start script is empty");
    }

    let port_str = port.to_string();
    let workers_str = workers.to_string();

    let program = tokens[0]
        .replace("$PORT", &port_str)
        .replace("$WORKERS", &workers_str);

    let args: Vec<String> = tokens[1..]
        .iter()
        .map(|t| {
            t.replace("$PORT", &port_str)
                .replace("$WORKERS", &workers_str)
        })
        .collect();

    Ok((program, args))
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeploymentStatus {
    Idle,
    Deploying,
    RollingBack,
    Failed(String),
}

pub struct DeploymentManager {
    /// Per-app deployment locks: contains app names currently being deployed
    deploying_apps: Arc<Mutex<HashSet<String>>>,
    /// PIDs that are being intentionally stopped (not unexpected exits)
    stopping_pids: Arc<Mutex<HashSet<u32>>>,
    /// PIDs that exited unexpectedly, mapped to a human-readable reason.
    /// Read by `wait_for_health` so it can bail out as soon as the process it
    /// is waiting on dies, instead of polling a dead port for 30s.
    exited_pids: Arc<Mutex<HashMap<u32, String>>>,
    /// Ports currently mapped to PIDs that we spawned (port -> pid).
    /// Used to verify we only kill processes we spawned, not unrelated listeners.
    spawned_pids: Arc<Mutex<HashMap<u16, u32>>>,
    /// Channel to notify AppManager of unexpected process exits
    process_exit_tx: mpsc::UnboundedSender<ProcessExit>,
    dev_mode: bool,
    http_client: reqwest::Client,
    default_user: Option<String>,
    default_group: Option<String>,
    /// Untrusted-tenant mode: require containers and impose hardening the app
    /// cannot weaken. See `AppsTomlConfig::multi_tenant`.
    multi_tenant: bool,
    /// Container flags appended after the app's own `docker_options`, so the
    /// platform's values win.
    mandatory_docker_args: Vec<String>,
}

impl DeploymentManager {
    pub fn new(
        dev_mode: bool,
        default_user: Option<String>,
        default_group: Option<String>,
        process_exit_tx: mpsc::UnboundedSender<ProcessExit>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            deploying_apps: Arc::new(Mutex::new(HashSet::new())),
            stopping_pids: Arc::new(Mutex::new(HashSet::new())),
            exited_pids: Arc::new(Mutex::new(HashMap::new())),
            spawned_pids: Arc::new(Mutex::new(HashMap::new())),
            process_exit_tx,
            dev_mode,
            http_client,
            default_user,
            default_group,
            multi_tenant: false,
            mandatory_docker_args: Vec::new(),
        }
    }

    /// Enable untrusted-tenant mode with the platform's mandatory container
    /// flags. Off by default, so existing single-tenant deployments are
    /// unaffected.
    pub fn with_tenant_isolation(mut self, enabled: bool, mandatory_args: Vec<String>) -> Self {
        self.multi_tenant = enabled;
        self.mandatory_docker_args = mandatory_args;
        self
    }

    pub fn is_deploying(&self, app_name: &str) -> bool {
        self.deploying_apps.lock().unwrap().contains(app_name)
    }

    async fn check_port_in_use(&self, port: u16) -> bool {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)).is_ok()
    }

    /// Mark an app as deploying (prevents concurrent deploys).
    /// Returns false if a deploy is already in progress.
    pub fn mark_deploying(&self, app_name: &str) -> bool {
        let mut deploying = self.deploying_apps.lock().unwrap();
        if deploying.contains(app_name) {
            return false;
        }
        deploying.insert(app_name.to_string());
        true
    }

    /// Unmark an app as deploying.
    pub fn unmark_deploying(&self, app_name: &str) {
        self.deploying_apps.lock().unwrap().remove(app_name);
    }

    /// Mark a PID as being intentionally stopped, so the process exit
    /// monitor ignores its death.
    pub fn mark_stopping(&self, pid: u32) {
        self.stopping_pids.lock().unwrap().insert(pid);
    }

    /// Deploy an app to a slot. Returns the PID of the started process.
    pub async fn deploy(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        {
            let mut deploying = self.deploying_apps.lock().unwrap();
            if deploying.contains(&app.config.name) {
                anyhow::bail!("Deployment already in progress for {}", app.config.name);
            }
            deploying.insert(app.config.name.clone());
        }

        let deploying_apps = self.deploying_apps.clone();
        let app_name = app.config.name.clone();
        let _guard = scopeguard::guard((), move |_| {
            deploying_apps.lock().unwrap().remove(&app_name);
        });

        tracing::info!(
            "Starting deployment of {} to slot {}",
            app.config.name,
            slot
        );

        let pid = self.start_instance(app, slot).await?;

        if let Err(e) = self.wait_for_health(app, slot, pid).await {
            self.stop_instance(app, slot).await?;
            return Err(e);
        }

        tracing::info!("Health check passed for {} slot {}", app.config.name, slot);
        Ok(pid)
    }

    pub async fn start_instance(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        validate_path_component(&app.config.name, "App name")?;

        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };

        if let Some(ref docker_image) = app.config.docker_image {
            return self
                .start_docker_instance(app, slot, port, docker_image)
                .await;
        }

        // Refuse to start untrusted code outside a container. The native path
        // gives a tenant process the host filesystem — every other tenant's
        // site directory, `certs/`, and `config.toml` with the admin API key —
        // so falling back to it under multi-tenant mode would silently undo the
        // isolation the mode exists to provide. Failing the deploy is the point.
        if self.multi_tenant {
            anyhow::bail!(
                "{} has no docker_image, and [apps] multi_tenant = true forbids the native \
                 start path: it does not isolate the app from the host filesystem or from \
                 other tenants",
                app.config.name
            );
        }

        self.start_native_instance(app, slot, port).await
    }

    async fn start_docker_instance(
        &self,
        app: &AppInfo,
        slot: &str,
        port: u16,
        docker_image: &str,
    ) -> Result<u32> {
        let container_name = format!("{}-{}", app.config.name, slot);

        let _ = self.stop_docker_container(&container_name).await;

        let base_script = if let Some(ref script) = app.config.start_script {
            script.clone()
        } else if app.path.join("app").exists() && app.path.join("app/models").exists() {
            "soli serve .".to_string()
        } else {
            anyhow::bail!("No start script configured for {}", app.config.name)
        };

        let script = if self.dev_mode && base_script.starts_with("soli ") {
            format!("{} --dev", base_script)
        } else {
            base_script.clone()
        };

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        let docker_network = app.config.docker_network.as_deref().unwrap_or("soli-apps");

        // Build (and thereby validate) the whole argv — image, options and
        // network name — before the daemon is touched, so a rejected manifest
        // cannot leave a tenant-named network behind.
        let docker_args = self.docker_run_args(
            app,
            &container_name,
            docker_network,
            port,
            docker_image,
            &script,
            &passthrough_env(DOCKER_PASSTHROUGH_ENV),
        )?;

        ensure_docker_network(docker_network).await?;

        tracing::info!(
            "Starting Docker container {} for {} slot {} with image {}",
            container_name,
            app.config.name,
            slot,
            docker_image
        );

        let output_text = tokio::process::Command::new("docker")
            .args(&docker_args)
            .current_dir(&app.path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("LANG", std::env::var("LANG").unwrap_or_default())
            .env("TZ", std::env::var("TZ").unwrap_or_default())
            .env("PORT", port.to_string())
            .env("WORKERS", app.config.workers.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::from(output))
            .output()
            .await?;

        if !output_text.status.success() {
            anyhow::bail!(
                "Docker run failed for {} slot {}: {}",
                app.config.name,
                slot,
                String::from_utf8_lossy(&output_text.stderr)
            );
        }

        let container_id = String::from_utf8_lossy(&output_text.stdout)
            .trim()
            .to_string();
        let pid = self.get_container_pid(&container_name).await?;

        tracing::info!(
            "Started Docker container {} ({} slot {}) with PID {}",
            container_id,
            app.config.name,
            slot,
            pid
        );

        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let container_id_for_monitoring = container_id.clone();
        let stopping_pids = self.stopping_pids.clone();
        let exited_pids = self.exited_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            let reason = loop {
                sleep(Duration::from_secs(5)).await;
                let status = tokio::process::Command::new("docker")
                    .args([
                        "inspect",
                        "-f",
                        "{{.State.Status}}",
                        &container_id_for_monitoring,
                    ])
                    .output()
                    .await;

                match status {
                    Ok(output) if output.status.success() => {
                        let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if status_str == "exited" || status_str == "dead" {
                            let reason = format!("container {}", status_str);
                            tracing::warn!(
                                "Container {} ({} slot {}) {}",
                                container_id_for_monitoring,
                                app_name,
                                slot_name,
                                reason
                            );
                            break reason;
                        }
                    }
                    Ok(_) | Err(_) => {
                        let reason = "container no longer exists".to_string();
                        tracing::warn!(
                            "Container {} ({} slot {}) {}",
                            container_id_for_monitoring,
                            app_name,
                            slot_name,
                            reason
                        );
                        break reason;
                    }
                }
            };
            // If intentional stop, skip notification
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            exited_pids.lock().unwrap().insert(pid, reason);
            let _ = exit_tx.send(ProcessExit {
                app_name,
                slot: slot_name,
                pid,
            });
        });

        Ok(pid)
    }

    /// Build the `docker run` argv. Pure (the environment to forward is
    /// passed in), so the flag ordering the isolation depends on can be
    /// asserted in tests without a docker daemon.
    #[allow(clippy::too_many_arguments)]
    fn docker_run_args(
        &self,
        app: &AppInfo,
        container_name: &str,
        docker_network: &str,
        port: u16,
        docker_image: &str,
        script: &str,
        passthrough: &[(String, String)],
    ) -> Result<Vec<String>> {
        validate_docker_image(docker_image)?;
        validate_docker_network(docker_network)?;

        let mut docker_args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            container_name.to_string(),
            "--network".to_string(),
            docker_network.to_string(),
        ];

        if let Some(ref options) = app.config.docker_options {
            // Individual argv tokens, never the whole string as one argument
            // (docker would read "-e FOO=bar" as a single invalid flag).
            // Whitespace-split, no quoting/escaping — and in multi-tenant
            // mode a sanitised rewrite rather than the tenant's own tokens.
            docker_args.extend(validate_docker_options(
                options,
                self.multi_tenant,
                &app.path,
            )?);
        }

        // Platform hardening goes last so it wins: `docker run` takes the final
        // occurrence of a repeated flag, so an app that sets its own --memory
        // or --user cannot raise its ceiling or become root.
        docker_args.extend(self.mandatory_docker_args.iter().cloned());

        // Tenants cannot publish ports themselves (docker_options is not
        // $PORT-substituted and a chosen host port could shadow another
        // tenant's slot), so expose the allocated slot port on loopback here.
        if self.multi_tenant {
            docker_args.push("-p".to_string());
            docker_args.push(format!("127.0.0.1:{port}:{port}"));
        }

        docker_args.push("-e".to_string());
        docker_args.push(format!("PORT={}", port));
        docker_args.push("-e".to_string());
        docker_args.push(format!("WORKERS={}", app.config.workers));

        if let Some(ref health_check) = app.config.health_check {
            docker_args.push("-e".to_string());
            docker_args.push(format!("HEALTH_CHECK={}", health_check));
        }

        // The egress / toolchain variables the native path lets through its
        // `env_clear()`, so a container behind a corporate proxy can make
        // outbound requests too. Setting them on the `docker` CLI process
        // would not do it — that is not the container's environment.
        for (key, value) in passthrough {
            docker_args.push("-e".to_string());
            docker_args.push(format!("{key}={value}"));
        }

        // End of flags: whatever follows is the image and its command, even if
        // the image reference (or a start_script token) begins with `-`. This
        // is what keeps a tenant's `docker_image = "--user=0:0"` from being
        // parsed as one more `docker run` flag after the mandatory ones.
        docker_args.push("--".to_string());
        docker_args.push(docker_image.to_string());

        // Never use a shell for the container command — same argv parsing as
        // the native spawn path, so a compromised start_script cannot inject
        // via `/bin/sh -c`.
        let (program, args) = parse_start_command(script, port, app.config.workers)?;
        docker_args.push(program);
        docker_args.extend(args);

        Ok(docker_args)
    }

    async fn get_container_pid(&self, container_name: &str) -> Result<u32> {
        let output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.State.Pid}}", container_name])
            .output()
            .await?;

        if !output.status.success() {
            anyhow::bail!("Failed to get PID for container {}", container_name);
        }

        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        pid_str
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("Invalid PID from docker inspect: {}", pid_str))
    }

    async fn stop_docker_container(&self, container_name: &str) -> Result<()> {
        let check_output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Id}}", container_name])
            .output()
            .await?;

        if check_output.status.success() {
            tracing::info!("Stopping existing container {}", container_name);
            let _ = tokio::process::Command::new("docker")
                .args(["stop", "-t", "30", container_name])
                .output()
                .await;
            let _ = tokio::process::Command::new("docker")
                .args(["rm", "-f", container_name])
                .output()
                .await;
        }
        Ok(())
    }

    async fn start_native_instance(&self, app: &AppInfo, slot: &str, port: u16) -> Result<u32> {
        if self.check_port_in_use(port).await {
            if let Some(orphan_pid) = super::find_pid_by_port(port) {
                let spawned_pid = self.spawned_pids.lock().unwrap().get(&port).copied();
                if orphan_pid <= 1 {
                    tracing::warn!(
                        "Rejecting unsafe PID {} on port {} for {} slot {}",
                        orphan_pid,
                        port,
                        app.config.name,
                        slot
                    );
                } else if orphan_pid != spawned_pid.unwrap_or(0) {
                    tracing::warn!(
                        "Port {} is in use by PID {} which was not spawned by the proxy. \
                         Refusing to kill it for {} slot {}",
                        port,
                        orphan_pid,
                        app.config.name,
                        slot
                    );
                } else {
                    tracing::warn!(
                        "Killing orphaned process {} on port {} before starting {} slot {}",
                        orphan_pid,
                        port,
                        app.config.name,
                        slot
                    );
                    self.stopping_pids.lock().unwrap().insert(orphan_pid);
                    let pgid = format!("-{}", orphan_pid);
                    let _ = tokio::process::Command::new("kill")
                        .arg("-TERM")
                        .arg("--")
                        .arg(&pgid)
                        .output()
                        .await;

                    for _ in 0..20 {
                        sleep(Duration::from_millis(100)).await;
                        if !self.check_port_in_use(port).await {
                            break;
                        }
                    }

                    let _ = tokio::process::Command::new("kill")
                        .arg("-9")
                        .arg("--")
                        .arg(&pgid)
                        .output()
                        .await;

                    for _ in 0..20 {
                        sleep(Duration::from_millis(100)).await;
                        let alive = tokio::process::Command::new("kill")
                            .arg("-0")
                            .arg("--")
                            .arg(&pgid)
                            .output()
                            .await
                            .map(|o| o.status.success())
                            .unwrap_or(false);
                        if !alive {
                            break;
                        }
                    }
                }
            }

            if self.check_port_in_use(port).await {
                anyhow::bail!(
                    "Port {} is already in use by another process. Cannot start {} slot {}",
                    port,
                    app.config.name,
                    slot
                );
            }
        }

        let base_script = if let Some(ref script) = app.config.start_script {
            script.clone()
        } else if app.path.join("app").exists() && app.path.join("app/models").exists() {
            "soli serve .".to_string()
        } else {
            anyhow::bail!("No start script configured for {}", app.config.name)
        };

        let script = if self.dev_mode && base_script.starts_with("soli ") {
            format!("{} --dev", base_script)
        } else {
            base_script.clone()
        };

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        let (program, args) = parse_start_command(&script, port, app.config.workers)?;

        let user = app.config.user.as_ref().or(self.default_user.as_ref());
        let group = app.config.group.as_ref().or(self.default_group.as_ref());

        // `HOME` must belong to the uid the child runs as, not to the proxy.
        // The proxy typically runs as root (HOME=/root) and drops privileges
        // below, so copying its own HOME pointed the app at a directory it
        // cannot read — breaking every `~`-resolved path soli uses, including
        // the pinned-interpreter cache.
        let home = match user {
            Some(user) => resolve_home(user)?,
            None => std::env::var("HOME").unwrap_or_default(),
        };

        let mut cmd = tokio::process::Command::new(&program);
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("LANG", std::env::var("LANG").unwrap_or_default())
            .env("TZ", std::env::var("TZ").unwrap_or_default())
            .env("PORT", port.to_string())
            .env("WORKERS", app.config.workers.to_string())
            .args(&args)
            .current_dir(&app.path)
            .stdout(std::process::Stdio::from(output.try_clone()?))
            .stderr(std::process::Stdio::from(output));

        // A cleared environment is the right default, but a handful of
        // variables have to survive it or the child cannot do its job:
        // a shared toolchain cache, an outbound proxy, a custom CA bundle.
        // Everything else stays cleared.
        for (key, value) in passthrough_env(PASSTHROUGH_ENV) {
            cmd.env(key, value);
        }

        #[cfg(unix)]
        let proxy_is_root = unsafe { libc::geteuid() } == 0;

        #[cfg(unix)]
        if proxy_is_root && user.is_none() {
            anyhow::bail!(
                "Refusing to spawn {} as root: no user/group configured. \
                 Set `user` in app.infos or default_user in [apps], or run the proxy as non-root.",
                app.config.name
            );
        }

        if let (Some(user), Some(group)) = (user, group) {
            let uid = resolve_user(user)?;
            let gid = resolve_group(group)?;
            cmd.uid(uid).gid(gid);
            tracing::info!(
                "Running {} as user {} (uid: {}, gid: {})",
                app.config.name,
                user,
                uid,
                gid
            );
        } else if let Some(user) = user {
            let uid = resolve_user(user)?;
            let gid = resolve_group(user)?;
            cmd.uid(uid).gid(gid);
            tracing::info!(
                "Running {} as user {} (uid: {}, gid: {})",
                app.config.name,
                user,
                uid,
                gid
            );
        }

        let run_as = match user {
            Some(user) => format!("as user `{}`", user),
            None => "as the proxy's own user".to_string(),
        };
        let mut child = unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                #[cfg(target_os = "linux")]
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                Ok(())
            })
            .spawn()
        }
        .with_context(|| {
            format!(
                "Failed to spawn `{}` for {} (in {}) {}. \
                 A `Permission denied` error usually means that user cannot execute the \
                 program or traverse the working directory — check file ownership/permissions \
                 (e.g. `ls -l {0}`) and that every parent directory is accessible to that user.",
                program,
                app.config.name,
                app.path.display(),
                run_as,
            )
        })?;

        let pid = child.id().unwrap_or(0);
        tracing::info!(
            "Started {} slot {} with PID {} using command: {} {:?}",
            app.config.name,
            slot,
            pid,
            program,
            args
        );
        tracing::info!("Full start command: {} {}", program, args.join(" "));

        if pid > 0 {
            self.spawned_pids.lock().unwrap().insert(port, pid);
        }

        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let stopping_pids = self.stopping_pids.clone();
        let exited_pids = self.exited_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            let reason = match child.wait().await {
                Ok(status) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        if let Some(signal) = status.signal() {
                            format!("killed by signal {}", signal)
                        } else if let Some(code) = status.code() {
                            format!("exited with status {}", code)
                        } else {
                            format!("exited ({})", status)
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        if let Some(code) = status.code() {
                            format!("exited with status {}", code)
                        } else {
                            format!("exited ({})", status)
                        }
                    }
                }
                Err(e) => format!("wait failed: {}", e),
            };
            tracing::warn!(
                "Process {} ({} slot {}) {}",
                pid,
                app_name,
                slot_name,
                reason
            );
            // If this was an intentional stop, just clean up the marker
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            // Unexpected exit — record reason so wait_for_health can surface
            // it, then notify AppManager for immediate failover
            exited_pids.lock().unwrap().insert(pid, reason);
            let _ = exit_tx.send(ProcessExit {
                app_name,
                slot: slot_name,
                pid,
            });
        });

        Ok(pid)
    }

    pub async fn stop_instance(&self, app: &AppInfo, slot: &str) -> Result<()> {
        if let Some(ref _docker_image) = app.config.docker_image {
            let container_name = format!("{}-{}", app.config.name, slot);
            return self.stop_docker_container(&container_name).await;
        }

        let pid = if slot == "blue" {
            app.blue.pid
        } else {
            app.green.pid
        };

        if let Some(pid) = pid {
            // Mark as intentional stop so the exit monitor ignores it
            self.stopping_pids.lock().unwrap().insert(pid);
            if slot == "blue" {
                self.spawned_pids.lock().unwrap().remove(&app.blue.port);
            } else {
                self.spawned_pids.lock().unwrap().remove(&app.green.port);
            }
            tracing::info!("Stopping {} slot {} (PID: {})", app.config.name, slot, pid);

            #[cfg(unix)]
            {
                let pgid = format!("-{}", pid);

                tokio::process::Command::new("kill")
                    .arg("-TERM")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await?;

                let timeout = app.config.graceful_timeout as u64;
                let mut waited_ms = 0u64;
                while waited_ms < timeout * 1000 {
                    let output = tokio::process::Command::new("kill")
                        .arg("-0")
                        .arg(pid.to_string())
                        .output()
                        .await?;

                    if !output.status.success() {
                        tracing::info!("Process {} terminated gracefully", pid);
                        return Ok(());
                    }
                    let delay = if waited_ms < 500 { 50 } else { 200 };
                    sleep(Duration::from_millis(delay)).await;
                    waited_ms += delay;
                }

                tracing::warn!("Force killing process group {}", pid);
                tokio::process::Command::new("kill")
                    .arg("-9")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn wait_for_health(&self, app: &AppInfo, slot: &str, pid: u32) -> Result<()> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        let health_path = app.config.health_check.as_deref().unwrap_or("/health");

        let url = format!("http://localhost:{}{}", port, health_path);
        let log_path = format!("run/logs/{}/{}.log", app.config.name, slot);
        let timeout_secs = 30;
        let mut last_err: Option<String> = None;

        for i in 0..timeout_secs {
            // Sleep between retries, but try immediately on the first attempt
            if i > 0 {
                sleep(Duration::from_secs(1)).await;
            }

            // Bail early if the process already died — no point polling a dead
            // port for the full 30s.
            if let Some(reason) = self.exited_pids.lock().unwrap().get(&pid).cloned() {
                anyhow::bail!(
                    "{} slot {} (PID {}) {} before becoming healthy on {} (see {} for app output)",
                    app.config.name,
                    slot,
                    pid,
                    reason,
                    url,
                    log_path,
                );
            }

            match self.http_client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "Health check passed for {} slot {} after {}s",
                        app.config.name,
                        slot,
                        i
                    );
                    return Ok(());
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::debug!(
                        "Health check response for {} slot {}: HTTP {} (attempt {})",
                        app.config.name,
                        slot,
                        status,
                        i + 1
                    );
                    last_err = Some(format!("HTTP {}", status));
                }
                Err(e) => {
                    tracing::debug!(
                        "Health check failed for {} slot {}: {} (attempt {})",
                        app.config.name,
                        slot,
                        e,
                        i + 1
                    );
                    last_err = Some(e.to_string());
                }
            }
        }

        anyhow::bail!(
            "{} slot {} did not become healthy on {} within {}s (last error: {}; see {} for app output)",
            app.config.name,
            slot,
            url,
            timeout_secs,
            last_err.as_deref().unwrap_or("none"),
            log_path,
        );
    }

    pub async fn switch_traffic(&self, app: &AppInfo, new_slot: &str) -> Result<()> {
        tracing::info!(
            "Switching traffic for {} to slot {}",
            app.config.name,
            new_slot
        );

        let old_slot = if new_slot == "blue" { "green" } else { "blue" };
        self.stop_instance(app, old_slot).await?;

        Ok(())
    }

    pub async fn rollback(&self, app: &AppInfo) -> Result<()> {
        let target_slot = if app.current_slot == "blue" {
            "green"
        } else {
            "blue"
        };
        self.deploy(app, target_slot).await?;
        Ok(())
    }

    pub async fn get_deployment_log(&self, app_name: &str, slot: &str) -> Result<String> {
        /// Cap admin log responses so a multi-GB log cannot OOM the proxy.
        const MAX_LOG_BYTES: u64 = 256 * 1024;

        validate_path_component(app_name, "App name")?;
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        let log_path = PathBuf::from(format!("run/logs/{}/{}.log", app_name, slot));
        if !log_path.exists() {
            return Ok(String::new());
        }
        let meta = std::fs::metadata(&log_path)?;
        let file = std::fs::File::open(&log_path)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut file = file;
        let mut buf = Vec::new();
        if meta.len() > MAX_LOG_BYTES {
            file.seek(SeekFrom::End(-(MAX_LOG_BYTES as i64)))?;
            // Drop a partial first line so the response starts cleanly.
            let mut skip = [0u8; 1];
            while file.read(&mut skip)? == 1 && skip[0] != b'\n' {}
            file.read_to_end(&mut buf)?;
        } else {
            file.read_to_end(&mut buf)?;
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

fn resolve_user(user: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_user = CString::new(user)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8 as libc::c_char; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // getpwnam_r is the thread-safe variant: the non-reentrant getpwnam
        // returns a pointer into a shared static buffer that a concurrent
        // lookup (here, or anywhere else in the process) can overwrite.
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if ret == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if ret != 0 {
            anyhow::bail!(
                "Failed to look up user '{}': {}",
                user,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        break;
    }
    if result.is_null() {
        anyhow::bail!("User '{}' not found", user);
    }
    Ok(pwd.pw_uid)
}

/// Environment variables that survive `env_clear()` when spawning an app.
///
/// The child gets a deliberately bare environment, but a few variables carry
/// information it cannot obtain any other way:
///
/// * `XDG_CACHE_HOME` — where a shared, pre-provisioned soli toolchain cache
///   lives, so a pinned app does not have to download its interpreter on a
///   server, and so several apps running as different users can share one.
/// * `SOLI_RELEASE_BASE_URL` — an internal mirror for those downloads.
/// * `SOLI_NO_PIN` — an operator override for the pin, e.g. during an incident.
/// * the proxy and CA variables — without them, any outbound HTTPS the app or
///   its toolchain fetch performs fails behind a corporate egress proxy, with
///   an error that names TLS rather than the missing configuration.
const PASSTHROUGH_ENV: &[&str] = &[
    "XDG_CACHE_HOME",
    "SOLI_RELEASE_BASE_URL",
    "SOLI_NO_PIN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The subset of `PASSTHROUGH_ENV` forwarded into a Docker container. The
/// entries that name a host path (`XDG_CACHE_HOME`, `SSL_CERT_FILE`,
/// `SSL_CERT_DIR`) are left out: the container has its own filesystem and a
/// cache directory or CA bundle it cannot see would only break the app's
/// own defaults.
const DOCKER_PASSTHROUGH_ENV: &[&str] = &[
    "SOLI_RELEASE_BASE_URL",
    "SOLI_NO_PIN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// The `(key, value)` pairs of `keys` that are set and non-empty on the proxy.
fn passthrough_env(keys: &[&str]) -> Vec<(String, String)> {
    keys.iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .filter(|v| !v.is_empty())
                .map(|v| (key.to_string(), v))
        })
        .collect()
}

/// The home directory of `user`, from the passwd database.
///
/// The proxy drops privileges to the app's user but used to hand the child its
/// *own* `HOME`. Under systemd that is `/root`, so anything the app resolves
/// through `~` pointed at a directory it cannot read or write: the soli package
/// cache (`~/.soli/packages`), the registry credentials, the Tailwind CLI
/// (`~/.soli/bin`), and the pinned-interpreter cache
/// (`~/.cache/soli/runtimes`). Giving the child the home that belongs to the
/// uid it runs as is what makes all of those work.
fn resolve_home(user: &str) -> Result<String> {
    use std::ffi::CString;
    let c_user = CString::new(user)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8 as libc::c_char; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // getpwnam_r, not getpwnam: see resolve_user.
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if ret == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if ret != 0 {
            anyhow::bail!(
                "Failed to look up home directory for '{}': {}",
                user,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        break;
    }
    if result.is_null() {
        anyhow::bail!("User '{}' not found", user);
    }
    if pwd.pw_dir.is_null() {
        anyhow::bail!("User '{}' has no home directory", user);
    }
    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Ok(home.to_string_lossy().into_owned())
}

fn resolve_group(group: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_group = CString::new(group)?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8 as libc::c_char; 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    loop {
        // getgrnam_r: thread-safe counterpart of getgrnam (see resolve_user).
        let ret = unsafe {
            libc::getgrnam_r(
                c_group.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if ret == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if ret != 0 {
            anyhow::bail!(
                "Failed to look up group '{}': {}",
                group,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        break;
    }
    if result.is_null() {
        anyhow::bail!("Group '{}' not found", group);
    }
    Ok(grp.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_start_command, resolve_home, validate_docker_image, validate_docker_network,
        validate_docker_options, validate_path_component, DeploymentManager,
        DOCKER_PASSTHROUGH_ENV, PASSTHROUGH_ENV,
    };
    use crate::app::{AppConfig, AppInfo, AppInstance, InstanceStatus};
    use std::path::Path;
    use tempfile::TempDir;

    /// Single-tenant validation has no site directory to compare against.
    fn validate_single_tenant(options: &str) -> anyhow::Result<Vec<String>> {
        validate_docker_options(options, false, Path::new("."))
    }

    fn validate_tenant(options: &str, site_dir: &Path) -> anyhow::Result<Vec<String>> {
        validate_docker_options(options, true, site_dir)
    }

    fn instance(slot: &str) -> AppInstance {
        AppInstance {
            name: "app.example.com".to_string(),
            slot: slot.to_string(),
            port: 0,
            pid: None,
            status: InstanceStatus::Stopped,
            last_started: None,
        }
    }

    fn tenant_app(path: &Path, docker_image: &str, docker_options: Option<&str>) -> AppInfo {
        AppInfo {
            config: AppConfig {
                name: "app.example.com".to_string(),
                domain: "app.example.com".to_string(),
                docker_image: Some(docker_image.to_string()),
                docker_options: docker_options.map(str::to_string),
                ..AppConfig::default()
            },
            path: path.to_path_buf(),
            blue: instance("blue"),
            green: instance("green"),
            current_slot: "blue".to_string(),
            quarantined: false,
        }
    }

    fn tenant_manager() -> DeploymentManager {
        let cfg = crate::config::AppsTomlConfig {
            multi_tenant: Some(true),
            ..Default::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        DeploymentManager::new(false, None, None, tx)
            .with_tenant_isolation(true, cfg.mandatory_docker_args())
    }

    /// The image reference is where `docker run` stops parsing flags, so it
    /// must be preceded by `--` — otherwise a tenant's `docker_image =
    /// "--user=0:0"` is one more flag after the mandatory `--user 10000:10000`
    /// and wins, and the start script's first token becomes the image.
    #[test]
    fn docker_image_cannot_inject_flags() {
        let site = TempDir::new().unwrap();
        let manager = tenant_manager();

        let app = tenant_app(site.path(), "nginx:1.27", None);
        let argv = manager
            .docker_run_args(
                &app,
                "app-blue",
                "soli-apps",
                8080,
                "nginx:1.27",
                "./serve",
                &[],
            )
            .unwrap();
        let image_at = argv.iter().position(|a| a == "nginx:1.27").unwrap();
        assert_eq!(argv[image_at - 1], "--");
        assert_eq!(argv[image_at + 1], "./serve");
        // Every flag, mandatory ones included, sits before the terminator.
        let dashdash = argv.iter().position(|a| a == "--").unwrap();
        let user_at = argv.iter().rposition(|a| a == "--user").unwrap();
        assert!(user_at < dashdash);
        // The platform, not the tenant, publishes the slot port on loopback.
        let publish_at = argv.iter().position(|a| a == "-p").unwrap();
        assert_eq!(argv[publish_at + 1], "127.0.0.1:8080:8080");
        assert!(publish_at < dashdash);

        let app = tenant_app(site.path(), "--user=0:0", None);
        let err = manager
            .docker_run_args(
                &app,
                "app-blue",
                "soli-apps",
                8080,
                "--user=0:0",
                "./serve",
                &[],
            )
            .unwrap_err();
        assert!(err.to_string().contains("docker_image"), "{}", err);
    }

    /// `docker_network` is tenant input that lands in `--network` unchecked
    /// by `docker_options` validation; `host` would put the container in the
    /// host network namespace next to the admin API and every other tenant's
    /// loopback slot port.
    #[test]
    fn docker_network_cannot_join_host_or_another_container() {
        assert!(validate_docker_network("soli-apps").is_ok());
        assert!(validate_docker_network("my_net.v2").is_ok());
        assert!(validate_docker_network("none").is_ok());
        for name in [
            "host",
            "HOST",
            "container:other",
            "",
            "-host",
            "--network=host",
            "a b",
            "a/b",
        ] {
            assert!(
                validate_docker_network(name).is_err(),
                "should reject {name:?}"
            );
        }

        let site = TempDir::new().unwrap();
        let manager = tenant_manager();
        let app = tenant_app(site.path(), "nginx:1.27", None);
        let err = manager
            .docker_run_args(&app, "app-blue", "host", 8080, "nginx:1.27", "./serve", &[])
            .unwrap_err();
        assert!(err.to_string().contains("docker_network"), "{err}");
    }

    /// The proxy-family variables reach the container as `-e` flags, before
    /// the `--` terminator; host-path entries of the native allowlist do not.
    #[test]
    fn docker_run_args_forwards_passthrough_env_into_the_container() {
        let site = TempDir::new().unwrap();
        let manager = tenant_manager();
        let app = tenant_app(site.path(), "nginx:1.27", None);
        let env = vec![("HTTPS_PROXY".to_string(), "http://egress:3128".to_string())];
        let argv = manager
            .docker_run_args(
                &app,
                "app-blue",
                "soli-apps",
                8080,
                "nginx:1.27",
                "./serve",
                &env,
            )
            .unwrap();
        let at = argv
            .iter()
            .position(|a| a == "HTTPS_PROXY=http://egress:3128")
            .expect("env forwarded");
        assert_eq!(argv[at - 1], "-e");
        assert!(at < argv.iter().position(|a| a == "--").unwrap());

        for key in DOCKER_PASSTHROUGH_ENV {
            assert!(
                PASSTHROUGH_ENV.contains(key),
                "{key} is not in the native list"
            );
        }
        for key in ["XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
            assert!(
                !DOCKER_PASSTHROUGH_ENV.contains(&key),
                "{key} names a host path"
            );
        }
    }

    #[test]
    fn docker_image_reference_grammar() {
        assert!(validate_docker_image("nginx:1.27").is_ok());
        assert!(validate_docker_image("nginx").is_ok());
        assert!(validate_docker_image("ghcr.io/org/app:v1").is_ok());
        assert!(validate_docker_image("my-org/my_app.web:latest").is_ok());
        assert!(
            validate_docker_image(&format!("registry:5000/a/b@sha256:{}", "ab".repeat(32))).is_ok()
        );
        assert!(validate_docker_image(&format!("nginx:1.27@sha256:{}", "0".repeat(64))).is_ok());

        assert!(validate_docker_image("--user=0:0").is_err());
        assert!(validate_docker_image("-v").is_err());
        assert!(validate_docker_image("").is_err());
        assert!(validate_docker_image("Nginx").is_err());
        assert!(validate_docker_image("nginx:").is_err());
        assert!(validate_docker_image("nginx:-tag").is_err());
        assert!(validate_docker_image("nginx@sha256:abc").is_err());
        assert!(validate_docker_image("a//b").is_err());
        assert!(validate_docker_image("a b").is_err());
        assert!(validate_docker_image("nginx..latest").is_err());
    }

    /// The hardening is a floor, not a default: it is appended after the app's
    /// own `docker_options`, and `docker run` honours the last occurrence of a
    /// repeated flag. A tenant that sets `--memory 64g --user 0:0` must still
    /// end up with the platform's ceiling and a non-root uid.
    #[test]
    fn mandatory_docker_args_override_app_supplied_ones() {
        let cfg = crate::config::AppsTomlConfig {
            multi_tenant: Some(true),
            tenant_memory: Some("256m".to_string()),
            tenant_cpus: Some("0.5".to_string()),
            ..Default::default()
        };

        let app_options = ["--memory", "64g", "--user", "0:0"];
        let mut argv: Vec<String> = app_options.iter().map(|s| s.to_string()).collect();
        argv.extend(cfg.mandatory_docker_args());

        let last_value = |flag: &str| -> Option<String> {
            argv.iter()
                .enumerate()
                .rfind(|(_, tok)| tok.as_str() == flag)
                .and_then(|(i, _)| argv.get(i + 1).cloned())
        };

        assert_eq!(last_value("--memory").as_deref(), Some("256m"));
        assert_eq!(last_value("--cpus").as_deref(), Some("0.5"));
        assert_eq!(last_value("--user").as_deref(), Some("10000:10000"));
        assert!(argv.iter().any(|a| a == "--read-only"));
        assert!(argv.iter().any(|a| a == "--cap-drop"));
        assert!(argv.iter().any(|a| a == "no-new-privileges"));
        assert!(argv.iter().any(|a| a == "--pids-limit"));
    }

    #[test]
    fn multi_tenant_defaults_off_so_existing_deployments_are_unchanged() {
        let cfg = crate::config::AppsTomlConfig::default();
        assert!(!cfg.multi_tenant());
    }

    #[test]
    fn docker_options_allows_benign_flags() {
        assert!(validate_single_tenant("-e FOO=bar --memory 512m").is_ok());
        assert!(validate_single_tenant("-v /srv/data:/data:ro").is_ok());
        assert!(validate_single_tenant("").is_ok());
    }

    #[test]
    fn docker_options_rejects_privileged_and_caps() {
        assert!(validate_single_tenant("--privileged").is_err());
        assert!(validate_single_tenant("--cap-add=NET_ADMIN").is_err());
        assert!(validate_single_tenant("--CAP-ADD SYS_ADMIN").is_err());
        assert!(validate_single_tenant("--device /dev/kmsg").is_err());
        assert!(validate_single_tenant("--security-opt seccomp=unconfined").is_err());
    }

    #[test]
    fn docker_options_rejects_host_namespaces_regardless_of_separator() {
        assert!(validate_single_tenant("--pid=host").is_err());
        assert!(validate_single_tenant("--pid host").is_err());
        assert!(validate_single_tenant("--pid HOST").is_err());
        assert!(validate_single_tenant("--pid container:other").is_err());
        assert!(validate_single_tenant("--network=host").is_err());
        assert!(validate_single_tenant("--net host").is_err());
        assert!(validate_single_tenant("--network container:other").is_err());
        assert!(validate_single_tenant("--ipc host").is_err());
        assert!(validate_single_tenant("--uts=host").is_err());
        // A user-defined network name (not "host") is fine.
        assert!(validate_single_tenant("--network my-net").is_ok());
    }

    #[test]
    fn docker_options_rejects_host_mounts() {
        assert!(validate_single_tenant("-v /:/host").is_err());
        assert!(
            validate_single_tenant("--volume /var/run/docker.sock:/var/run/docker.sock").is_err()
        );
        assert!(validate_single_tenant(
            "--mount type=bind,source=/var/run/docker.sock,target=/sock"
        )
        .is_err());
    }

    /// The single-tenant denylist is defense-in-depth, but it has to read
    /// docker's syntax the way docker does: attached shorthand, `--mount`
    /// key=value specs, alternate spellings of `/`, and the flags that hand
    /// over host resources without being a mount.
    #[test]
    fn docker_options_denylist_reads_every_spelling() {
        for options in [
            "-v/:/host",
            "-v=/:/host",
            "--volume=/:/host",
            "-v /./:/host",
            "-v //:/host",
            "-v /etc/..:/host",
            "-v /:/host:ro",
            "--mount type=bind,source=/,target=/host",
            "--mount=type=bind,src=/,dst=/host",
            "--mount type=bind,source=/var/run/docker.sock,target=/s",
            "-v /var/run/DOCKER.SOCK:/s",
            "--pid=container:x",
            "--volumes-from other",
            "--volumes-from=other",
            "--env-file /etc/passwd",
            "--group-add 0",
            "--device-cgroup-rule a",
            "-e FOO=bar --privileged",
        ] {
            assert!(
                validate_single_tenant(options).is_err(),
                "should reject {options:?}"
            );
        }
        // Ordinary host mounts and named volumes stay allowed, and the tokens
        // come back exactly as written.
        assert_eq!(
            validate_single_tenant("-v /srv/data:/data:ro -v named:/v").unwrap(),
            vec!["-v", "/srv/data:/data:ro", "-v", "named:/v"]
        );
        assert!(validate_single_tenant("--mount type=bind,source=/srv/x,target=/x").is_ok());
        assert!(validate_single_tenant("--init").is_ok());
    }

    /// Multi-tenant: the denylist is replaced by an allowlist. Every mount
    /// form that slipped past the denylist — `--mount` key=value syntax,
    /// attached shorthand, `/./` and `//` spellings, and plain non-root host
    /// paths — is rejected, as are namespace/volume flags it never covered.
    #[test]
    fn tenant_docker_options_rejects_mount_denylist_bypasses() {
        let site = TempDir::new().unwrap();
        let site = site.path();
        for options in [
            "--mount type=bind,source=/,target=/host",
            "--mount=type=bind,src=/etc,dst=/hetc",
            "-v/:/host",
            "-v /./:/host",
            "-v //:/host",
            "-v /etc:/hetc",
            "--volume=/etc:/hetc",
            "-v /var/run/docker.sock:/var/run/docker.sock",
            "--pid container:other",
            "--network container:other",
            "--volumes-from other",
            "--group-add 0",
            "--device-cgroup-rule a",
            "--userns host",
            "--privileged",
            "--env-file /etc/passwd",
            // Named / anonymous volumes have no source to pin to the site dir.
            "-v data:/data",
            "-v /data",
            // Publishing is the platform's job; any form is rejected.
            "-p 80:80",
            "-p 0.0.0.0:8080:80",
            "-p 127.0.0.1:8081:80",
            "--publish 127.0.0.1:8082:53/udp",
            // A value-taking flag in last position would swallow --read-only.
            "-e FOO=bar --memory",
            "-e FOO=bar --init",
            // Values that are themselves flags.
            "-e --privileged",
            "--label -v",
            "notaflag",
            "-e FOO=bar image",
        ] {
            assert!(
                validate_tenant(options, site).is_err(),
                "should reject {:?}",
                options
            );
        }
    }

    #[test]
    fn tenant_docker_options_allows_listed_flags() {
        let site = TempDir::new().unwrap();
        let site = site.path();
        for options in [
            "",
            "-e FOO=bar --env BAZ=qux -eATTACHED=1 --env=EQ=2",
            "-m 256m --memory 1g --cpus 0.5 --cpu-shares 512 --pids-limit 64 --shm-size 64m",
            "-l a=b --label c --restart unless-stopped --restart on-failure:3 --stop-timeout 5",
            "--health-cmd curl --health-interval 10s --health-retries 3",
        ] {
            assert!(
                validate_tenant(options, site).is_ok(),
                "should accept {:?}: {:?}",
                options,
                validate_tenant(options, site)
            );
        }
        // Attached and `=` forms are normalised to `flag value` pairs.
        assert_eq!(
            validate_tenant("-eATTACHED=1 --env=EQ=2 -m256m", site).unwrap(),
            vec!["-e", "ATTACHED=1", "--env", "EQ=2", "-m", "256m"]
        );
    }

    /// Bind mounts may only be of the tenant's own site directory, and the
    /// emitted source is its canonical path, never the tenant's spelling. A
    /// sub-path is rejected even though it is "inside": its components are
    /// writable by the tenant's running container, which could swap one for
    /// a symlink between this check and docker's own resolution at mount
    /// time. Sibling directories, symlinks out, and missing sources are
    /// rejected as before.
    #[test]
    fn tenant_docker_options_pins_bind_mounts_to_site_dir() {
        let sites = TempDir::new().unwrap();
        let mine = sites.path().join("mine.example.com");
        let other = sites.path().join("other.example.com");
        std::fs::create_dir_all(mine.join("data")).unwrap();
        std::fs::create_dir_all(other.join("data")).unwrap();
        std::os::unix::fs::symlink("/etc", mine.join("escape")).unwrap();
        // The operator's `sites/<name>` is routinely a symlink into a repo.
        std::os::unix::fs::symlink(&mine, sites.path().join("link.example.com")).unwrap();
        let link = sites.path().join("link.example.com");

        let canonical = std::fs::canonicalize(&mine).unwrap();
        let canonical = canonical.to_str().unwrap();
        let site = mine.to_str().unwrap();
        assert_eq!(
            validate_tenant(&format!("-v {}:/site", site), &mine).unwrap(),
            vec!["-v", &format!("{canonical}:/site")]
        );
        assert_eq!(
            validate_tenant(&format!("-v{}:/site:ro", site), &mine).unwrap(),
            vec!["-v", &format!("{canonical}:/site:ro")]
        );
        // Spellings that canonicalise to the site dir are accepted and
        // normalised away: `//`, `/./`, `data/..`, and the symlinked entry.
        assert_eq!(
            validate_tenant(&format!("-v {}/data/..//./:/site", site), &mine).unwrap(),
            vec!["-v", &format!("{canonical}:/site")]
        );
        assert_eq!(
            validate_tenant(&format!("-v {}:/site", link.display()), &mine).unwrap(),
            vec!["-v", &format!("{canonical}:/site")]
        );
        assert_eq!(
            validate_tenant(
                &format!("--mount type=bind,source={},target=/site,readonly", site),
                &mine
            )
            .unwrap(),
            vec![
                "--mount",
                &format!("type=bind,source={canonical},target=/site,readonly")
            ]
        );
        assert_eq!(
            validate_tenant(&format!("--mount type=bind,src={},dst=/site", site), &mine).unwrap(),
            vec![
                "--mount",
                &format!("type=bind,source={canonical},target=/site")
            ]
        );
        assert_eq!(
            validate_tenant(
                &format!("--mount type=bind,source={},target=/site,ro=false", site),
                &mine
            )
            .unwrap(),
            vec![
                "--mount",
                &format!("type=bind,source={canonical},target=/site")
            ]
        );

        // A sub-path of the site dir: inside, but racy.
        let data = mine.join("data");
        let data = data.to_str().unwrap();
        for options in [
            format!("-v {}:/data", data),
            format!("-v {}:/data:ro", data),
            format!("--mount type=bind,source={},target=/data,readonly", data),
        ] {
            let err = validate_tenant(&options, &mine).unwrap_err();
            assert!(
                format!("{err:#}").contains("only the app directory itself"),
                "{options}: {err:#}"
            );
        }

        let sibling = other.join("data");
        let sibling = sibling.to_str().unwrap();
        assert!(validate_tenant(&format!("-v {}:/data", sibling), &mine).is_err());
        assert!(validate_tenant(&format!("-v {}:/data", other.display()), &mine).is_err());
        assert!(validate_tenant(
            &format!("--mount type=bind,source={},target=/data", sibling),
            &mine
        )
        .is_err());
        // Path tricks that stay textually under the site dir.
        assert!(validate_tenant(&format!("-v {}/../other.example.com:/x", data), &mine).is_err());
        assert!(validate_tenant(&format!("-v {}/escape:/x", mine.display()), &mine).is_err());
        assert!(validate_tenant(&format!("-v {}/missing:/x", mine.display()), &mine).is_err());
        assert!(validate_tenant("-v /:/host", &mine).is_err());
        // Propagation / relabel options and non-bind mount types.
        assert!(validate_tenant(&format!("-v {}:/site:rshared", site), &mine).is_err());
        assert!(validate_tenant(
            &format!(
                "--mount type=bind,source={},target=/site,bind-propagation=rshared",
                site
            ),
            &mine
        )
        .is_err());
        assert!(validate_tenant("--mount type=tmpfs,target=/x", &mine).is_err());
        assert!(validate_tenant(&format!("--mount source={},target=/site", site), &mine).is_err());
    }

    #[test]
    fn start_command_substitutes_port_and_workers_without_shell() {
        let (program, args) =
            parse_start_command("./serve --port $PORT -w $WORKERS", 8080, 4).expect("parses");
        assert_eq!(program, "./serve");
        assert_eq!(args, vec!["--port", "8080", "-w", "4"]);
    }

    #[test]
    fn path_component_rejects_traversal() {
        assert!(validate_path_component("myapp", "App name").is_ok());
        assert!(validate_path_component("..", "App name").is_err());
        assert!(validate_path_component("a/b", "App name").is_err());
        assert!(validate_path_component("a\0b", "App name").is_err());
    }

    /// The child must get the home of the uid it runs as, not the proxy's.
    /// The proxy usually runs as root and drops privileges, so copying its own
    /// HOME pointed apps at `/root` — unreadable to them, and the reason every
    /// `~`-resolved soli path (package cache, credentials, Tailwind CLI, the
    /// pinned-interpreter cache) silently failed under the proxy.
    #[test]
    fn resolve_home_returns_the_users_own_directory() {
        // `root` exists on every system this runs on, and its home is not the
        // home of whoever runs the test suite.
        let home = resolve_home("root").expect("root must be resolvable");
        assert!(
            home.starts_with('/'),
            "a home directory must be absolute: {home}"
        );
        assert!(!home.is_empty());
    }

    #[test]
    fn resolve_home_reports_an_unknown_user() {
        let err = resolve_home("zz_no_such_user_zz")
            .expect_err("an unknown user must not silently yield a home");
        assert!(err.to_string().contains("not found"), "{err}");
    }

    /// The passthrough list is an allowlist: everything it does not name stays
    /// cleared. Assert the entries the pin depends on are present, and that no
    /// blanket wildcard crept in.
    #[test]
    fn passthrough_env_covers_the_toolchain_cache_and_egress() {
        for key in [
            "XDG_CACHE_HOME",
            "SOLI_RELEASE_BASE_URL",
            "SOLI_NO_PIN",
            "https_proxy",
            "SSL_CERT_FILE",
        ] {
            assert!(
                PASSTHROUGH_ENV.contains(&key),
                "{key} should survive env_clear()"
            );
        }
        // The guard variable is set by soli on itself; the proxy must never
        // forward one, or an app would refuse to honour its own pin.
        assert!(!PASSTHROUGH_ENV.contains(&"SOLI_PINNED_EXEC"));
    }
}
