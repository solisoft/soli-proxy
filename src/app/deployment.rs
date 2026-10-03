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
        // The proxy supervises the slot: it decides when a container runs,
        // stops it on deploy and failover, and restarts it through the health
        // monitor. A docker restart policy is a second supervisor that does
        // not know about blue/green — `always` brought "stopped" slots back
        // next to their replacements, each with its own memory ceiling.
        "--restart" => anyhow::bail!(
            "--restart is not allowed in multi_tenant mode: the proxy supervises the container"
        ),
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

/// Labels the proxy puts on the containers it starts; see `docker_run_args`.
const LABEL_APP: &str = "soli-proxy.app";
const LABEL_CONTAINER: &str = "soli-proxy.container";
const LABEL_PORT: &str = "soli-proxy.port";
const LABEL_LAUNCH: &str = "soli-proxy.launch";

/// `<app>-<slot>`, the container name a slot runs under.
fn container_name(app: &AppInfo, slot: &str) -> String {
    format!("{}-{}", app.config.name, slot)
}

/// A tenant's private network. App names are hostname characters, so this is
/// always a valid docker network name.
pub(crate) fn tenant_network_name(app_name: &str) -> String {
    format!("soli-app-{}", app_name)
}

/// The host-side bridge interface of a tenant network: `sl-` and 12 hex
/// digits of a stable hash of the app name (15 bytes, the kernel's limit).
/// A fixed prefix is what lets an operator firewall every tenant bridge with
/// one `iifname "sl-*"` rule instead of chasing docker's random `br-<id>`.
fn tenant_bridge_name(app_name: &str) -> String {
    // FNV-1a: stable across Rust versions, unlike `DefaultHasher`.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in app_name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("sl-{:012x}", hash & 0xffff_ffff_ffff)
}

/// `docker network create` arguments. `isolated_for` names the app when the
/// network is a tenant's private one: inter-container traffic off, a
/// predictable bridge name, and a label tying it back to the app.
fn network_create_args(network_name: &str, isolated_for: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["network", "create", "--driver", "bridge"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(app) = isolated_for {
        args.extend([
            "--opt".to_string(),
            "com.docker.network.bridge.enable_icc=false".to_string(),
            "--opt".to_string(),
            format!("com.docker.network.bridge.name={}", tenant_bridge_name(app)),
            "--label".to_string(),
            format!("soli-proxy.app={}", app),
        ]);
    }
    args.push(network_name.to_string());
    args
}

async fn ensure_docker_network(network_name: &str, isolated_for: Option<&str>) -> Result<()> {
    let output = tokio::process::Command::new("docker")
        .args(["network", "inspect", network_name])
        .output()
        .await?;

    if !output.status.success() {
        tracing::info!("Creating Docker network: {}", network_name);
        let output = tokio::process::Command::new("docker")
            .args(network_create_args(network_name, isolated_for))
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

/// Signal a whole process group: SIGTERM, up to `grace` for it to empty,
/// then SIGKILL. The group, not the leader, because a worker that outlives
/// its parent still holds the slot's port.
async fn kill_group(pgid: u32, grace: Duration) {
    // 0 and 1 would address our own group and init.
    let Ok(pgid) = i32::try_from(pgid) else {
        return;
    };
    if pgid < 2 {
        return;
    }
    // SAFETY: kill(2) with a negative pid signals that process group; no
    // memory is involved.
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + grace;
    while std::time::Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
        // Signal 0 probes: fails with ESRCH once no member is left.
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            return;
        }
    }
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

/// `(starttime, pgrp)` of a live process, from `/proc/<pid>/stat`.
///
/// The start time (field 22, clock ticks since boot) is what makes a PID an
/// identity: PIDs are reused, a PID plus its start time is not.
fn proc_identity(pid: u32) -> Option<(u64, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // `comm` is parenthesised and may itself contain `)`; fields restart
    // after the last one. `fields[0]` is field 3, so field N is `fields[N-3]`.
    let rest = stat.get(stat.rfind(')')? + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some((fields.get(19)?.parse().ok()?, fields.get(2)?.parse().ok()?))
}

/// One native process the proxy spawned.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct SpawnRecord {
    app: String,
    slot: String,
    port: u16,
    /// `/proc/<pid>/stat` starttime when it was spawned.
    start_time: u64,
    /// [`launch_fingerprint`] of how it was started: program, arguments,
    /// working directory, environment and user. A restarted proxy adopts the
    /// process only while it would still start it exactly this way.
    #[serde(default)]
    launch: Option<String>,
}

/// SHA-256 over the parts of a launch, NUL-separated: two launches with the
/// same fingerprint run the same command, as the same user, with the same
/// environment.
fn launch_fingerprint<S: AsRef<str>>(parts: impl IntoIterator<Item = S>) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part.as_ref().as_bytes());
        hasher.update([0u8]);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Whether `pid` is still the process that started at `start_time` (clock
/// ticks since boot) and has not exited. A zombie has exited: its PID stays
/// in `/proc` only until its parent — init, for an adopted process — reaps it.
fn is_alive_as(pid: u32, start_time: u64) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    let Some(rest) = stat.rfind(')').and_then(|at| stat.get(at + 2..)) else {
        return false;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields
        .first()
        .is_some_and(|state| *state != "Z" && *state != "X")
        && fields
            .get(19)
            .and_then(|start| start.parse::<u64>().ok())
            .is_some_and(|start| start == start_time)
}

/// Whether `pid` looks like an instance of an app started by a proxy older
/// than 1.0, which kept no spawn registry: the leader of its own session and
/// process group (every native app is started with `setsid()`), running as
/// `uid`, in the app's directory `app_dir`, with `program` as its executable.
///
/// Without this, the first start of 1.0 found every app a 0.35 proxy had left
/// running on its port, could not prove it was its own, refused to touch it —
/// correctly, for a stranger — and quarantined the app. These four facts
/// together are what a 0.35-started app has and a stranger holding the port
/// does not: a database or another service does not run from the app's own
/// site directory under the app's program. Linux only (`/proc`); elsewhere
/// nothing qualifies.
fn is_pre_registry_instance(pid: u32, app_dir: &Path, uid: u32, program: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
            return false;
        };
        let Some(rest) = stat.rfind(')').and_then(|at| stat.get(at + 2..)) else {
            return false;
        };
        // state, ppid, pgrp, session
        let fields: Vec<&str> = rest.split_whitespace().take(4).collect();
        let pid_s = pid.to_string();
        if fields.len() < 4
            || matches!(fields[0], "Z" | "X")
            || fields[2] != pid_s
            || fields[3] != pid_s
        {
            return false;
        }
        let real_uid = std::fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
            });
        if real_uid != Some(uid) {
            return false;
        }
        let same_dir = match (
            std::fs::read_link(format!("/proc/{}/cwd", pid)),
            std::fs::canonicalize(app_dir),
        ) {
            (Ok(cwd), Ok(dir)) => cwd == dir,
            _ => false,
        };
        if !same_dir {
            return false;
        }
        let argv0 = std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .and_then(|raw| {
                raw.split(|b| *b == 0)
                    .next()
                    .map(|a| String::from_utf8_lossy(a).into_owned())
            });
        let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
        argv0.is_some_and(|a| !a.is_empty() && base(&a) == base(program))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, app_dir, uid, program);
        false
    }
}

/// What a restarted proxy finds running in an app's slot.
#[derive(Debug, Clone, PartialEq)]
pub enum SlotOwnership {
    /// Nothing of ours runs there.
    Absent,
    /// A live instance this proxy started, launched exactly as it would be
    /// started now. `pid` is the process (native) or the container's init.
    Ours { pid: u32 },
    /// Ours, but not to be kept — it runs an old launch, on the wrong port,
    /// or does not serve its port. Stop it before starting afresh.
    Stale { pid: Option<u32>, reason: String },
    /// Something runs there that this proxy cannot prove it started. It is
    /// neither adopted nor touched.
    Unverifiable(String),
}

/// The native processes this proxy spawned, keyed by PID — persisted so a
/// restarted proxy still knows which leftovers are its own.
///
/// Every native process is started with `setsid()`, so its PID is also its
/// process-group id, and a group is what gets signalled. Before this, the
/// proxy decided what to kill by asking "who listens on this port?" — and at
/// startup it killed that process group without any ownership check at all.
/// Now a PID is signalled only when it (or the group it belongs to) is in
/// this registry with a matching start time.
pub(crate) struct SpawnRegistry {
    path: Option<PathBuf>,
    records: Mutex<HashMap<u32, SpawnRecord>>,
}

impl SpawnRegistry {
    fn in_memory() -> Self {
        Self {
            path: None,
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Load the registry a previous run left at `path`, keeping only the
    /// records whose process is still alive with the recorded start time: a
    /// dead PID may have been reused by anything since.
    fn load(path: PathBuf) -> Self {
        let records: HashMap<u32, SpawnRecord> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default();
        let loaded = records.len();
        let records: HashMap<u32, SpawnRecord> = records
            .into_iter()
            .filter(|(pid, record)| {
                proc_identity(*pid).is_some_and(|(start, _)| start == record.start_time)
            })
            .collect();
        let registry = Self {
            path: Some(path),
            records: Mutex::new(records),
        };
        if registry.records.lock().unwrap().len() != loaded {
            registry.persist();
        }
        registry
    }

    fn record(&self, pid: u32, app: &str, slot: &str, port: u16, launch: String) {
        let Some((start_time, _)) = proc_identity(pid) else {
            // Gone before we could look: nothing left to own.
            return;
        };
        self.records.lock().unwrap().insert(
            pid,
            SpawnRecord {
                app: app.to_string(),
                slot: slot.to_string(),
                port,
                start_time,
                launch: Some(launch),
            },
        );
        self.persist();
    }

    /// The live record for an app's slot, if any: `(pid, record)`.
    fn find(&self, app: &str, slot: &str) -> Option<(u32, SpawnRecord)> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|(pid, record)| {
                record.app == app && record.slot == slot && is_alive_as(**pid, record.start_time)
            })
            .map(|(pid, record)| (*pid, record.clone()))
    }

    /// Every recorded PID — for stopping everything this proxy started.
    fn pids(&self) -> Vec<u32> {
        self.records.lock().unwrap().keys().copied().collect()
    }

    fn forget(&self, pid: u32) {
        if self.records.lock().unwrap().remove(&pid).is_some() {
            self.persist();
        }
    }

    /// The process group to signal for `pid`, if it is ours: `pid` itself
    /// when we spawned it, or the group of one of our spawns when `pid` is a
    /// worker it forked (the process actually holding a port can be either).
    ///
    /// A recorded leader that has already exited still owns its group — that
    /// is the case of the exit monitor cleaning up surviving workers — while
    /// one whose PID now shows a different start time has been reused by a
    /// stranger and owns nothing.
    fn owned_group(&self, pid: u32) -> Option<u32> {
        let records = self.records.lock().unwrap();
        let owns = |leader: u32| {
            records.get(&leader).is_some_and(|record| {
                proc_identity(leader).is_none_or(|(start, _)| start == record.start_time)
            })
        };
        if owns(pid) {
            return Some(pid);
        }
        let (_, pgrp) = proc_identity(pid)?;
        owns(pgrp).then_some(pgrp)
    }

    fn persist(&self) {
        let Some(ref path) = self.path else {
            return;
        };
        let content = {
            let records = self.records.lock().unwrap();
            match serde_json::to_string_pretty(&*records) {
                Ok(content) => content,
                Err(e) => {
                    tracing::error!("Failed to serialize spawn registry: {}", e);
                    return;
                }
            }
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = crate::config::write_atomic(path, content.as_bytes()) {
            tracing::error!("Failed to write {}: {}", path.display(), e);
        }
    }
}

/// The egress variables gated by `[apps] tenant_proxy_env`.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Whether a URL-ish value carries `user[:password]@` in its authority —
/// with or without a scheme, since `user:pw@proxy:3128` is accepted by most
/// clients too.
fn carries_userinfo(value: &str) -> bool {
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

/// Multi-tenant filtering of the forwarded environment; see
/// `DeploymentManager::container_env`.
fn filter_tenant_env(
    pairs: Vec<(String, String)>,
    proxy_env: bool,
    credentials: bool,
) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .filter(|(key, value)| {
            if PROXY_ENV_KEYS.contains(&key.as_str()) && !proxy_env {
                return false;
            }
            if carries_userinfo(value) && !credentials {
                tracing::warn!(
                    "Not forwarding {} to tenant containers: it carries credentials \
                     ([apps] tenant_proxy_env_credentials is off)",
                    key
                );
                return false;
            }
            true
        })
        .collect()
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

/// A native slot's launch; see `DeploymentManager::native_launch`.
struct NativeLaunch {
    program: String,
    args: Vec<String>,
    /// The child's whole environment (it starts from an empty one).
    env: Vec<(String, String)>,
    user: Option<String>,
    /// uid and gid to switch to, when a user is configured.
    ids: Option<(u32, u32)>,
}

impl NativeLaunch {
    fn fingerprint(&self, cwd: &Path) -> String {
        let (uid, gid) = self.ids.unwrap_or((u32::MAX, u32::MAX));
        let mut parts = vec![
            self.program.clone(),
            cwd.display().to_string(),
            format!("uid={uid} gid={gid}"),
        ];
        parts.extend(self.args.iter().cloned());
        parts.extend(self.env.iter().map(|(k, v)| format!("{k}={v}")));
        launch_fingerprint(parts)
    }
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
    /// The processes this proxy spawned, persisted across restarts. The only
    /// authority for "may I signal this PID": see [`SpawnRegistry`].
    spawns: Arc<SpawnRegistry>,
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
    /// `[apps] tenant_proxy_env` / `tenant_proxy_env_credentials`: whether
    /// the proxy's egress variables reach tenant containers. Only consulted
    /// in multi_tenant mode.
    tenant_proxy_env: bool,
    tenant_proxy_env_credentials: bool,
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
            spawns: Arc::new(SpawnRegistry::in_memory()),
            process_exit_tx,
            dev_mode,
            http_client,
            default_user,
            default_group,
            multi_tenant: false,
            mandatory_docker_args: Vec::new(),
            tenant_proxy_env: false,
            tenant_proxy_env_credentials: false,
        }
    }

    /// Persist the spawn registry at `path` (loading what a previous run left
    /// there). Without it the registry lives in memory only — what tests and
    /// read-only tools want.
    pub fn with_spawn_registry(mut self, path: PathBuf) -> Self {
        self.spawns = Arc::new(SpawnRegistry::load(path));
        self
    }

    /// Opt tenant containers into the proxy's egress variables; see
    /// `AppsTomlConfig::tenant_proxy_env`.
    pub fn with_tenant_env(mut self, proxy_env: bool, credentials: bool) -> Self {
        self.tenant_proxy_env = proxy_env;
        self.tenant_proxy_env_credentials = credentials;
        self
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

    /// [`Self::mark_stopping`], for a process that still exists. A marker
    /// for one that is already gone is never consumed — no exit is coming to
    /// consume it — and would silence the crash of whatever later process is
    /// handed the same PID.
    fn mark_stopping_if_alive(&self, pid: u32) {
        if proc_identity(pid).is_some() {
            self.mark_stopping(pid);
        }
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
        let container_name = container_name(app, slot);

        let _ = self
            .stop_docker_container(&container_name, app.config.graceful_timeout)
            .await;

        // Build (and thereby validate) the whole argv — image, options and
        // network name — before the daemon is touched, so a rejected manifest
        // cannot leave a network behind.
        let (docker_args, docker_network) = self.docker_launch(app, slot, port, docker_image)?;

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        let isolated_for = self.multi_tenant.then_some(app.config.name.as_str());
        ensure_docker_network(&docker_network, isolated_for).await?;

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

        self.watch_container(&app.config.name, slot, container_id, pid);
        Ok(pid)
    }

    /// The command a slot runs, `--dev` added for a Soli app in dev mode.
    fn start_script_for(&self, app: &AppInfo) -> Result<String> {
        let base_script = if let Some(ref script) = app.config.start_script {
            script.clone()
        } else if app.path.join("app").exists() && app.path.join("app/models").exists() {
            "soli serve .".to_string()
        } else {
            anyhow::bail!("No start script configured for {}", app.config.name)
        };
        Ok(if self.dev_mode && base_script.starts_with("soli ") {
            format!("{} --dev", base_script)
        } else {
            base_script
        })
    }

    /// The `docker run` argv for a slot, and the network it joins. Pure but
    /// for reading the environment to pass through — so a restarted proxy
    /// recomputes exactly what it would run, and adopts a container only
    /// while that has not changed.
    fn docker_launch(
        &self,
        app: &AppInfo,
        slot: &str,
        port: u16,
        docker_image: &str,
    ) -> Result<(Vec<String>, String)> {
        let script = self.start_script_for(app)?;
        let docker_network = self.docker_network_for(app);
        let args = self.docker_run_args(
            app,
            &container_name(app, slot),
            &docker_network,
            port,
            docker_image,
            &script,
            &self.container_env(passthrough_env(DOCKER_PASSTHROUGH_ENV)),
        )?;
        Ok((args, docker_network))
    }

    /// Watch a container until it stops, then report the exit like a native
    /// process's — unless the stop was ours.
    fn watch_container(&self, app_name: &str, slot: &str, container_id: String, pid: u32) {
        let app_name = app_name.to_string();
        let slot_name = slot.to_string();
        let container_id_for_monitoring = container_id;
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
        let mut tail = vec!["--".to_string(), docker_image.to_string()];

        // Never use a shell for the container command — same argv parsing as
        // the native spawn path, so a compromised start_script cannot inject
        // via `/bin/sh -c`.
        let (program, args) = parse_start_command(script, port, app.config.workers)?;
        tail.push(program);
        tail.extend(args);

        // Ownership labels, last among the flags so an app's own `--label`
        // cannot override them. A restarted proxy adopts a running container
        // only when these name this app, this container and this port, and
        // `launch` — a digest of every other argument — says it would still
        // start it exactly this way.
        let launch = launch_fingerprint(docker_args.iter().chain(tail.iter()));
        for (key, value) in [
            (LABEL_APP, app.config.name.clone()),
            (LABEL_CONTAINER, container_name.to_string()),
            (LABEL_PORT, port.to_string()),
            (LABEL_LAUNCH, launch),
        ] {
            docker_args.push("--label".to_string());
            docker_args.push(format!("{key}={value}"));
        }
        docker_args.extend(tail);

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

    /// Stop and remove a container **by name**.
    ///
    /// Never by PID: the PID `docker inspect` reports is the container's init
    /// as seen from the host, and killing its process group leaves the
    /// container record behind with its restart policy intact — docker then
    /// brings the "stopped" slot straight back, next to the one that replaced
    /// it. `docker stop` + `docker rm -f` end it for good.
    async fn stop_docker_container(&self, container_name: &str, graceful_secs: u32) -> Result<()> {
        let check_output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Id}}", container_name])
            .output()
            .await?;

        if check_output.status.success() {
            tracing::info!("Stopping existing container {}", container_name);
            let _ = tokio::process::Command::new("docker")
                .args(["stop", "-t", &graceful_secs.to_string(), container_name])
                .output()
                .await;
            let _ = tokio::process::Command::new("docker")
                .args(["rm", "-f", container_name])
                .output()
                .await;
        }
        Ok(())
    }

    /// How a native slot is started: command, environment and user. Shared
    /// by the spawn and by adoption, which keeps a running process only while
    /// this has not changed.
    fn native_launch(&self, app: &AppInfo, port: u16) -> Result<NativeLaunch> {
        let script = self.start_script_for(app)?;
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

        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("HOME".into(), home),
            ("LANG".into(), std::env::var("LANG").unwrap_or_default()),
            ("TZ".into(), std::env::var("TZ").unwrap_or_default()),
            ("PORT".into(), port.to_string()),
            ("WORKERS".into(), app.config.workers.to_string()),
        ];
        // A cleared environment is the right default, but a handful of
        // variables have to survive it or the child cannot do its job:
        // a shared toolchain cache, an outbound proxy, a custom CA bundle.
        // Everything else stays cleared.
        env.extend(passthrough_env(PASSTHROUGH_ENV));

        let ids = match (user, group) {
            (Some(user), Some(group)) => Some((resolve_user(user)?, resolve_group(group)?)),
            (Some(user), None) => Some((resolve_user(user)?, resolve_group(user)?)),
            (None, _) => None,
        };

        Ok(NativeLaunch {
            program,
            args,
            env,
            user: user.cloned(),
            ids,
        })
    }

    async fn start_native_instance(&self, app: &AppInfo, slot: &str, port: u16) -> Result<u32> {
        if self.check_port_in_use(port).await {
            // Kills only a process group this proxy recorded spawning.
            self.reclaim_port(app, slot, port).await;
            for _ in 0..20 {
                if !self.check_port_in_use(port).await {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
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

        let launch = self.native_launch(app, port)?;
        let NativeLaunch {
            ref program,
            ref args,
            ref user,
            ..
        } = launch;

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        // stdout and stderr go straight to the slot's log file, never through
        // a pipe the proxy holds: an app outlives the proxy that started it
        // (see `[apps] stop_on_shutdown`), and a write to a pipe whose reader
        // has exited is a SIGPIPE. stdin is /dev/null for the same reason —
        // an inherited terminal is gone with the proxy too.
        let mut cmd = tokio::process::Command::new(program);
        cmd.env_clear()
            .envs(launch.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .args(args)
            .current_dir(&app.path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(output.try_clone()?))
            .stderr(std::process::Stdio::from(output));

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

        if let (Some(user), Some((uid, gid))) = (user, launch.ids) {
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
        // The child is the leader of its own session and process group, so
        // neither a terminal's ^C nor a signal to the proxy's group reaches
        // it; and nothing ties its life to the proxy's — no PR_SET_PDEATHSIG,
        // no `kill_on_drop`. That is what lets an app survive a proxy restart
        // (under systemd it also takes `KillMode=process`, see
        // scripts/soli-proxy.service). Stopping it is always explicit.
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
            self.spawns.record(
                pid,
                &app.config.name,
                slot,
                port,
                launch.fingerprint(&app.path),
            );
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
        if app.config.docker_image.is_some() {
            return self
                .stop_docker_container(&container_name(app, slot), app.config.graceful_timeout)
                .await;
        }

        let pid = if slot == "blue" {
            app.blue.pid
        } else {
            app.green.pid
        };

        if let Some(pid) = pid {
            tracing::info!("Stopping {} slot {} (PID: {})", app.config.name, slot, pid);
            let grace = Duration::from_secs(u64::from(app.config.graceful_timeout));
            self.terminate_native(app, slot, pid, grace).await;
        }

        Ok(())
    }

    /// Stop whatever runs a slot, by the means that owns it: `docker stop`
    /// for a container, a signal to the process group for a native process
    /// this proxy spawned — and nothing at all for a PID it has no record of.
    ///
    /// This is the one way deploy, failover and the exit monitor end a slot.
    pub async fn terminate(&self, app: &AppInfo, slot: &str, pid: u32) {
        if app.config.docker_image.is_some() {
            self.mark_stopping_if_alive(pid);
            let name = container_name(app, slot);
            if let Err(e) = self
                .stop_docker_container(&name, app.config.graceful_timeout)
                .await
            {
                tracing::warn!("Failed to stop container {}: {}", name, e);
            }
            return;
        }
        self.terminate_native(app, slot, pid, Duration::from_secs(2))
            .await;
    }

    async fn terminate_native(&self, app: &AppInfo, slot: &str, pid: u32, grace: Duration) {
        // Mark as intentional stop so the exit monitor ignores it
        self.mark_stopping_if_alive(pid);
        match self.spawns.owned_group(pid) {
            Some(group) => {
                kill_group(group, grace).await;
                self.spawns.forget(group);
            }
            None => tracing::warn!(
                "Not signalling PID {} ({} slot {}): this proxy has no record of spawning it",
                pid,
                app.config.name,
                slot
            ),
        }
    }

    /// Stop the process holding `port` if it is an instance of `app` started
    /// by a proxy older than 1.0 (see [`is_pre_registry_instance`]). Returns
    /// whether one was stopped.
    ///
    /// Native apps only, and never in multi-tenant mode, where native apps are
    /// refused and a port holder is never trusted on circumstantial evidence.
    pub async fn stop_pre_registry_instance(&self, app: &AppInfo, slot: &str, port: u16) -> bool {
        if self.multi_tenant || app.config.docker_image.is_some() || port == 0 {
            return false;
        }
        let Ok(launch) = self.native_launch(app, port) else {
            return false;
        };
        #[cfg(unix)]
        let own_uid = unsafe { libc::geteuid() };
        #[cfg(not(unix))]
        let own_uid = 0;
        let uid = launch.ids.map(|(uid, _)| uid).unwrap_or(own_uid);
        let dir = app.path.clone();
        let program = launch.program.clone();
        let found = tokio::task::spawn_blocking(move || {
            let pid = super::find_pid_by_port(port)?;
            is_pre_registry_instance(pid, &dir, uid, &program).then_some(pid)
        })
        .await
        .ok()
        .flatten();
        let Some(pid) = found else {
            return false;
        };
        tracing::warn!(
            "Stopping {} slot {} (PID {} on port {}): started by a proxy older than 1.0, which \
             kept no record of its apps; it is restarted under this one",
            app.config.name,
            slot,
            pid,
            port
        );
        self.mark_stopping(pid);
        kill_group(
            pid,
            Duration::from_secs(app.config.graceful_timeout.clamp(2, 10) as u64),
        )
        .await;
        true
    }

    /// Free `port` for `app`'s slot from a process left over by a previous
    /// run — if, and only if, this proxy spawned it (or a proxy older than
    /// 1.0 did, see [`Self::stop_pre_registry_instance`]).
    ///
    /// "Listens on the app's port" is not "belongs to the app": the port may
    /// be held by a database, another service, or a process squatting it on
    /// purpose, and the old code killed whichever it found, process group and
    /// all. A container slot is reclaimed by its name, `<app>-<slot>`, which
    /// only the proxy creates — never by whatever PID holds the port (for a
    /// published port that is docker's own proxy process, not the app).
    pub async fn reclaim_port(&self, app: &AppInfo, slot: &str, port: u16) {
        if app.config.docker_image.is_some() {
            let name = container_name(app, slot);
            if let Err(e) = self
                .stop_docker_container(&name, app.config.graceful_timeout)
                .await
            {
                tracing::warn!("Failed to stop leftover container {}: {}", name, e);
            }
            return;
        }
        let holder = tokio::task::spawn_blocking(move || super::find_pid_by_port(port))
            .await
            .ok()
            .flatten();
        let Some(pid) = holder else {
            return;
        };
        match self.spawns.owned_group(pid) {
            Some(group) => {
                tracing::warn!(
                    "Killing orphaned process group {} (PID {} on port {}) left by a previous \
                     run, before starting {} slot {}",
                    group,
                    pid,
                    port,
                    app.config.name,
                    slot
                );
                self.mark_stopping(pid);
                kill_group(group, Duration::from_secs(2)).await;
                self.spawns.forget(group);
            }
            None => {
                if !self.stop_pre_registry_instance(app, slot, port).await {
                    tracing::error!(
                        "Port {} for {} slot {} is held by PID {}, which this proxy did not \
                         spawn; leaving it alone",
                        port,
                        app.config.name,
                        slot,
                        pid
                    );
                }
            }
        }
    }

    /// Validate how `app` would be started, without starting anything: the
    /// whole `docker run` argv (image, options, network — the tenant rules in
    /// multi_tenant mode), or the native command and the user it runs as.
    /// For `soli-proxy check`.
    pub(crate) fn check_launch(&self, app: &AppInfo) -> Result<()> {
        let port = app.blue.port.max(1);
        if let Some(ref image) = app.config.docker_image {
            return self.docker_launch(app, "blue", port, image).map(|_| ());
        }
        if self.multi_tenant {
            anyhow::bail!(
                "no docker_image: [apps] multi_tenant = true forbids the native start path"
            );
        }
        self.native_launch(app, port).map(|_| ())
    }

    /// What runs in `app`'s `slot`, as far as this proxy can prove it: the
    /// first step of adopting what a previous proxy left running.
    ///
    /// Native: the spawn registry must hold a record for this app and slot
    /// whose PID is alive with the recorded start time (so not a reused PID),
    /// on the slot's current port, launched with today's exact command,
    /// environment and user; and the process listening on that port must be
    /// that PID or a member of its process group. Container: `<app>-<slot>`
    /// must be running and carry this proxy's labels for this app, container
    /// and port, with a launch digest equal to the `docker run` this proxy
    /// would issue now.
    ///
    /// Health is not judged here — that is the caller's next step.
    pub async fn verify_slot(&self, app: &AppInfo, slot: &str) -> SlotOwnership {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        if port == 0 {
            return SlotOwnership::Absent;
        }
        if let Some(ref image) = app.config.docker_image {
            return self.verify_container(app, slot, port, image).await;
        }
        if self.multi_tenant {
            return SlotOwnership::Absent;
        }

        let Some((pid, record)) = self.spawns.find(&app.config.name, slot) else {
            return SlotOwnership::Absent;
        };
        let stale = |reason: String| SlotOwnership::Stale {
            pid: Some(pid),
            reason,
        };
        if record.port != port {
            return stale(format!(
                "it listens on port {}, the slot now has {}",
                record.port, port
            ));
        }
        let expected = match self.native_launch(app, port) {
            Ok(launch) => launch.fingerprint(&app.path),
            Err(e) => return stale(format!("its launch cannot be recomputed: {:#}", e)),
        };
        if record.launch.as_deref() != Some(expected.as_str()) {
            return stale(
                "its command, environment or user changed since it was started".to_string(),
            );
        }
        let holder = tokio::task::spawn_blocking(move || super::find_pid_by_port(port))
            .await
            .ok()
            .flatten();
        match holder {
            Some(holder) if self.spawns.owned_group(holder) == Some(pid) => {
                SlotOwnership::Ours { pid }
            }
            Some(holder) => stale(format!(
                "port {} is held by PID {}, which is not part of it",
                port, holder
            )),
            None if !self.check_port_in_use(port).await => {
                stale(format!("it does not listen on port {}", port))
            }
            None => SlotOwnership::Unverifiable(format!(
                "cannot tell which process listens on port {} (no permission to inspect it?)",
                port
            )),
        }
    }

    async fn verify_container(
        &self,
        app: &AppInfo,
        slot: &str,
        port: u16,
        image: &str,
    ) -> SlotOwnership {
        let name = container_name(app, slot);
        let output = tokio::process::Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{json .State}}\n{{json .Config.Labels}}\n{{.Id}}",
                &name,
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .await;
        let output = match output {
            Ok(output) if output.status.success() => output,
            // No such container (or no docker): nothing to adopt.
            _ => return SlotOwnership::Absent,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut lines = text.lines();
        let state: serde_json::Value = lines
            .next()
            .and_then(|l| serde_json::from_str(l).ok())
            .unwrap_or_default();
        let labels: HashMap<String, String> = lines
            .next()
            .and_then(|l| serde_json::from_str::<Option<HashMap<String, String>>>(l).ok())
            .flatten()
            .unwrap_or_default();
        let id = lines.next().unwrap_or_default().trim().to_string();
        let pid = state["Pid"]
            .as_u64()
            .and_then(|p| u32::try_from(p).ok())
            .filter(|p| *p > 0);
        // The name is the proxy's own (`<app>-<slot>`, which `stop` and
        // `reclaim_port` already rely on), so anything below is a container
        // this proxy may replace — but adopt only one that proves itself.
        let stale = |reason: &str| SlotOwnership::Stale {
            pid,
            reason: format!("container {}: {}", name, reason),
        };
        if state["Running"].as_bool() != Some(true) {
            return stale("not running");
        }
        let label = |key: &str| labels.get(key).map(String::as_str);
        if label(LABEL_APP) != Some(app.config.name.as_str())
            || label(LABEL_CONTAINER) != Some(name.as_str())
        {
            return stale("not labelled as this app's (started by an older proxy?)");
        }
        if label(LABEL_PORT) != Some(port.to_string().as_str()) {
            return stale("labelled with another port");
        }
        let expected = match self.docker_launch(app, slot, port, image) {
            Ok((args, _)) => args
                .windows(2)
                .find(|w| w[0] == "--label" && w[1].starts_with(LABEL_LAUNCH))
                .and_then(|w| w[1].split_once('=').map(|(_, v)| v.to_string())),
            Err(_) => None,
        };
        if expected.is_none() || label(LABEL_LAUNCH) != expected.as_deref() {
            return stale("its image, options or environment changed since it was started");
        }
        match pid {
            Some(pid) if !id.is_empty() => SlotOwnership::Ours { pid },
            _ => stale("docker reports no process for it"),
        }
    }

    /// Supervise an instance adopted from a previous proxy as if this one had
    /// started it: an unexpected exit is reported like any other, so failover
    /// works the same.
    ///
    /// A container is watched by `docker inspect`, as always. A native
    /// process is not this proxy's child — it was reparented to init when its
    /// parent exited — so there is no `wait()`; its PID and start time are
    /// polled instead.
    pub fn watch_adopted(&self, app: &AppInfo, slot: &str, pid: u32) {
        if app.config.docker_image.is_some() {
            self.watch_container(&app.config.name, slot, container_name(app, slot), pid);
            return;
        }
        let Some((start_time, _)) = proc_identity(pid) else {
            return;
        };
        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let stopping_pids = self.stopping_pids.clone();
        let exited_pids = self.exited_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            while is_alive_as(pid, start_time) {
                sleep(Duration::from_secs(2)).await;
            }
            tracing::warn!(
                "Process {} ({} slot {}, adopted) exited",
                pid,
                app_name,
                slot_name
            );
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            exited_pids
                .lock()
                .unwrap()
                .insert(pid, "exited (adopted process; status unknown)".to_string());
            let _ = exit_tx.send(ProcessExit {
                app_name,
                slot: slot_name,
                pid,
            });
        });
    }

    /// The live PID this proxy recorded for an app's slot — what `stop` uses
    /// when the slot was started by a proxy that has since exited.
    pub fn recorded_pid(&self, app_name: &str, slot: &str) -> Option<u32> {
        self.spawns.find(app_name, slot).map(|(pid, _)| pid)
    }

    /// Stop every native process group this proxy (or a predecessor) recorded
    /// spawning and that is still alive. The last step of stopping
    /// everything: whatever the apps map no longer knows about.
    pub async fn stop_all_recorded(&self, grace: Duration) {
        for pid in self.spawns.pids() {
            if let Some(group) = self.spawns.owned_group(pid) {
                self.mark_stopping_if_alive(pid);
                kill_group(group, grace).await;
            }
            self.spawns.forget(pid);
        }
    }

    /// The network an app's containers join.
    ///
    /// Multi-tenant: a private one per app (`soli-app-<name>`), created with
    /// inter-container traffic disabled. A shared bridge put every tenant on
    /// one L2 segment with every other tenant's containers; the tenant's own
    /// `docker_network` is ignored, since it could name a shared or
    /// operator-owned network. Single-tenant: the app's choice, default
    /// `soli-apps`.
    fn docker_network_for(&self, app: &AppInfo) -> String {
        if self.multi_tenant {
            if let Some(ref requested) = app.config.docker_network {
                tracing::warn!(
                    "app.infos for {}: docker_network {:?} is ignored in multi_tenant mode",
                    app.config.name,
                    requested
                );
            }
            return tenant_network_name(&app.config.name);
        }
        app.config
            .docker_network
            .clone()
            .unwrap_or_else(|| "soli-apps".to_string())
    }

    /// Remove a deprovisioned tenant's private network. Best effort: a
    /// network still in use, or already gone, is left to the operator.
    pub async fn remove_app_network(&self, app_name: &str) {
        if !self.multi_tenant {
            return;
        }
        let network = tenant_network_name(app_name);
        match tokio::process::Command::new("docker")
            .args(["network", "rm", &network])
            .output()
            .await
        {
            Ok(out) if out.status.success() => tracing::info!("Removed Docker network {}", network),
            Ok(out) => tracing::debug!(
                "docker network rm {}: {}",
                network,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => tracing::debug!("docker network rm {}: {}", network, e),
        }
    }

    /// The proxy's passthrough environment as a container should see it.
    ///
    /// Multi-tenant: the egress variables are the operator's, and a proxy URL
    /// commonly carries `user:password@` — forwarded, it is one `env` away
    /// from every tenant. They are dropped unless `tenant_proxy_env` opts in,
    /// and any value carrying credentials is dropped unless
    /// `tenant_proxy_env_credentials` opts in as well.
    fn container_env(&self, pairs: Vec<(String, String)>) -> Vec<(String, String)> {
        if !self.multi_tenant {
            return pairs;
        }
        filter_tenant_env(
            pairs,
            self.tenant_proxy_env,
            self.tenant_proxy_env_credentials,
        )
    }

    pub async fn wait_for_health(&self, app: &AppInfo, slot: &str, pid: u32) -> Result<()> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        let health_path = app.config.health_check.as_deref().unwrap_or("/health");

        let url = format!("http://127.0.0.1:{}{}", port, health_path);
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
                    let reason = crate::upstream::retry::error_chain(&e);
                    tracing::debug!(
                        "Health check failed for {} slot {}: {} (attempt {})",
                        app.config.name,
                        slot,
                        reason,
                        i + 1
                    );
                    last_err = Some(reason);
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

    /// A process a 0.35 proxy left behind is recognised by what it is — its
    /// own session leader, our uid, the app's directory, the app's program —
    /// and anything differing in one of those is not.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pre_registry_instance_is_recognised_and_a_stranger_is_not() {
        use std::os::unix::process::CommandExt;
        let site = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        let mut leader = std::process::Command::new("sleep");
        leader.arg("30").current_dir(site.path());
        unsafe {
            leader.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut leader = leader.spawn().unwrap();
        let mut follower = std::process::Command::new("sleep")
            .arg("30")
            .current_dir(site.path())
            .spawn()
            .unwrap();
        let uid = unsafe { libc::geteuid() };
        let pid = leader.id();
        // Give the child time to exec, so /proc shows `sleep`, not the test.
        std::thread::sleep(Duration::from_millis(200));

        assert!(is_pre_registry_instance(pid, site.path(), uid, "sleep"));
        assert!(is_pre_registry_instance(
            pid,
            site.path(),
            uid,
            "/usr/bin/sleep"
        ));
        assert!(
            !is_pre_registry_instance(pid, elsewhere.path(), uid, "sleep"),
            "another directory"
        );
        assert!(
            !is_pre_registry_instance(pid, site.path(), uid, "soli"),
            "another program"
        );
        assert!(
            !is_pre_registry_instance(pid, site.path(), uid + 1, "sleep"),
            "another user"
        );
        assert!(
            !is_pre_registry_instance(follower.id(), site.path(), uid, "sleep"),
            "not the leader of its own session"
        );

        let _ = leader.kill();
        let _ = follower.kill();
        let _ = leader.wait();
        let _ = follower.wait();
    }

    use super::{
        carries_userinfo, filter_tenant_env, is_pre_registry_instance, network_create_args,
        parse_start_command, proc_identity, resolve_home, tenant_bridge_name,
        validate_docker_image, validate_docker_network, validate_docker_options,
        validate_path_component, DeploymentManager, SlotOwnership, SpawnRecord, SpawnRegistry,
        DOCKER_PASSTHROUGH_ENV, LABEL_APP, LABEL_CONTAINER, LABEL_LAUNCH, LABEL_PORT,
        PASSTHROUGH_ENV,
    };
    use crate::app::{AppConfig, AppInfo, AppInstance, InstanceStatus};
    use std::path::Path;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::time::sleep;

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
            maintenance: false,
            error_pages: None,
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
            // The proxy supervises the slot; a restart policy resurrected
            // slots it had stopped.
            "--restart always",
            "--restart=unless-stopped",
            "--restart on-failure:3",
            "--restart no",
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
            "-l a=b --label c --stop-timeout 5",
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

    /// Multi-tenant: every app gets its own network, whatever its manifest
    /// says, created with inter-container traffic off and a bridge name an
    /// operator's firewall can match.
    #[test]
    fn tenant_containers_get_a_private_network() {
        let site = TempDir::new().unwrap();
        let manager = tenant_manager();
        let mut app = tenant_app(site.path(), "nginx:1.27", None);
        assert_eq!(manager.docker_network_for(&app), "soli-app-app.example.com");
        app.config.docker_network = Some("soli-apps".to_string());
        assert_eq!(
            manager.docker_network_for(&app),
            "soli-app-app.example.com",
            "a tenant's docker_network must not choose a shared network"
        );
        assert!(validate_docker_network(&manager.docker_network_for(&app)).is_ok());

        let args = network_create_args("soli-app-app.example.com", Some("app.example.com"));
        assert!(args
            .iter()
            .any(|a| a == "com.docker.network.bridge.enable_icc=false"));
        assert_eq!(args.last().unwrap(), "soli-app-app.example.com");
        // Interface names are capped at 15 bytes by the kernel.
        let bridge = tenant_bridge_name("a-very-long-tenant-name.example.com");
        assert!(bridge.starts_with("sl-") && bridge.len() <= 15, "{bridge}");
        assert_eq!(
            bridge,
            tenant_bridge_name("a-very-long-tenant-name.example.com")
        );
        assert_ne!(bridge, tenant_bridge_name("another.example.com"));

        // Single-tenant keeps the manifest's network, default `soli-apps`.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let single = DeploymentManager::new(false, None, None, tx);
        assert_eq!(single.docker_network_for(&app), "soli-apps");
        app.config.docker_network = None;
        assert_eq!(single.docker_network_for(&app), "soli-apps");
        assert!(!network_create_args("soli-apps", None)
            .iter()
            .any(|a| a.contains("enable_icc")));
    }

    /// The operator's egress proxy is not the tenants': off unless opted in,
    /// and credentials only with a second opt-in.
    #[test]
    fn tenant_env_withholds_the_egress_proxy_and_credentials() {
        let env = || {
            vec![
                ("HTTPS_PROXY".to_string(), "http://egress:3128".to_string()),
                (
                    "http_proxy".to_string(),
                    "http://user:secret@egress:3128".to_string(),
                ),
                ("NO_PROXY".to_string(), "localhost".to_string()),
                (
                    "SOLI_RELEASE_BASE_URL".to_string(),
                    "https://mirror.internal/soli".to_string(),
                ),
            ]
        };
        let keys = |pairs: Vec<(String, String)>| -> Vec<String> {
            pairs.into_iter().map(|(k, _)| k).collect()
        };

        assert_eq!(
            keys(filter_tenant_env(env(), false, false)),
            ["SOLI_RELEASE_BASE_URL"]
        );
        assert_eq!(
            keys(filter_tenant_env(env(), true, false)),
            ["HTTPS_PROXY", "NO_PROXY", "SOLI_RELEASE_BASE_URL"]
        );
        assert_eq!(keys(filter_tenant_env(env(), true, true)).len(), 4);

        assert!(carries_userinfo("http://user:pw@proxy:3128"));
        assert!(carries_userinfo("user@proxy:3128"));
        assert!(!carries_userinfo("http://proxy:3128/path@x"));
        assert!(!carries_userinfo("http://proxy:3128"));
        assert!(!carries_userinfo("localhost,.internal"));
    }

    /// The single authority for "may I signal this PID": a process we
    /// spawned is ours; the test runner itself, an unknown PID, or a record
    /// whose start time no longer matches (a reused PID) is not.
    #[test]
    fn spawn_registry_owns_only_what_it_spawned() {
        use std::os::unix::process::CommandExt;
        let mut child = unsafe {
            std::process::Command::new("sleep")
                .arg("30")
                .pre_exec(|| {
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .unwrap()
        };
        let pid = child.id();

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("spawned.json");
        let registry = SpawnRegistry::load(path.clone());
        assert_eq!(registry.owned_group(pid), None, "not recorded yet");
        registry.record(pid, "app.example.com", "blue", 20000, "launch".into());
        assert_eq!(registry.owned_group(pid), Some(pid));
        assert_eq!(registry.owned_group(std::process::id()), None);

        // Survives a restart: a fresh registry reloads it from disk.
        let reloaded = SpawnRegistry::load(path.clone());
        assert_eq!(reloaded.owned_group(pid), Some(pid));

        // A record whose start time does not match is a reused PID.
        let (start, _) = proc_identity(pid).unwrap();
        reloaded.records.lock().unwrap().insert(
            pid,
            SpawnRecord {
                app: "app.example.com".to_string(),
                slot: "blue".to_string(),
                port: 20000,
                start_time: start + 1,
                launch: None,
            },
        );
        assert_eq!(reloaded.owned_group(pid), None);
        reloaded.persist();
        assert_eq!(
            SpawnRegistry::load(path).owned_group(pid),
            None,
            "a stale record is dropped on load"
        );

        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// The labels a restarted proxy adopts a container by: they name the app,
    /// the container and the port, and the launch digest is stable for the
    /// same launch and moves with anything that changes it.
    #[test]
    fn containers_are_labelled_with_their_launch() {
        let site = TempDir::new().unwrap();
        let manager = tenant_manager();
        let label = |argv: &[String], key: &str| -> Option<String> {
            argv.windows(2)
                .find(|w| w[0] == "--label" && w[1].starts_with(&format!("{key}=")))
                .map(|w| w[1][key.len() + 1..].to_string())
        };
        let args = |options: Option<&str>| {
            let app = tenant_app(site.path(), "nginx:1.27", options);
            manager
                .docker_run_args(
                    &app,
                    "app.example.com-blue",
                    "soli-app-app.example.com",
                    8080,
                    "nginx:1.27",
                    "nginx",
                    &[],
                )
                .unwrap()
        };
        let first = args(None);
        assert_eq!(label(&first, LABEL_APP).as_deref(), Some("app.example.com"));
        assert_eq!(
            label(&first, LABEL_CONTAINER).as_deref(),
            Some("app.example.com-blue")
        );
        assert_eq!(label(&first, LABEL_PORT).as_deref(), Some("8080"));
        // Labels are flags: before the `--` that ends them.
        let dashdash = first.iter().position(|a| a == "--").unwrap();
        assert!(first.iter().rposition(|a| a == "--label").unwrap() < dashdash);

        let launch = label(&first, LABEL_LAUNCH).unwrap();
        assert_eq!(label(&args(None), LABEL_LAUNCH).unwrap(), launch);
        assert_ne!(
            label(&args(Some("--env FOO=bar")), LABEL_LAUNCH).unwrap(),
            launch
        );
    }

    /// Adoption of a native slot: a process this proxy recorded, alive, on
    /// the slot's port and launched as it would be now, is `Ours`; the same
    /// process after the launch changed, or recorded for another port, is
    /// `Stale`; a slot with no record is `Absent`.
    #[tokio::test]
    async fn native_slots_are_adopted_only_when_provably_ours_and_unchanged() {
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("python3 not available; skipping");
            return;
        }
        let port = portpicker::pick_unused_port().expect("a free port");
        let site = TempDir::new().unwrap();
        let script = "python3 -m http.server $PORT --bind 127.0.0.1";
        let mut app = AppInfo {
            config: AppConfig {
                name: "native.example.com".to_string(),
                domain: "native.example.com".to_string(),
                start_script: Some(script.to_string()),
                ..AppConfig::default()
            },
            path: site.path().to_path_buf(),
            blue: instance("blue"),
            green: instance("green"),
            current_slot: "blue".to_string(),
            quarantined: false,
            maintenance: false,
            error_pages: None,
        };
        app.blue.port = port;

        let registry_dir = TempDir::new().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let manager = DeploymentManager::new(false, None, None, tx)
            .with_spawn_registry(registry_dir.path().join("spawned.json"));
        assert_eq!(
            manager.verify_slot(&app, "blue").await,
            SlotOwnership::Absent
        );

        // Started the way the proxy starts a slot: own session, the launch's
        // program, arguments and environment.
        let launch = manager.native_launch(&app, port).unwrap();
        let mut child = {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(&launch.program);
            cmd.args(&launch.args)
                .env_clear()
                .envs(launch.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .current_dir(site.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            cmd.spawn().unwrap()
        };
        let pid = child.id();
        for _ in 0..100 {
            if manager.check_port_in_use(port).await {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        manager.spawns.record(
            pid,
            &app.config.name,
            "blue",
            port,
            launch.fingerprint(&app.path),
        );

        // A fresh manager, as after a proxy restart: the registry is reloaded.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let restarted = DeploymentManager::new(false, None, None, tx)
            .with_spawn_registry(registry_dir.path().join("spawned.json"));
        assert_eq!(
            restarted.verify_slot(&app, "blue").await,
            SlotOwnership::Ours { pid }
        );
        assert_eq!(
            restarted.verify_slot(&app, "green").await,
            SlotOwnership::Absent
        );

        // The manifest changed since: not adopted, and marked for a stop.
        let mut changed = app.clone();
        changed.config.start_script = Some(format!("{script} --directory ."));
        assert!(matches!(
            restarted.verify_slot(&changed, "blue").await,
            SlotOwnership::Stale { pid: Some(p), .. } if p == pid
        ));
        // The slot's port moved (ports.lock reallocated it).
        let mut moved = app.clone();
        moved.blue.port = port.wrapping_add(1).max(1024);
        assert!(matches!(
            restarted.verify_slot(&moved, "blue").await,
            SlotOwnership::Stale { .. }
        ));

        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            restarted.verify_slot(&app, "blue").await,
            SlotOwnership::Absent,
            "a dead process is nobody's"
        );
    }
}
