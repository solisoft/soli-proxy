//! How the proxy talks to its upstreams: per-route options (`@retries`,
//! `@h2`, `@tls_*`, `@connect_timeout`, `@timeout`, `@health`), the
//! dedicated clients they need, retrying a failed attempt on another target,
//! and active health checks.
//!
//! The pieces:
//! - [`UpstreamOptions`] — what a rule's directives say, serialised with the
//!   rule (admin API JSON) and written back by the `proxy.conf` serializer;
//! - [`client`] — hyper clients for the option sets that cannot use the
//!   shared pool (HTTP/2, custom TLS, Unix sockets, another connect timeout),
//!   built once per distinct option set when the configuration loads and
//!   attached to the rule, so picking one per request is a field read;
//! - [`retry`] — the send loop that replays a request on the next target
//!   when that is safe;
//! - [`health`] — background probes that mark static targets up or down in
//!   the circuit breaker.

pub mod client;
pub mod health;
pub mod retry;
pub mod unix;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use url::Url;

pub use client::UpstreamClient;
pub use retry::{Attempt, RetryOn, SendError};

/// The most `@retries` / `[upstream] retries` may ask for. Each retry is a
/// different target, so more than a handful only makes a dead pool slower to
/// report itself.
pub const MAX_RETRIES: u32 = 10;

/// Upper bound for every duration directive: a day is far beyond any sane
/// timeout or probe interval, and keeps the millisecond arithmetic far from
/// overflowing.
const MAX_DURATION_MS: u64 = 24 * 60 * 60 * 1000;

/// Directives this module parses, as they appear after `@` in `proxy.conf`.
const DIRECTIVES: &[&str] = &[
    "retries",
    "connect_timeout",
    "timeout",
    "h2",
    "tls_ca",
    "tls_insecure",
    "tls_sni",
    "tls_client_cert",
    "health",
    "health_interval",
];

/// Whether `@kind` is one of this module's directives.
pub fn is_directive(kind: &str) -> bool {
    DIRECTIVES.contains(&kind)
}

/// Whether `@kind` is a flag, written without `:value`.
pub fn is_flag(kind: &str) -> bool {
    matches!(kind, "h2" | "tls_insecure")
}

/// Authority every `unix:` target is addressed under. A socket target has no
/// host of its own, and the request URI still needs one; `.invalid` is
/// reserved (RFC 6761) and never resolves, so the name can never reach DNS or
/// collide with a real backend. The client's own `Host` header is forwarded
/// untouched.
pub const UNIX_AUTHORITY: &str = "unix.invalid";

static UNIX_ROUTING_URL: LazyLock<Url> =
    LazyLock::new(|| Url::parse("http://unix.invalid/").expect("static URL parses"));

/// The URL a target's request URLs are built from: the target itself, except
/// for a `unix:` socket, whose path names the socket and not a request path —
/// requests to it are built on `http://unix.invalid/` and the socket's client
/// connects to the socket whatever the URI says.
pub fn routing_url(target: &Url) -> &Url {
    if target.scheme() == "unix" {
        &UNIX_ROUTING_URL
    } else {
        target
    }
}

/// Check a target URL whose scheme is one this module adds: `unix:` must be
/// an absolute socket path and nothing else, `h2c://` a host and port. Every
/// other scheme is left to the existing checks.
pub fn validate_target(url: &Url) -> Result<()> {
    let bad = match url.scheme() {
        "unix" => {
            let path = url.path();
            url.host().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !path.starts_with('/')
                || path.contains('\0')
                || path.contains('%')
                || path.split('/').any(|seg| seg == "..")
        }
        "h2c" => {
            url.host_str().is_none_or(str::is_empty)
                || !url.username().is_empty()
                || url.password().is_some()
        }
        _ => false,
    };
    if bad {
        bail!(
            "invalid target {:?} (expected unix:/absolute/path.sock — with no '..' segment, \
             percent-encoding, query or fragment — or h2c://host:port)",
            url.as_str()
        );
    }
    Ok(())
}

/// Parse `2s`, `500ms`, `3m` (or `1h`) into milliseconds. A unit is required:
/// a bare `30` would read as seconds to some and milliseconds to others.
pub fn parse_duration_ms(value: &str) -> Result<u64> {
    let value = value.trim();
    let (digits, factor) = if let Some(n) = value.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = value.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = value.strip_suffix('m') {
        (n, 60 * 1000)
    } else if let Some(n) = value.strip_suffix('h') {
        (n, 60 * 60 * 1000)
    } else {
        bail!(
            "invalid duration {:?} (expected a number with a unit: 500ms, 2s, 5m)",
            value
        );
    };
    let n: u64 = digits.parse().map_err(|_| {
        anyhow::anyhow!("invalid duration {:?} (expected e.g. 500ms, 2s, 5m)", value)
    })?;
    let ms = n.saturating_mul(factor);
    check_duration_ms(ms)?;
    Ok(ms)
}

fn check_duration_ms(ms: u64) -> Result<()> {
    if ms == 0 {
        bail!("a duration of zero is not allowed");
    }
    if ms > MAX_DURATION_MS {
        bail!("duration {}ms is longer than a day", ms);
    }
    Ok(())
}

/// The canonical spelling of a duration, as the serializer writes it back.
pub fn format_duration_ms(ms: u64) -> String {
    if ms.is_multiple_of(60 * 1000) {
        format!("{}m", ms / (60 * 1000))
    } else if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

/// A rule's upstream options: what its `@retries`, `@connect_timeout`,
/// `@timeout`, `@h2`, `@tls_*` and `@health*` directives say.
///
/// Serialised with the rule (only the options that are set), so a rule
/// fetched from the admin API and written back keeps them; `deny_unknown_fields`
/// like the rest of the rule.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamOptions {
    /// `@retries:N` — overrides `[upstream] retries` for this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// `@connect_timeout:2s` (default 5 s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// `@timeout:120s` — time to the response headers, overriding
    /// `[limits] request_timeout`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// `@h2` — speak HTTP/2 to this rule's targets: ALPN `h2` over TLS,
    /// prior knowledge over cleartext and Unix sockets.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub h2: bool,
    /// `@tls_ca:/path/ca.pem` — trust these CAs (instead of the public roots)
    /// for the rule's `https://` targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<String>,
    /// `@tls_insecure` — do not verify the upstream's certificate at all.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tls_insecure: bool,
    /// `@tls_sni:name` — the name sent as SNI and verified in the certificate,
    /// instead of the target's host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    /// `@tls_client_cert:/cert.pem,/key.pem` — client certificate for mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_key: Option<String>,
    /// `@health:/path` — probe each target at this path; `@health:off`
    /// exempts the rule from `[health_checks] default_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    /// `@health_interval:10s`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_interval_ms: Option<u64>,
    /// The clients this rule's targets need, built by [`prepare`] when the
    /// configuration loads. Never serialised; equal to anything, so it does
    /// not take part in comparing options.
    #[serde(skip)]
    runtime: Runtime,
}

/// The built side of [`UpstreamOptions`].
#[derive(Clone, Default)]
struct Runtime(Option<Arc<RuleClients>>);

impl PartialEq for Runtime {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "built" } else { "-" })
    }
}

/// The dedicated clients of one rule.
struct RuleClients {
    /// One entry per target, in rule order: the target's URL as configured
    /// (what the circuit breaker is keyed by), the client that reaches it
    /// (`None` for the shared pool), and its origin, for a Lua `on_route`
    /// override (see [`UpstreamOptions::client_for`]).
    targets: Vec<(String, Option<Arc<UpstreamClient>>, Option<Origin>)>,
}

/// Scheme, host and port: what decides whether a URL a hook substituted is
/// one of the rule's own upstreams. (`url::Origin` would not do: `h2c://` is
/// not a special scheme, so its origin is opaque and equal to nothing.)
type Origin = (String, String, Option<u16>);

fn origin_of(url: &str) -> Option<Origin> {
    let url = Url::parse(url).ok()?;
    Some((
        url.scheme().to_string(),
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default(),
    ))
}

impl UpstreamOptions {
    /// True when no directive is set — the rule serialises without them.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Apply one `@kind:value` directive from `proxy.conf`. Each may be given
    /// once per rule.
    pub fn apply_directive(&mut self, kind: &str, value: &str) -> Result<()> {
        fn once<T>(slot: &mut Option<T>, value: T, kind: &str) -> Result<()> {
            if slot.is_some() {
                bail!("@{} given more than once", kind);
            }
            *slot = Some(value);
            Ok(())
        }
        fn flag(slot: &mut bool, value: &str, kind: &str) -> Result<()> {
            if !value.is_empty() {
                bail!("@{} takes no value", kind);
            }
            if std::mem::replace(slot, true) {
                bail!("@{} given more than once", kind);
            }
            Ok(())
        }
        let duration =
            |value: &str| parse_duration_ms(value).with_context(|| format!("@{}:{}", kind, value));
        match kind {
            "retries" => {
                let n = value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n <= MAX_RETRIES)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "invalid @retries:{} (expected an integer from 0 to {})",
                            value,
                            MAX_RETRIES
                        )
                    })?;
                once(&mut self.retries, n, kind)
            }
            "connect_timeout" => once(&mut self.connect_timeout_ms, duration(value)?, kind),
            "timeout" => once(&mut self.timeout_ms, duration(value)?, kind),
            "health_interval" => once(&mut self.health_interval_ms, duration(value)?, kind),
            "h2" => flag(&mut self.h2, value, kind),
            "tls_insecure" => flag(&mut self.tls_insecure, value, kind),
            "tls_ca" => once(&mut self.tls_ca, value.to_string(), kind),
            "tls_sni" => once(&mut self.tls_sni, value.to_string(), kind),
            "tls_client_cert" => {
                let (cert, key) = value.split_once(',').ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid @tls_client_cert:{} (expected /path/cert.pem,/path/key.pem)",
                        value
                    )
                })?;
                once(&mut self.tls_client_key, key.trim().to_string(), kind)?;
                once(&mut self.tls_client_cert, cert.trim().to_string(), kind)
            }
            "health" => once(&mut self.health, value.to_string(), kind),
            other => bail!("@{} is not an upstream directive", other),
        }
    }

    /// The directives, as `proxy.conf` spells them (each with a leading
    /// space), for the serializer.
    pub fn directives(&self) -> String {
        let mut out = String::new();
        if let Some(n) = self.retries {
            out.push_str(&format!(" @retries:{}", n));
        }
        if let Some(ms) = self.connect_timeout_ms {
            out.push_str(&format!(" @connect_timeout:{}", format_duration_ms(ms)));
        }
        if let Some(ms) = self.timeout_ms {
            out.push_str(&format!(" @timeout:{}", format_duration_ms(ms)));
        }
        if self.h2 {
            out.push_str(" @h2");
        }
        if let Some(ca) = &self.tls_ca {
            out.push_str(&format!(" @tls_ca:{}", ca));
        }
        if self.tls_insecure {
            out.push_str(" @tls_insecure");
        }
        if let Some(sni) = &self.tls_sni {
            out.push_str(&format!(" @tls_sni:{}", sni));
        }
        if let (Some(cert), Some(key)) = (&self.tls_client_cert, &self.tls_client_key) {
            out.push_str(&format!(" @tls_client_cert:{},{}", cert, key));
        }
        if let Some(path) = &self.health {
            out.push_str(&format!(" @health:{}", path));
        }
        if let Some(ms) = self.health_interval_ms {
            out.push_str(&format!(" @health_interval:{}", format_duration_ms(ms)));
        }
        out
    }

    /// Everything that can be checked without touching the filesystem — run
    /// by the `.conf` parser and on rules arriving through the admin API.
    pub fn validate(&self, targets: &[crate::config::Target]) -> Result<()> {
        for target in targets {
            validate_target(&target.url)?;
        }
        if self.retries.is_some_and(|n| n > MAX_RETRIES) {
            bail!("retries must be at most {}", MAX_RETRIES);
        }
        for ms in [
            self.connect_timeout_ms,
            self.timeout_ms,
            self.health_interval_ms,
        ]
        .into_iter()
        .flatten()
        {
            check_duration_ms(ms)?;
        }
        let tls = self.tls_ca.is_some()
            || self.tls_insecure
            || self.tls_sni.is_some()
            || self.tls_client_cert.is_some()
            || self.tls_client_key.is_some();
        if tls && !targets.iter().any(|t| t.url.scheme() == "https") {
            bail!("@tls_* directives apply to https:// targets, and this rule has none");
        }
        if self.tls_insecure && self.tls_ca.is_some() {
            bail!("@tls_insecure and @tls_ca contradict each other: pick one");
        }
        // Paths are written back to proxy.conf verbatim, as one token (the
        // certificate and key as `cert,key`): no whitespace, no control
        // character — a `\n` arriving through the admin API's JSON would
        // inject a proxy.conf line — and no comma in the pair.
        for (what, path, also) in [
            ("@tls_ca", &self.tls_ca, &[][..]),
            ("@tls_client_cert", &self.tls_client_cert, &[','][..]),
            ("@tls_client_cert key", &self.tls_client_key, &[','][..]),
        ] {
            if let Some(path) = path {
                if !path.starts_with('/') {
                    bail!("{} path {:?} must be absolute", what, path);
                }
                crate::config::check_conf_token(what, path, also)?;
            }
        }
        if self.tls_client_cert.is_some() != self.tls_client_key.is_some() {
            bail!("a client certificate needs both its certificate and its key");
        }
        if let Some(name) = &self.tls_sni {
            crate::config::check_conf_token("@tls_sni", name, &[])?;
            rustls_pki_types::ServerName::try_from(name.as_str())
                .map_err(|_| anyhow::anyhow!("@tls_sni:{} is not a DNS name or IP", name))?;
        }
        if let Some(path) = &self.health {
            crate::config::check_conf_token("@health", path, &[])?;
            if path != "off" {
                validate_health_path(path)?;
            }
        }
        Ok(())
    }

    /// Build the dedicated clients the rule's targets need (none when every
    /// target can use the shared pool). Reads `@tls_ca` / `@tls_client_cert`
    /// files, so an unreadable or invalid one fails the load.
    fn resolve(&mut self, targets: &[crate::config::Target]) -> Result<()> {
        self.validate(targets)?;
        if self.tls_insecure {
            tracing::warn!(
                targets = %targets
                    .iter()
                    .map(|t| t.url.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                "@tls_insecure: upstream TLS certificates are NOT verified for this route — \
                 anyone on the path to it can read and alter the traffic"
            );
        }
        let base = client::ClientKey::for_options(self)?;
        let needs_tcp = !base.is_shared_default();
        let tcp = needs_tcp.then(|| client::get_or_build(&base)).transpose()?;
        let any_h2c = targets.iter().any(|t| t.url.scheme() == "h2c");
        let h2c = if any_h2c {
            Some(client::get_or_build(&base.with_h2())?)
        } else {
            None
        };
        let mut built = Vec::with_capacity(targets.len());
        let mut any = tcp.is_some();
        for target in targets {
            let client = match target.url.scheme() {
                "unix" => Some(client::get_or_build(
                    &base.with_unix(target.url.path().into()),
                )?),
                "h2c" => h2c.clone(),
                _ => tcp.clone(),
            };
            any |= client.is_some();
            built.push((
                target.url.as_str().to_string(),
                client,
                origin_of(target.url.as_str()),
            ));
        }
        self.runtime = Runtime(any.then(|| Arc::new(RuleClients { targets: built })));
        Ok(())
    }

    /// The client for one attempt: `base_url` is the configured target it
    /// came from (`None` after a Lua `on_route` override, when `target_url`
    /// alone decides), `None` meaning the shared pool.
    ///
    /// ⚠️ An override keeps the rule's client — its `@tls_ca`, client
    /// certificate, `@tls_sni`, `@tls_insecure`, `@h2`, connect timeout — only
    /// when it goes to one of the rule's own origins. Anywhere else it gets the
    /// shared pool (or the default h2c client): a script that sends a request
    /// to another host must not present the rule's mTLS certificate there, nor
    /// skip verification because the rule's own backend needed it.
    pub fn client_for(&self, base_url: Option<&str>, target_url: &str) -> Option<&UpstreamClient> {
        let h2c = target_url.starts_with("h2c://");
        let Some(rt) = &self.runtime.0 else {
            return h2c.then(client::default_h2c);
        };
        let own = match base_url {
            Some(base) => rt.targets.iter().find(|(url, _, _)| url == base),
            None => {
                let origin = origin_of(target_url);
                rt.targets
                    .iter()
                    .find(|(_, _, o)| o.is_some() && *o == origin)
            }
        };
        match own {
            Some((_, client, _)) => client
                .as_deref()
                .or_else(|| (base_url.is_none() && h2c).then(client::default_h2c)),
            None if base_url.is_none() && h2c => Some(client::default_h2c()),
            None => None,
        }
    }

    /// The client of the configured target `base_url`, `None` for the
    /// shared pool — for the health checks, which hold on to it.
    pub(crate) fn target_client(&self, base_url: &str) -> Option<Arc<UpstreamClient>> {
        self.runtime
            .0
            .as_ref()?
            .targets
            .iter()
            .find(|(url, _, _)| url == base_url)
            .and_then(|(_, c, _)| c.clone())
    }

    /// `@timeout`, if set.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout_ms.map(Duration::from_millis)
    }
}

/// A health path must be an absolute path (with an optional query) that can
/// go on a request line as is.
fn validate_health_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains('#')
        || path.parse::<http::uri::PathAndQuery>().is_err()
    {
        bail!(
            "invalid health check path {:?} (expected an absolute path such as /healthz, \
             or `off`)",
            path
        );
    }
    Ok(())
}

/// `[upstream]` in config.toml.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTomlConfig {
    pub retries: Option<u32>,
    pub retry_on: Option<Vec<String>>,
    pub try_duration: Option<String>,
}

/// `[health_checks]` in config.toml.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct HealthChecksTomlConfig {
    pub default_path: Option<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub unhealthy_threshold: Option<u32>,
    pub healthy_threshold: Option<u32>,
}

fn serialize_opt_duration<S: serde::Serializer>(
    d: &Option<Duration>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_some(&format_duration_ms(d.as_millis() as u64)),
        None => s.serialize_none(),
    }
}

fn serialize_duration<S: serde::Serializer>(
    d: &Duration,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&format_duration_ms(d.as_millis() as u64))
}

/// The resolved `[upstream]` section.
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamConfig {
    /// Extra attempts on another target after a failure that is safe to
    /// replay. Default 1.
    pub retries: u32,
    pub retry_on: RetryOn,
    /// Stop retrying once this long has passed since the first attempt.
    #[serde(serialize_with = "serialize_opt_duration")]
    pub try_duration: Option<Duration>,
    /// Whether any rule has `@timeout` — when none does, the request path
    /// never looks for one.
    #[serde(skip)]
    pub route_timeouts: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            retries: 1,
            retry_on: RetryOn::default(),
            try_duration: None,
            route_timeouts: false,
        }
    }
}

impl UpstreamConfig {
    pub fn from_toml(toml: Option<&UpstreamTomlConfig>) -> Result<Self> {
        let Some(t) = toml else {
            return Ok(Self::default());
        };
        let retries = t.retries.unwrap_or(1);
        if retries > MAX_RETRIES {
            bail!("[upstream] retries must be at most {}", MAX_RETRIES);
        }
        let retry_on = match &t.retry_on {
            Some(list) => RetryOn::parse(list).context("[upstream] retry_on")?,
            None => RetryOn::default(),
        };
        let try_duration = t
            .try_duration
            .as_deref()
            .map(parse_duration_ms)
            .transpose()
            .context("[upstream] try_duration")?
            .map(Duration::from_millis);
        Ok(Self {
            retries,
            retry_on,
            try_duration,
            route_timeouts: false,
        })
    }
}

/// The resolved `[health_checks]` section.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HealthChecksConfig {
    /// Probe every static target at this path unless its rule says
    /// `@health:off` (or names its own path). `None`: only rules with
    /// `@health:` are checked.
    pub default_path: Option<String>,
    #[serde(serialize_with = "serialize_duration")]
    pub interval: Duration,
    #[serde(serialize_with = "serialize_duration")]
    pub timeout: Duration,
    /// Consecutive failed probes before a target is taken out of rotation.
    pub unhealthy_threshold: u32,
    /// Consecutive successful probes before a target marked down is put back.
    pub healthy_threshold: u32,
}

impl Default for HealthChecksConfig {
    fn default() -> Self {
        Self {
            default_path: None,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

impl HealthChecksConfig {
    pub fn from_toml(toml: Option<&HealthChecksTomlConfig>) -> Result<Self> {
        let mut out = Self::default();
        let Some(t) = toml else {
            return Ok(out);
        };
        if let Some(path) = &t.default_path {
            validate_health_path(path).context("[health_checks] default_path")?;
            out.default_path = Some(path.clone());
        }
        if let Some(v) = &t.interval {
            out.interval =
                Duration::from_millis(parse_duration_ms(v).context("[health_checks] interval")?);
        }
        if let Some(v) = &t.timeout {
            out.timeout =
                Duration::from_millis(parse_duration_ms(v).context("[health_checks] timeout")?);
        }
        for (name, value, slot) in [
            (
                "unhealthy_threshold",
                t.unhealthy_threshold,
                &mut out.unhealthy_threshold,
            ),
            (
                "healthy_threshold",
                t.healthy_threshold,
                &mut out.healthy_threshold,
            ),
        ] {
            if let Some(n) = value {
                if n == 0 {
                    bail!("[health_checks] {} must be at least 1", name);
                }
                *slot = n;
            }
        }
        Ok(out)
    }
}

/// Build every rule's clients and the derived flags. Run on every
/// configuration the proxy is about to use: a load (startup or reload) and
/// a rule change through the admin API.
pub fn prepare(config: &mut crate::config::Config) -> Result<()> {
    let mut route_timeouts = false;
    for (i, rule) in config.rules.iter_mut().enumerate() {
        rule.upstream
            .resolve(&rule.targets)
            .with_context(|| format!("route #{} ({:?})", i + 1, rule.matcher))?;
        route_timeouts |= rule.upstream.timeout_ms.is_some();
    }
    config.upstream.route_timeouts = route_timeouts;
    Ok(())
}

/// The request timeout for a request routed by rule `rule` (`None`: no
/// rule matched), falling back to `[limits] request_timeout` (60 s).
pub fn request_timeout(config: &crate::config::Config, rule: Option<usize>) -> Duration {
    rule.and_then(|i| config.rules.get(i))
        .and_then(|r| r.upstream.timeout())
        .unwrap_or_else(|| Duration::from_secs(config.limits.request_timeout.unwrap_or(60)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> crate::config::Target {
        crate::config::Target {
            url: Url::parse(url).unwrap(),
            weight: 100,
        }
    }

    #[test]
    fn durations_need_a_unit_and_round_trip() {
        assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
        assert_eq!(parse_duration_ms("2s").unwrap(), 2000);
        assert_eq!(parse_duration_ms("5m").unwrap(), 300_000);
        assert_eq!(parse_duration_ms("1h").unwrap(), 3_600_000);
        assert!(parse_duration_ms("30").is_err());
        assert!(parse_duration_ms("0s").is_err());
        assert!(parse_duration_ms("-1s").is_err());
        assert!(parse_duration_ms("25h").is_err());
        assert!(parse_duration_ms("1.5s").is_err());
        for ms in [1, 500, 1500, 2000, 60_000, 90_000, 3_600_000] {
            assert_eq!(parse_duration_ms(&format_duration_ms(ms)).unwrap(), ms);
        }
    }

    #[test]
    fn directives_parse_once_and_round_trip() {
        let mut o = UpstreamOptions::default();
        for (k, v) in [
            ("retries", "2"),
            ("connect_timeout", "1500ms"),
            ("timeout", "2m"),
            ("h2", ""),
            ("tls_ca", "/etc/pki/ca.pem"),
            ("tls_sni", "internal.example"),
            ("tls_client_cert", "/etc/pki/c.pem,/etc/pki/k.pem"),
            ("health", "/healthz"),
            ("health_interval", "5s"),
        ] {
            o.apply_directive(k, v).unwrap();
        }
        assert!(o.apply_directive("retries", "1").is_err());
        assert!(o.apply_directive("h2", "").is_err());
        assert_eq!(
            o.directives(),
            " @retries:2 @connect_timeout:1500ms @timeout:2m @h2 @tls_ca:/etc/pki/ca.pem \
             @tls_sni:internal.example @tls_client_cert:/etc/pki/c.pem,/etc/pki/k.pem \
             @health:/healthz @health_interval:5s"
        );
        let mut again = UpstreamOptions::default();
        for token in o.directives().split_whitespace() {
            let d = token.strip_prefix('@').unwrap();
            let (k, v) = d.split_once(':').unwrap_or((d, ""));
            again.apply_directive(k, v).unwrap();
        }
        assert_eq!(again, o);
    }

    #[test]
    fn bad_directive_values_are_refused() {
        let mut o = UpstreamOptions::default();
        assert!(o.apply_directive("retries", "11").is_err());
        assert!(o.apply_directive("retries", "x").is_err());
        assert!(o.apply_directive("timeout", "10").is_err());
        assert!(o.apply_directive("h2", "yes").is_err());
        assert!(o
            .apply_directive("tls_client_cert", "/only-one.pem")
            .is_err());
    }

    /// Paths are written back verbatim: a control character or a trailing
    /// backslash (a line continuation) is refused by the parser too, and a
    /// comma in the certificate pair.
    #[test]
    fn directive_paths_must_survive_a_rewrite() {
        let https = [target("https://a.example")];
        for (kind, value) in [
            ("tls_ca", "/etc/ca\u{1}.pem"),
            ("tls_ca", "/etc/ca.pem\\"),
            ("tls_ca", "/etc/ca\u{7f}.pem"),
            ("tls_client_cert", "/c.pem,/k,2.pem"),
            ("health", "/up\u{1}"),
        ] {
            let mut o = UpstreamOptions::default();
            o.apply_directive(kind, value).unwrap();
            assert!(o.validate(&https).is_err(), "{kind}:{value:?}");
        }
        let line = "/x/* -> https://a.example @tls_ca:/etc/ca\u{1}.pem";
        assert!(crate::config::parse_proxy_config(line).is_err());
    }

    #[test]
    fn validation_ties_options_to_targets() {
        let https = [target("https://a.example")];
        let http = [target("http://a.example")];
        let mut o = UpstreamOptions {
            tls_ca: Some("/ca.pem".into()),
            ..Default::default()
        };
        assert!(o.validate(&https).is_ok());
        assert!(
            o.validate(&http).is_err(),
            "TLS options without an https target"
        );
        o.tls_insecure = true;
        assert!(o.validate(&https).is_err(), "insecure and a CA contradict");
        let o = UpstreamOptions {
            tls_ca: Some("relative/ca.pem".into()),
            ..Default::default()
        };
        assert!(o.validate(&https).is_err());
        let o = UpstreamOptions {
            tls_client_cert: Some("/c.pem".into()),
            ..Default::default()
        };
        assert!(o.validate(&https).is_err(), "a certificate without its key");
        let o = UpstreamOptions {
            tls_sni: Some("not a name".into()),
            ..Default::default()
        };
        assert!(o.validate(&https).is_err());
        for bad in ["healthz", "/a b", "/x#frag"] {
            let o = UpstreamOptions {
                health: Some(bad.into()),
                ..Default::default()
            };
            assert!(o.validate(&http).is_err(), "{bad}");
        }
        let o = UpstreamOptions {
            health: Some("/healthz?full=1".into()),
            ..Default::default()
        };
        assert!(o.validate(&http).is_ok());
    }

    #[test]
    fn unix_and_h2c_targets_are_checked() {
        assert!(validate_target(&Url::parse("unix:/run/app.sock").unwrap()).is_ok());
        // Dot segments are resolved by the URL parser before anyone sees them.
        let dotted = Url::parse("unix:/run/../etc/app.sock").unwrap();
        assert_eq!(dotted.path(), "/etc/app.sock");
        for bad in [
            "unix:run/app.sock",
            "unix:/run/app.sock?x=1",
            "unix:/run/a%20b.sock",
            "unix://host/run/app.sock",
        ] {
            assert!(validate_target(&Url::parse(bad).unwrap()).is_err(), "{bad}");
        }
        assert!(validate_target(&Url::parse("h2c://grpc:50051").unwrap()).is_ok());
        assert!(validate_target(&Url::parse("h2c://user@grpc:50051").unwrap()).is_err());
    }

    #[test]
    fn unix_targets_route_on_a_placeholder_authority() {
        let sock = Url::parse("unix:/run/app.sock").unwrap();
        assert_eq!(routing_url(&sock).as_str(), "http://unix.invalid/");
        let http = Url::parse("http://a:1/x").unwrap();
        assert_eq!(routing_url(&http).as_str(), "http://a:1/x");
    }

    #[test]
    fn upstream_section_defaults_and_validation() {
        let d = UpstreamConfig::from_toml(None).unwrap();
        assert_eq!(d.retries, 1);
        assert!(d.retry_on.connect && d.retry_on.error && d.retry_on.statuses.is_empty());
        let t: UpstreamTomlConfig = toml::from_str(
            "retries = 2\nretry_on = [\"connect\", \"503\"]\ntry_duration = \"3s\"\n",
        )
        .unwrap();
        let c = UpstreamConfig::from_toml(Some(&t)).unwrap();
        assert_eq!(c.retries, 2);
        assert!(c.retry_on.connect && !c.retry_on.error);
        assert_eq!(c.retry_on.statuses, vec![503]);
        assert_eq!(c.try_duration, Some(Duration::from_secs(3)));
        for bad in [
            "retries = 11\n",
            "retry_on = [\"teapot\"]\n",
            "retry_on = [\"404\"]\n",
            "try_duration = \"3\"\n",
        ] {
            let t: UpstreamTomlConfig = toml::from_str(bad).unwrap();
            assert!(UpstreamConfig::from_toml(Some(&t)).is_err(), "{bad}");
        }
        assert!(toml::from_str::<UpstreamTomlConfig>("retry = 1\n").is_err());
    }

    #[test]
    fn health_section_defaults_and_validation() {
        let d = HealthChecksConfig::from_toml(None).unwrap();
        assert_eq!(d.default_path, None);
        assert_eq!(d.unhealthy_threshold, 3);
        assert_eq!(d.healthy_threshold, 2);
        let t: HealthChecksTomlConfig = toml::from_str(
            "default_path = \"/up\"\ninterval = \"5s\"\ntimeout = \"500ms\"\n\
             unhealthy_threshold = 2\nhealthy_threshold = 1\n",
        )
        .unwrap();
        let c = HealthChecksConfig::from_toml(Some(&t)).unwrap();
        assert_eq!(c.default_path.as_deref(), Some("/up"));
        assert_eq!(c.interval, Duration::from_secs(5));
        assert_eq!(c.timeout, Duration::from_millis(500));
        let t: HealthChecksTomlConfig = toml::from_str("healthy_threshold = 0\n").unwrap();
        assert!(HealthChecksConfig::from_toml(Some(&t)).is_err());
        let t: HealthChecksTomlConfig = toml::from_str("default_path = \"up\"\n").unwrap();
        assert!(HealthChecksConfig::from_toml(Some(&t)).is_err());
    }

    #[test]
    fn plain_rules_build_nothing_and_use_the_shared_pool() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let targets = [target("http://a:1"), target("https://b")];
        let mut o = UpstreamOptions {
            retries: Some(3),
            timeout_ms: Some(1000),
            health: Some("/up".into()),
            ..Default::default()
        };
        o.resolve(&targets).unwrap();
        assert!(o.runtime.0.is_none());
        assert!(o.client_for(Some("http://a:1/"), "http://a:1/x").is_none());
        // A hook may still send a plain rule to an h2c URL.
        assert!(o
            .client_for(None, "h2c://grpc:50051/x")
            .is_some_and(|c| c.is_h2()));
    }

    #[test]
    fn special_targets_get_their_own_clients() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let targets = [
            target("unix:/run/a.sock"),
            target("h2c://grpc:50051"),
            target("http://plain:1"),
        ];
        let mut o = UpstreamOptions::default();
        o.resolve(&targets).unwrap();
        let unix = o
            .client_for(Some("unix:/run/a.sock"), "http://unix.invalid/")
            .unwrap();
        assert!(unix.is_unix() && !unix.is_h2());
        let h2c = o
            .client_for(Some("h2c://grpc:50051"), "h2c://grpc:50051/")
            .unwrap();
        assert!(h2c.is_h2() && !h2c.is_unix());
        assert!(o
            .client_for(Some("http://plain:1/"), "http://plain:1/")
            .is_none());

        // The same options elsewhere share the same clients (and pools).
        let mut other = UpstreamOptions::default();
        other.resolve(&targets[..1]).unwrap();
        let again = other
            .client_for(Some("unix:/run/a.sock"), "http://unix.invalid/")
            .unwrap();
        assert!(std::ptr::eq(unix, again));
    }

    /// A Lua `on_route` override to another origin does not take the rule's
    /// TLS client along (its client certificate, its `@tls_insecure`): only an
    /// override to one of the rule's own origins does.
    #[test]
    fn an_override_elsewhere_gets_the_default_client() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut o = UpstreamOptions {
            tls_insecure: true,
            tls_sni: Some("internal.example".into()),
            ..Default::default()
        };
        o.resolve(&[target("https://backend.internal:8443")])
            .unwrap();
        let rule_client = o
            .client_for(
                Some("https://backend.internal:8443/"),
                "https://backend.internal:8443/x",
            )
            .unwrap();
        // The rule's own origin, rewritten by a hook: its client.
        let own = o
            .client_for(None, "https://BACKEND.internal:8443/other")
            .unwrap();
        assert!(std::ptr::eq(rule_client, own));
        // Elsewhere: the shared pool, or the default h2c client.
        assert!(o.client_for(None, "https://evil.example/").is_none());
        assert!(o.client_for(None, "https://backend.internal/").is_none());
        let h2c = o.client_for(None, "h2c://grpc:50051/x").unwrap();
        assert!(std::ptr::eq(h2c, client::default_h2c()));
    }

    #[test]
    fn a_missing_ca_file_fails_the_load() {
        let mut o = UpstreamOptions {
            tls_ca: Some("/nonexistent/soli-proxy-test-ca.pem".into()),
            ..Default::default()
        };
        let err = o.resolve(&[target("https://a.example")]).unwrap_err();
        assert!(format!("{:#}", err).contains("soli-proxy-test-ca.pem"));
    }
}
