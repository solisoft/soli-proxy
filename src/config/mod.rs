pub mod serializer;

use crate::auth::BasicAuth;
use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;

#[async_trait::async_trait]
pub trait ConfigManagerTrait: Send + Sync {
    async fn reload(&self) -> Result<()>;
    fn get_config(&self) -> Arc<Config>;
    fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()>;
    fn add_route(&self, rule: ProxyRule) -> Result<()>;
    fn remove_route(&self, index: usize) -> Result<()>;
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct TomlConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
    pub scripting: Option<ScriptingTomlConfig>,
    pub admin: Option<AdminConfig>,
    pub circuit_breaker: Option<CircuitBreakerTomlConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CircuitBreakerTomlConfig {
    pub failure_threshold: Option<u32>,
    pub recovery_timeout_secs: Option<u64>,
    pub success_threshold: Option<u32>,
    pub failure_status_codes: Option<Vec<u16>>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AdminConfig {
    pub enabled: bool,
    pub bind: String,
    pub api_key: Option<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9090".to_string(),
            api_key: None,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ScriptingTomlConfig {
    pub enabled: bool,
    pub scripts_dir: Option<String>,
    pub hook_timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct ServerConfig {
    pub bind: String,
    pub https_port: u16,
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct TlsConfig {
    pub mode: String,
    pub cache_dir: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct LetsEncryptConfig {
    pub staging: bool,
    pub email: String,
    pub terms_agreed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
    pub scripting: ScriptingTomlConfig,
    pub admin: AdminConfig,
    pub circuit_breaker: Option<CircuitBreakerTomlConfig>,
    pub rules: Vec<ProxyRule>,
    pub global_scripts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyRule {
    pub matcher: RuleMatcher,
    pub targets: Vec<Target>,
    pub headers: Vec<HeaderRule>,
    pub scripts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<BasicAuth>,
}

#[derive(Clone, Debug)]
pub enum RuleMatcher {
    Default,
    Prefix(String),
    Regex(RegexMatcher),
    Exact(String),
    Domain(String),
    DomainPath(String, String),
}

/// Wrapper around Regex that stores the original pattern for serialization
#[derive(Clone, Debug)]
pub struct RegexMatcher {
    pub pattern: String,
    pub regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: &str) -> Result<Self> {
        Ok(Self {
            pattern: pattern.to_string(),
            regex: Regex::new(pattern)?,
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl Serialize for RuleMatcher {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            RuleMatcher::Default => {
                map.serialize_entry("type", "default")?;
            }
            RuleMatcher::Prefix(v) => {
                map.serialize_entry("type", "prefix")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::Regex(rm) => {
                map.serialize_entry("type", "regex")?;
                map.serialize_entry("value", &rm.pattern)?;
            }
            RuleMatcher::Exact(v) => {
                map.serialize_entry("type", "exact")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::Domain(v) => {
                map.serialize_entry("type", "domain")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::DomainPath(d, p) => {
                map.serialize_entry("type", "domain_path")?;
                map.serialize_entry("domain", d)?;
                map.serialize_entry("path", p)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for RuleMatcher {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| D::Error::custom("expected object"))?;
        let matcher_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| D::Error::custom("missing 'type' field"))?;

        match matcher_type {
            "default" => Ok(RuleMatcher::Default),
            "exact" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Exact(v.to_string()))
            }
            "prefix" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Prefix(v.to_string()))
            }
            "regex" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                let rm = RegexMatcher::new(v)
                    .map_err(|e| D::Error::custom(format!("invalid regex: {}", e)))?;
                Ok(RuleMatcher::Regex(rm))
            }
            "domain" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Domain(v.to_string()))
            }
            "domain_path" => {
                let d = obj
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'domain'"))?;
                let p = obj
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'path'"))?;
                Ok(RuleMatcher::DomainPath(d.to_string(), p.to_string()))
            }
            other => Err(D::Error::custom(format!("unknown matcher type: {}", other))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub url: Url,
    pub weight: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

impl Config {
    /// Extract unique domain names from Domain and DomainPath rules,
    /// filtering out IPs and "localhost".
    pub fn acme_domains(&self) -> Vec<String> {
        let mut domains = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for rule in &self.rules {
            let domain = match &rule.matcher {
                RuleMatcher::Domain(d) => Some(d.as_str()),
                RuleMatcher::DomainPath(d, _) => Some(d.as_str()),
                _ => None,
            };

            if let Some(d) = domain {
                if d == "localhost" || d.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                if seen.insert(d.to_string()) {
                    domains.push(d.to_string());
                }
            }
        }

        domains
    }
}

pub struct ConfigManager {
    config: ArcSwap<Config>,
    config_path: PathBuf,
    _watcher: Option<RecommendedWatcher>,
    suppress_watch: Arc<AtomicBool>,
}

impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            config: ArcSwap::new(self.config.load().clone()),
            config_path: self.config_path.clone(),
            _watcher: None,
            suppress_watch: self.suppress_watch.clone(),
        }
    }
}

impl ConfigManager {
    pub fn new(config_path: &str) -> Result<Self> {
        let path = PathBuf::from(config_path);
        let config = Self::load_config(&path, &path)?;
        Ok(Self {
            config: ArcSwap::new(Arc::new(config)),
            config_path: path,
            _watcher: None,
            suppress_watch: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn suppress_watch(&self) -> &Arc<AtomicBool> {
        &self.suppress_watch
    }

    fn load_config(proxy_conf_path: &Path, config_path: &Path) -> Result<Config> {
        let content = std::fs::read_to_string(proxy_conf_path).unwrap_or_default();
        let (rules, global_scripts) = parse_proxy_config(&content)?;
        let toml_content = std::fs::read_to_string(
            config_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("config.toml"),
        )
        .ok();
        let toml_config: TomlConfig = toml_content
            .as_ref()
            .and_then(|c| toml::from_str(c).ok())
            .unwrap_or_default();

        Ok(Config {
            server: toml_config.server,
            tls: toml_config.tls,
            letsencrypt: toml_config.letsencrypt,
            scripting: toml_config.scripting.unwrap_or_default(),
            admin: toml_config.admin.unwrap_or_default(),
            circuit_breaker: toml_config.circuit_breaker,
            rules,
            global_scripts,
        })
    }

    pub fn get_config(&self) -> Arc<Config> {
        self.config.load().clone()
    }

    pub fn start_watcher(&self) -> Result<()> {
        // Ensure the file exists so the watcher has something to watch
        if !self.config_path.exists() {
            if let Some(parent) = self.config_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&self.config_path, "")?;
        }

        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();
        let suppress = self.suppress_watch.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        tracing::info!("Watching config file: {}", config_path.display());

        std::thread::spawn(move || {
            while let Some(res) = rx.blocking_recv() {
                match res {
                    Ok(event) => {
                        if event.kind.is_modify() {
                            if suppress.swap(false, Ordering::SeqCst) {
                                tracing::debug!(
                                    "Suppressing file watcher reload (admin API write)"
                                );
                                continue;
                            }
                            tracing::info!("Config file changed, reloading...");
                        }
                    }
                    Err(e) => tracing::error!("Watch error: {}", e),
                }
            }
        });

        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        let new_config = Self::load_config(&self.config_path, &self.config_path)?;
        self.config.store(Arc::new(new_config));
        tracing::info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Persist current rules to proxy.conf and swap in-memory config
    fn persist_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        let content = serializer::serialize_proxy_conf(&rules, &global_scripts);
        self.suppress_watch.store(true, Ordering::SeqCst);
        std::fs::write(&self.config_path, &content)?;
        let mut config = (*self.config.load().as_ref()).clone();
        config.rules = rules;
        config.global_scripts = global_scripts;
        self.config.store(Arc::new(config));
        tracing::info!("Configuration persisted to {}", self.config_path.display());
        Ok(())
    }

    pub fn add_route(&self, rule: ProxyRule) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        rules.push(rule);
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn update_route(&self, index: usize, rule: ProxyRule) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        if index >= rules.len() {
            anyhow::bail!(
                "Route index {} out of range (have {} routes)",
                index,
                rules.len()
            );
        }
        rules[index] = rule;
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn remove_route(&self, index: usize) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        if index >= rules.len() {
            anyhow::bail!(
                "Route index {} out of range (have {} routes)",
                index,
                rules.len()
            );
        }
        rules.remove(index);
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        self.persist_rules(rules, global_scripts)
    }
}

#[async_trait::async_trait]
impl ConfigManagerTrait for ConfigManager {
    async fn reload(&self) -> Result<()> {
        self.reload().await
    }

    fn get_config(&self) -> Arc<Config> {
        self.get_config()
    }

    fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        self.update_rules(rules, global_scripts)
    }

    fn add_route(&self, rule: ProxyRule) -> Result<()> {
        self.add_route(rule)
    }

    fn remove_route(&self, index: usize) -> Result<()> {
        self.remove_route(index)
    }
}

/// Extract `@script:a.lua,b.lua` from a string, returning (remaining_str, scripts_vec).
fn extract_scripts(s: &str) -> (&str, Vec<String>) {
    if let Some(idx) = s.find("@script:") {
        let before = s[..idx].trim();
        let after = &s[idx + "@script:".len()..];
        // Scripts are comma-separated, ending at whitespace or end-of-string
        let script_part = after.split_whitespace().next().unwrap_or(after);
        let scripts: Vec<String> = script_part
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        (before, scripts)
    } else {
        (s, Vec::new())
    }
}

/// Extract `@auth:user:hash` entries from a string, returning (remaining_str, auth_vec).
/// Multiple @auth entries can appear: `@auth:user1:hash1 @auth:user2:hash2`
/// Hash is everything after the second colon (bcrypt hashes start with $2a$, $2b$, $2y$)
fn extract_auth(s: &str) -> (String, Vec<BasicAuth>) {
    let mut auth_entries = Vec::new();
    let mut remaining = s.to_string();

    while let Some(idx) = remaining.find("@auth:") {
        // Keep the part BEFORE @auth:
        let before = &remaining[..idx];
        let after = &remaining[idx + "@auth:".len()..];

        // Find the end of this auth entry (whitespace or end of string)
        let end_idx = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());

        let auth_part = &after[..end_idx];

        // Parse username:hash - hash is everything after the first colon
        if let Some((username, hash)) = auth_part.split_once(':') {
            if !username.is_empty() && !hash.is_empty() {
                auth_entries.push(BasicAuth {
                    username: username.to_string(),
                    hash: hash.to_string(),
                });
            }
        }

        // Continue with the part BEFORE this @auth, plus any remaining after it
        let rest = &after[end_idx..];
        remaining = if rest.is_empty() {
            before.to_string()
        } else {
            format!("{}{}", before, rest)
        };
    }

    (remaining.trim().to_string(), auth_entries)
}

fn parse_proxy_config(content: &str) -> Result<(Vec<ProxyRule>, Vec<String>)> {
    let mut rules = Vec::new();
    let mut global_scripts = Vec::new();

    // Join continuation lines (backslash at end of line)
    let mut joined_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        if let Some(current) = joined_lines.last_mut() {
            if current.ends_with('\\') {
                current.pop(); // remove the backslash
                current.push_str(line.trim());
                continue;
            }
        }
        joined_lines.push(line.to_string());
    }

    for line in &joined_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handle [global] @script:cors.lua,logging.lua
        if trimmed.starts_with("[global]") {
            let rest = trimmed.strip_prefix("[global]").unwrap().trim();
            let (_, scripts) = extract_scripts(rest);
            global_scripts.extend(scripts);
            continue;
        }

        if let Some((source, target_str)) = trimmed.split_once("->") {
            let source = source.trim();
            // Extract @script: from the target side
            let (target_str, route_scripts) = extract_scripts(target_str.trim());
            // Extract @auth: entries from the target side
            let (target_str, auth_entries) = extract_auth(target_str);

            let matcher = if source == "default" || source == "*" {
                RuleMatcher::Default
            } else if let Some(pattern) = source.strip_prefix("~") {
                RuleMatcher::Regex(RegexMatcher::new(pattern)?)
            } else if !source.starts_with('/')
                && (source.contains('.') || source.parse::<std::net::IpAddr>().is_ok())
            {
                if let Some((domain, path)) = source.split_once('/') {
                    if path.is_empty() || path == "*" {
                        RuleMatcher::Domain(domain.to_string())
                    } else if path.ends_with("/*") {
                        RuleMatcher::DomainPath(
                            domain.to_string(),
                            path.trim_end_matches('*').to_string(),
                        )
                    } else {
                        RuleMatcher::DomainPath(domain.to_string(), path.to_string())
                    }
                } else {
                    RuleMatcher::Domain(source.to_string())
                }
            } else if source.ends_with("/*") {
                RuleMatcher::Prefix(source.trim_end_matches('*').to_string())
            } else {
                RuleMatcher::Exact(source.to_string())
            };

            let targets: Vec<Target> = target_str
                .split(',')
                .map(|t| {
                    Ok(Target {
                        url: Url::parse(t.trim())?,
                        weight: 100,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            rules.push(ProxyRule {
                matcher,
                targets,
                headers: vec![],
                scripts: route_scripts,
                auth: auth_entries,
            });
        }
    }

    Ok((rules, global_scripts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backslash_continuation_joins_lines() {
        let config = "/api/* -> http://backend1:8080, \\\n          http://backend2:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 2);
        assert_eq!(rules[0].targets[0].url.as_str(), "http://backend1:8080/");
        assert_eq!(rules[0].targets[1].url.as_str(), "http://backend2:8080/");
    }

    #[test]
    fn test_multiple_continuation_lines() {
        let config = "/api/* -> http://backend1:8080, \\\n\
                       http://backend2:8080, \\\n\
                       http://backend3:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 3);
        assert_eq!(rules[0].targets[2].url.as_str(), "http://backend3:8080/");
    }

    #[test]
    fn test_backslash_mid_line_not_continuation() {
        let config = "/path -> http://localhost:8080\n\
                       ~^/foo\\dbar$ -> http://localhost:9090\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_continuation_trims_whitespace() {
        let config = "/api/* -> http://a:8080,   \\\n   http://b:8080,  \\\n   http://c:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 3);
    }

    #[test]
    fn test_continuation_with_scripts() {
        let config = "/api/* -> http://a:8080, \\\n\
                       http://b:8080 @script:auth.lua\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 2);
        assert_eq!(rules[0].scripts, vec!["auth.lua"]);
    }

    #[test]
    fn test_no_continuation_normal_config() {
        let config = "/api/* -> http://backend:8080\ndefault -> http://localhost:3000\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_auth_parsing() {
        let config = r#"
/db/* -> http://localhost:8080/ @auth:demo:$2b$12$YFlnIiACnSaAcxDWQlYjeedxq/3GvhvoGhRTYHMqLifJrETSqOZQa
"#;
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].auth.len(), 1);
        assert_eq!(rules[0].auth[0].username, "demo");
        assert!(rules[0].auth[0].hash.starts_with("$2b$"));
        assert_eq!(rules[0].targets.len(), 1);
        assert_eq!(rules[0].targets[0].url.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn test_multiple_auth_users() {
        let config = r#"
secure.example.com -> http://localhost:9000/ @auth:admin:$2b$12$hash1 @auth:user:$2b$12$hash2
"#;
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].auth.len(), 2);
        assert_eq!(rules[0].auth[0].username, "admin");
        assert_eq!(rules[0].auth[1].username, "user");
    }
}
