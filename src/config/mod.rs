use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;

#[derive(Deserialize, Default, Clone, Debug)]
pub struct TomlConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct ServerConfig {
    pub bind: String,
    pub https_port: u16,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct TlsConfig {
    pub mode: String,
    pub cache_dir: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct LetsEncryptConfig {
    pub staging: bool,
    pub email: String,
    pub terms_agreed: bool,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
    pub rules: Vec<ProxyRule>,
}

#[derive(Clone, Debug)]
pub struct ProxyRule {
    pub matcher: RuleMatcher,
    pub targets: Vec<Target>,
    pub headers: Vec<HeaderRule>,
}

#[derive(Clone, Debug)]
pub enum RuleMatcher {
    Default,
    Prefix(String),
    Regex(Regex),
    Exact(String),
    Domain(String),
    DomainPath(String, String),
}

#[derive(Clone, Debug)]
pub struct Target {
    pub url: Url,
    pub weight: u8,
}

#[derive(Clone, Debug)]
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
}

impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            config: ArcSwap::new(self.config.load().clone()),
            config_path: self.config_path.clone(),
            _watcher: None,
        }
    }
}

impl ConfigManager {
    pub fn new(config_path: &str) -> Result<Self> {
        let path = PathBuf::from(config_path);
        if !path.exists() {
            anyhow::bail!("Config file not found: {}", config_path);
        }

        let config = Self::load_config(&path, &path)?;
        Ok(Self {
            config: ArcSwap::new(Arc::new(config)),
            config_path: path,
            _watcher: None,
        })
    }

    fn load_config(proxy_conf_path: &Path, config_path: &Path) -> Result<Config> {
        let content = std::fs::read_to_string(proxy_conf_path)?;
        let rules = parse_proxy_config(&content)?;
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
            rules,
        })
    }

    pub fn get_config(&self) -> Arc<Config> {
        self.config.load().clone()
    }

    pub fn start_watcher(&self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();

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
}

fn parse_proxy_config(content: &str) -> Result<Vec<ProxyRule>> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((source, target_str)) = trimmed.split_once("->") {
            let source = source.trim();
            let target_str = target_str.trim();

            let matcher = if source == "default" || source == "*" {
                RuleMatcher::Default
            } else if let Some(pattern) = source.strip_prefix("~") {
                RuleMatcher::Regex(Regex::new(pattern)?)
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
            });
        }
    }

    Ok(rules)
}

use std::path::Path;
