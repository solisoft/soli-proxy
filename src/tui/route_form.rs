use crate::auth::{generate_hash, BasicAuth};
use crate::config::{LoadBalancingStrategy, ProxyRule, RegexMatcher, RuleMatcher, Target};
use anyhow::Result;
use url::Url;

pub const MATCHER_TYPES: &[&str] = &[
    "default",
    "prefix",
    "exact",
    "domain",
    "domain_path",
    "regex",
];
pub const LB_STRATEGIES: &[&str] = &["round-robin", "weighted", "failover"];

const FIELD_COUNT: usize = 7;

// ── Auth sub-state ────────────────────────────────────

#[derive(Clone)]
pub struct AuthEntry {
    pub username: String,
    pub hash: String,
}

#[derive(Clone, PartialEq)]
pub enum AuthMode {
    /// Browsing the user list (a:add, d:remove)
    List,
    /// Typing a new username
    AddUsername,
    /// Typing a new password (masked)
    AddPassword,
}

// ── Route form ────────────────────────────────────────

pub struct RouteForm {
    pub matcher_type: usize,
    pub matcher_value: String,
    pub targets: String,
    /// Comma-separated paths served without Basic Auth (`@noauth:`).
    pub auth_exempt: String,
    pub scripts: String,
    pub lb_strategy: usize,
    pub active_field: usize,
    pub edit_index: Option<usize>,
    pub cursor_pos: usize,
    pub error: Option<String>,

    // Auth
    pub auth_list: Vec<AuthEntry>,
    pub auth_mode: AuthMode,
    pub auth_new_username: String,
    pub auth_new_password: String,
    pub auth_selected: usize,

    /// The rule being edited, if any. The form only has widgets for some of
    /// a rule's settings; everything else — `headers { }`, `@forward_auth`,
    /// `@compress`, and whatever a later directive adds — is carried over
    /// from here untouched. Rebuilding the rule from the widgets alone used to
    /// drop them on save: a header block vanished, a route came out from
    /// behind its SSO.
    pub original: Option<ProxyRule>,
}

impl RouteForm {
    pub fn new_empty() -> Self {
        Self {
            matcher_type: 0,
            matcher_value: String::new(),
            targets: String::new(),
            auth_exempt: String::new(),
            scripts: String::new(),
            lb_strategy: 0,
            active_field: 0,
            edit_index: None,
            cursor_pos: 0,
            error: None,
            auth_list: Vec::new(),
            auth_mode: AuthMode::List,
            auth_new_username: String::new(),
            auth_new_password: String::new(),
            auth_selected: 0,
            original: None,
        }
    }

    pub fn from_rule(rule: &ProxyRule, index: usize) -> Self {
        let (matcher_type, matcher_value) = match &rule.matcher {
            RuleMatcher::Default => (0, String::new()),
            RuleMatcher::Prefix(v) => (1, v.clone()),
            RuleMatcher::Exact(v) => (2, v.clone()),
            RuleMatcher::Domain(v) => (3, v.clone()),
            RuleMatcher::DomainPath(d, p) => (4, format!("{}{}", d, p)),
            RuleMatcher::Regex(rm) => (5, rm.pattern.clone()),
        };

        // `weight:N url`, as proxy.conf writes it, whenever a weight is not
        // the default — so editing a weighted route keeps its weights.
        let targets = rule
            .targets
            .iter()
            .map(|t| {
                if t.weight == crate::config::DEFAULT_TARGET_WEIGHT {
                    t.url.to_string()
                } else {
                    format!("weight:{} {}", t.weight, t.url)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let auth_list: Vec<AuthEntry> = rule
            .auth
            .iter()
            .map(|a| AuthEntry {
                username: a.username.clone(),
                hash: a.hash.clone(),
            })
            .collect();

        let auth_exempt = rule.auth_exempt.join(", ");

        let scripts = rule.scripts.join(", ");

        let lb_strategy = match rule.load_balancing {
            LoadBalancingStrategy::RoundRobin => 0,
            LoadBalancingStrategy::Weighted => 1,
            LoadBalancingStrategy::Failover => 2,
        };

        Self {
            matcher_type,
            matcher_value,
            targets,
            auth_exempt,
            scripts,
            lb_strategy,
            active_field: 0,
            edit_index: Some(index),
            cursor_pos: 0,
            error: None,
            auth_list,
            auth_mode: AuthMode::List,
            auth_new_username: String::new(),
            auth_new_password: String::new(),
            auth_selected: 0,
            original: Some(rule.clone()),
        }
    }

    // ── Text field helpers ─────────────────────────────

    pub fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            1 => Some(&mut self.matcher_value),
            2 => Some(&mut self.targets),
            3 => match self.auth_mode {
                AuthMode::AddUsername => Some(&mut self.auth_new_username),
                AuthMode::AddPassword => Some(&mut self.auth_new_password),
                AuthMode::List => None,
            },
            4 => Some(&mut self.auth_exempt),
            5 => Some(&mut self.scripts),
            _ => None,
        }
    }

    pub fn active_text(&self) -> Option<&str> {
        match self.active_field {
            1 => Some(&self.matcher_value),
            2 => Some(&self.targets),
            3 => match self.auth_mode {
                AuthMode::AddUsername => Some(&self.auth_new_username),
                AuthMode::AddPassword => Some(&self.auth_new_password),
                AuthMode::List => None,
            },
            4 => Some(&self.auth_exempt),
            5 => Some(&self.scripts),
            _ => None,
        }
    }

    pub fn is_select_field(&self) -> bool {
        matches!(self.active_field, 0 | 6)
    }

    /// True when the Auth field is in add-credential sub-mode.
    pub fn is_auth_input_mode(&self) -> bool {
        self.active_field == 3 && self.auth_mode != AuthMode::List
    }

    /// True when field 3 is active but in list browsing mode.
    pub fn is_auth_list_mode(&self) -> bool {
        self.active_field == 3 && self.auth_mode == AuthMode::List
    }

    pub fn cycle_select(&mut self, dir: i32) {
        match self.active_field {
            0 => {
                let len = MATCHER_TYPES.len() as i32;
                self.matcher_type = ((self.matcher_type as i32 + dir).rem_euclid(len)) as usize;
            }
            6 => {
                let len = LB_STRATEGIES.len() as i32;
                self.lb_strategy = ((self.lb_strategy as i32 + dir).rem_euclid(len)) as usize;
            }
            _ => {}
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = (self.active_field + 1) % FIELD_COUNT;
        self.cursor_pos = self.active_text().map_or(0, |s| s.len());
    }

    pub fn prev_field(&mut self) {
        self.active_field = (self.active_field + FIELD_COUNT - 1) % FIELD_COUNT;
        self.cursor_pos = self.active_text().map_or(0, |s| s.len());
    }

    pub fn insert_char(&mut self, c: char) {
        let cursor = self.cursor_pos;
        if let Some(text) = self.active_text_mut() {
            let byte_pos = text
                .char_indices()
                .nth(cursor)
                .map(|(i, _)| i)
                .unwrap_or(text.len());
            text.insert(byte_pos, c);
            self.cursor_pos += 1;
        }
    }

    pub fn delete_char(&mut self) {
        if self.cursor_pos > 0 {
            let cursor = self.cursor_pos;
            if let Some(text) = self.active_text_mut() {
                let byte_pos = text
                    .char_indices()
                    .nth(cursor - 1)
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                text.remove(byte_pos);
            }
            self.cursor_pos -= 1;
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        if let Some(text) = self.active_text() {
            if self.cursor_pos < text.chars().count() {
                self.cursor_pos += 1;
            }
        }
    }

    // ── Auth actions ──────────────────────────────────

    pub fn auth_start_add(&mut self) {
        self.auth_new_username.clear();
        self.auth_new_password.clear();
        self.auth_mode = AuthMode::AddUsername;
        self.cursor_pos = 0;
    }

    pub fn auth_advance_to_password(&mut self) {
        if !self.auth_new_username.trim().is_empty() {
            self.auth_mode = AuthMode::AddPassword;
            self.cursor_pos = 0;
        }
    }

    pub fn auth_confirm_add(&mut self) {
        let username = self.auth_new_username.trim().to_string();
        let password = self.auth_new_password.clone();
        if !username.is_empty() && !password.is_empty() {
            let hash = generate_hash(&password);
            self.auth_list.push(AuthEntry { username, hash });
        }
        self.auth_mode = AuthMode::List;
        self.auth_new_username.clear();
        self.auth_new_password.clear();
        self.cursor_pos = 0;
    }

    pub fn auth_cancel_add(&mut self) {
        self.auth_mode = AuthMode::List;
        self.auth_new_username.clear();
        self.auth_new_password.clear();
        self.cursor_pos = 0;
    }

    pub fn auth_remove_selected(&mut self) {
        if !self.auth_list.is_empty() && self.auth_selected < self.auth_list.len() {
            self.auth_list.remove(self.auth_selected);
            if self.auth_selected > 0 && self.auth_selected >= self.auth_list.len() {
                self.auth_selected -= 1;
            }
        }
    }

    pub fn auth_move_selection(&mut self, dir: i32) {
        if self.auth_list.is_empty() {
            return;
        }
        let max = self.auth_list.len() as i32 - 1;
        self.auth_selected = ((self.auth_selected as i32 + dir).clamp(0, max)) as usize;
    }

    // ── Build rule ────────────────────────────────────

    pub fn build_rule(&self) -> Result<ProxyRule> {
        let matcher = match MATCHER_TYPES[self.matcher_type] {
            "default" => RuleMatcher::Default,
            "prefix" => {
                if self.matcher_value.is_empty() {
                    anyhow::bail!("Prefix matcher requires a value (e.g. /api/)");
                }
                RuleMatcher::Prefix(self.matcher_value.clone())
            }
            "exact" => {
                if self.matcher_value.is_empty() {
                    anyhow::bail!("Exact matcher requires a value");
                }
                RuleMatcher::Exact(self.matcher_value.clone())
            }
            "domain" => {
                if self.matcher_value.is_empty() {
                    anyhow::bail!("Domain matcher requires a value");
                }
                RuleMatcher::Domain(self.matcher_value.clone())
            }
            "domain_path" => {
                if let Some(slash_pos) = self.matcher_value.find('/') {
                    let domain = self.matcher_value[..slash_pos].to_string();
                    let path = self.matcher_value[slash_pos..].to_string();
                    RuleMatcher::DomainPath(domain, path)
                } else {
                    anyhow::bail!("domain_path requires format: domain.com/path");
                }
            }
            "regex" => {
                if self.matcher_value.is_empty() {
                    anyhow::bail!("Regex matcher requires a pattern");
                }
                RuleMatcher::Regex(RegexMatcher::new(&self.matcher_value)?)
            }
            _ => anyhow::bail!("Unknown matcher type"),
        };

        let targets: Vec<Target> = self
            .targets
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (weight, url) = match s.strip_prefix("weight:") {
                    Some(rest) => {
                        let (n, url) = rest.split_once(char::is_whitespace).ok_or_else(|| {
                            anyhow::anyhow!("'{}': expected weight:N followed by a URL", s)
                        })?;
                        let weight = n.parse::<u8>().map_err(|_| {
                            anyhow::anyhow!("Invalid weight '{}' (expected 0 to 255)", n)
                        })?;
                        (weight, url.trim())
                    }
                    None => (crate::config::DEFAULT_TARGET_WEIGHT, s),
                };
                let url =
                    Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL '{}': {}", url, e))?;
                Ok(Target { url, weight })
            })
            .collect::<Result<Vec<_>>>()?;

        if targets.is_empty() {
            anyhow::bail!("At least one target URL is required");
        }

        let auth: Vec<BasicAuth> = self
            .auth_list
            .iter()
            .map(|e| BasicAuth {
                username: e.username.clone(),
                hash: e.hash.clone(),
            })
            .collect();

        let auth_exempt: Vec<String> = self
            .auth_exempt
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let scripts: Vec<String> = self
            .scripts
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let load_balancing = match LB_STRATEGIES[self.lb_strategy] {
            "weighted" => LoadBalancingStrategy::Weighted,
            "failover" => LoadBalancingStrategy::Failover,
            _ => LoadBalancingStrategy::RoundRobin,
        };

        let edited = |base: ProxyRule| ProxyRule {
            matcher,
            targets,
            scripts,
            auth,
            auth_exempt,
            load_balancing,
            ..base
        };
        Ok(match &self.original {
            Some(original) => edited(original.clone()),
            None => edited(ProxyRule {
                matcher: RuleMatcher::Default,
                targets: Vec::new(),
                headers: Vec::new(),
                scripts: Vec::new(),
                auth: Vec::new(),
                auth_exempt: Vec::new(),
                load_balancing: LoadBalancingStrategy::default(),
                forward_auth: None,
                compress: None,
                upstream: Default::default(),
            }),
        })
    }

    // ── Display helpers ───────────────────────────────

    pub fn field_label(&self, idx: usize) -> &'static str {
        match idx {
            0 => "Matcher Type",
            1 => "Matcher Value",
            2 => "Targets",
            3 => "Auth",
            4 => "No-Auth Paths",
            5 => "Scripts",
            6 => "Load Balancing",
            _ => "",
        }
    }

    pub fn field_value(&self, idx: usize) -> String {
        match idx {
            0 => format!("<  {}  >", MATCHER_TYPES[self.matcher_type]),
            1 => self.matcher_value.clone(),
            2 => self.targets.clone(),
            3 => {
                // Auth is rendered specially; this is just the inline summary
                if self.auth_list.is_empty() {
                    "(none)".to_string()
                } else {
                    let names: Vec<&str> =
                        self.auth_list.iter().map(|e| e.username.as_str()).collect();
                    names.join(", ")
                }
            }
            4 => self.auth_exempt.clone(),
            5 => self.scripts.clone(),
            6 => format!("<  {}  >", LB_STRATEGIES[self.lb_strategy]),
            _ => String::new(),
        }
    }

    pub fn field_hint(&self, idx: usize) -> &'static str {
        match idx {
            0 => "Left/Right to change",
            1 => match MATCHER_TYPES[self.matcher_type] {
                "default" => "(no value needed)",
                "prefix" => "e.g. /api/",
                "exact" => "e.g. /health",
                "domain" => "e.g. example.com",
                "domain_path" => "e.g. example.com/api/",
                "regex" => "e.g. ^/admin/.*$",
                _ => "",
            },
            2 => "comma-separated URLs, each optionally weight:N URL",
            3 => match self.auth_mode {
                AuthMode::List => "a:add  d:remove  j/k:select",
                AuthMode::AddUsername => "type username, then Tab",
                AuthMode::AddPassword => "type password, then Enter to save",
            },
            4 => "paths exempt from Auth, e.g. /hooks/stripe,/health",
            5 => "comma-separated .lua files",
            6 => "Left/Right to change",
            _ => "",
        }
    }

    /// How many extra lines the auth field needs for rendering.
    pub fn auth_render_height(&self) -> u16 {
        let list_lines = if self.auth_list.is_empty() {
            0
        } else {
            self.auth_list.len() as u16
        };
        let add_lines = match self.auth_mode {
            AuthMode::List => 0,
            AuthMode::AddUsername => 1,
            AuthMode::AddPassword => 2,
        };
        list_lines + add_lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening a route in the editor and saving it unchanged must give back
    /// the same rule — including what the form has no widget for.
    #[test]
    fn an_unchanged_edit_keeps_every_setting() {
        let conf = "\
app.example.com -> weight:70 http://a:8080, weight:30 http://b:8080 @compress:off \
@forward_auth:http://auth.internal/verify
headers {
  X-Env: prod
  -X-Debug
}
";
        let (rules, _) = crate::config::parse_proxy_config(conf).unwrap();
        let rebuilt = RouteForm::from_rule(&rules[0], 0).build_rule().unwrap();

        let weights: Vec<u8> = rebuilt.targets.iter().map(|t| t.weight).collect();
        assert_eq!(weights, vec![70, 30]);
        assert_eq!(rebuilt.load_balancing, LoadBalancingStrategy::Weighted);
        assert_eq!(rebuilt.headers.len(), 2);
        assert_eq!(rebuilt.compress, Some(false));
        assert_eq!(rebuilt.forward_auth, rules[0].forward_auth);
        let a = crate::config::serializer::serialize_proxy_conf(&rules, &[]);
        let b = crate::config::serializer::serialize_proxy_conf(&[rebuilt], &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn a_bad_weight_is_an_error() {
        let mut form = RouteForm::new_empty();
        form.matcher_type = 0;
        form.targets = "weight:300 http://a:8080".to_string();
        assert!(form.build_rule().is_err());
        form.targets = "weight:5".to_string();
        assert!(form.build_rule().is_err());
    }
}
