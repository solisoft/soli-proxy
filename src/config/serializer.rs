use super::{ProxyRule, RuleMatcher};

/// Serialize proxy rules and global scripts back to the proxy.conf text format.
pub fn serialize_proxy_conf(rules: &[ProxyRule], global_scripts: &[String]) -> String {
    let mut output = String::new();

    if !global_scripts.is_empty() {
        output.push_str(&format!("[global] @script:{}\n", global_scripts.join(",")));
        output.push('\n');
    }

    for rule in rules {
        let matcher_str = match &rule.matcher {
            RuleMatcher::Default => "default".to_string(),
            RuleMatcher::Exact(path) => path.clone(),
            RuleMatcher::Prefix(prefix) => format!("{}*", prefix),
            RuleMatcher::Regex(rm) => format!("~{}", rm.pattern),
            RuleMatcher::Domain(domain) => domain.clone(),
            RuleMatcher::DomainPath(domain, path) => format!("{}{}", domain, path),
        };

        let targets_str: Vec<String> = rule.targets.iter().map(|t| t.url.to_string()).collect();
        let targets_joined = targets_str.join(", ");

        let scripts_suffix = if rule.scripts.is_empty() {
            String::new()
        } else {
            format!("  @script:{}", rule.scripts.join(","))
        };

        let auth_suffix: String = rule
            .auth
            .iter()
            .map(|a| format!(" @auth:{}:{}", a.username, a.hash))
            .collect();

        output.push_str(&format!(
            "{} -> {}{}{}\n",
            matcher_str, targets_joined, scripts_suffix, auth_suffix
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RegexMatcher, Target};
    use url::Url;

    fn target(url: &str) -> Target {
        Target {
            url: Url::parse(url).unwrap(),
            weight: 100,
        }
    }

    #[test]
    fn test_serialize_basic_rules() {
        let rules = vec![
            ProxyRule {
                matcher: RuleMatcher::Default,
                targets: vec![target("http://localhost:3000")],
                headers: vec![],
                scripts: vec![],
                auth: vec![],
            },
            ProxyRule {
                matcher: RuleMatcher::Prefix("/api/".to_string()),
                targets: vec![target("http://localhost:8888")],
                headers: vec![],
                scripts: vec!["auth.lua".to_string()],
                auth: vec![],
            },
        ];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(output.contains("default -> http://localhost:3000/"));
        assert!(output.contains("/api/* -> http://localhost:8888/  @script:auth.lua"));
    }

    #[test]
    fn test_serialize_with_global_scripts() {
        let rules = vec![ProxyRule {
            matcher: RuleMatcher::Default,
            targets: vec![target("http://localhost:3000")],
            headers: vec![],
            scripts: vec![],
            auth: vec![],
        }];

        let output =
            serialize_proxy_conf(&rules, &["cors.lua".to_string(), "logging.lua".to_string()]);
        assert!(output.starts_with("[global] @script:cors.lua,logging.lua"));
    }

    #[test]
    fn test_serialize_domain_rules() {
        let rules = vec![
            ProxyRule {
                matcher: RuleMatcher::Domain("example.com".to_string()),
                targets: vec![target("http://backend:8080")],
                headers: vec![],
                scripts: vec![],
                auth: vec![],
            },
            ProxyRule {
                matcher: RuleMatcher::DomainPath("api.example.com".to_string(), "/v1/".to_string()),
                targets: vec![target("http://api:8081")],
                headers: vec![],
                scripts: vec![],
                auth: vec![],
            },
        ];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(output.contains("example.com -> http://backend:8080/"));
        assert!(output.contains("api.example.com/v1/ -> http://api:8081/"));
    }

    #[test]
    fn test_serialize_regex_rule() {
        let rules = vec![ProxyRule {
            matcher: RuleMatcher::Regex(RegexMatcher::new("^/admin/.*$").unwrap()),
            targets: vec![target("http://admin:8082")],
            headers: vec![],
            scripts: vec![],
            auth: vec![],
        }];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(output.contains("~^/admin/.*$ -> http://admin:8082/"));
    }
}
