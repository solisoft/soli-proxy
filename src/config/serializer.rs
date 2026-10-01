use super::{LoadBalancingStrategy, ProxyRule, RuleMatcher, DEFAULT_TARGET_WEIGHT};

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

        // Weights are written whenever they mean something (a weighted rule)
        // or differ from the default, so what the admin API stored survives
        // the next reload — they used to be dropped, and every target came
        // back at 100.
        let weighted = rule.load_balancing == LoadBalancingStrategy::Weighted;
        let targets_str: Vec<String> = rule
            .targets
            .iter()
            .map(|t| {
                if weighted || t.weight != DEFAULT_TARGET_WEIGHT {
                    format!("weight:{} {}", t.weight, t.url)
                } else {
                    t.url.to_string()
                }
            })
            .collect();
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

        // Only meaningful alongside @auth; writing it on an unprotected rule
        // would be noise the parser reads back as a no-op.
        let noauth_suffix = if rule.auth.is_empty() || rule.auth_exempt.is_empty() {
            String::new()
        } else {
            format!(" @noauth:{}", rule.auth_exempt.join(","))
        };

        // Written for any multi-target rule, and for a single-target rule
        // whose strategy is not the default (a written `weight:` would
        // otherwise read back as weighted).
        let lb_suffix =
            if rule.targets.len() > 1 || rule.load_balancing != LoadBalancingStrategy::default() {
                match rule.load_balancing {
                    LoadBalancingStrategy::RoundRobin => "  @lb:round-robin",
                    LoadBalancingStrategy::Weighted => "  @lb:weighted",
                    LoadBalancingStrategy::Failover => "  @lb:failover",
                }
            } else {
                ""
            };

        output.push_str(&format!(
            "{} -> {}{}{}{}{}{}\n",
            matcher_str,
            targets_joined,
            scripts_suffix,
            auth_suffix,
            noauth_suffix,
            lb_suffix,
            rule.upstream.directives()
        ));

        if !rule.headers.is_empty() {
            output.push_str("headers {\n");
            for header in &rule.headers {
                if header.remove {
                    output.push_str(&format!("    -{}\n", header.name));
                } else {
                    output.push_str(&format!("    {}: {}\n", header.name, header.value));
                }
            }
            output.push_str("}\n");
        }
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
                auth_exempt: vec![],
                load_balancing: LoadBalancingStrategy::default(),
                upstream: Default::default(),
            },
            ProxyRule {
                matcher: RuleMatcher::Prefix("/api/".to_string()),
                targets: vec![target("http://localhost:8888")],
                headers: vec![],
                scripts: vec!["auth.lua".to_string()],
                auth: vec![],
                auth_exempt: vec![],
                load_balancing: LoadBalancingStrategy::default(),
                upstream: Default::default(),
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
            auth_exempt: vec![],
            load_balancing: LoadBalancingStrategy::default(),
            upstream: Default::default(),
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
                auth_exempt: vec![],
                load_balancing: LoadBalancingStrategy::default(),
                upstream: Default::default(),
            },
            ProxyRule {
                matcher: RuleMatcher::DomainPath("api.example.com".to_string(), "/v1/".to_string()),
                targets: vec![target("http://api:8081")],
                headers: vec![],
                scripts: vec![],
                auth: vec![],
                auth_exempt: vec![],
                load_balancing: LoadBalancingStrategy::default(),
                upstream: Default::default(),
            },
        ];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(output.contains("example.com -> http://backend:8080/"));
        assert!(output.contains("api.example.com/v1/ -> http://api:8081/"));
    }

    #[test]
    fn test_serialize_auth_exempt_roundtrips() {
        let rules = vec![ProxyRule {
            matcher: RuleMatcher::Domain("app.example.com".to_string()),
            targets: vec![target("http://backend:8080")],
            headers: vec![],
            scripts: vec![],
            auth: vec![crate::auth::BasicAuth {
                username: "admin".to_string(),
                hash: "$2b$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123X".to_string(),
            }],
            auth_exempt: vec!["/webhooks/stripe".to_string(), "/hooks/*".to_string()],
            load_balancing: LoadBalancingStrategy::default(),
            upstream: Default::default(),
        }];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(
            output.contains("@noauth:/webhooks/stripe,/hooks/*"),
            "{output}"
        );

        // What we wrote must parse back to the same rule: the admin API edits
        // rules through this file, so a lossy round trip silently drops the
        // carve-outs (or the protection) on the next reload.
        let (reparsed, _) = crate::config::parse_proxy_config(&output).unwrap();
        assert_eq!(reparsed.len(), 1);
        assert_eq!(reparsed[0].auth_exempt, rules[0].auth_exempt);
        assert_eq!(reparsed[0].auth[0].username, "admin");
        assert_eq!(reparsed[0].targets[0].url.as_str(), "http://backend:8080/");
    }

    /// `@noauth` without `@auth` is a no-op the parser would read back as an
    /// empty carve-out list — writing it would only invite confusion.
    #[test]
    fn test_auth_exempt_not_written_without_auth() {
        let rules = vec![ProxyRule {
            matcher: RuleMatcher::Domain("open.example.com".to_string()),
            targets: vec![target("http://backend:8080")],
            headers: vec![],
            scripts: vec![],
            auth: vec![],
            auth_exempt: vec!["/hooks/*".to_string()],
            load_balancing: LoadBalancingStrategy::default(),
            upstream: Default::default(),
        }];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(!output.contains("@noauth"), "{output}");
    }

    /// Weights and `headers { }` blocks were dropped on the way back to disk,
    /// so the first admin-API edit of any rule erased them.
    #[test]
    fn test_weights_and_headers_roundtrip() {
        let conf = "\
/api/* -> weight:70 http://heavy:8080/, weight:30 http://light:8080/  @lb:weighted
headers {
    X-Real-IP: $client_ip
    -Cookie
}
/solo/* -> weight:7 http://solo:8080/
~^/u/(\\d+)$ -> http://u:8080/users/$1
";
        let (rules, scripts) = crate::config::parse_proxy_config(conf).unwrap();
        let output = serialize_proxy_conf(&rules, &scripts);
        assert!(output.contains("weight:70 http://heavy:8080/"), "{output}");
        assert!(output.contains("    X-Real-IP: $client_ip\n"), "{output}");
        assert!(output.contains("    -Cookie\n"), "{output}");

        let (reparsed, _) = crate::config::parse_proxy_config(&output).unwrap();
        assert_eq!(reparsed.len(), rules.len());
        for (a, b) in rules.iter().zip(&reparsed) {
            assert_eq!(a.matcher, b.matcher);
            assert_eq!(a.load_balancing, b.load_balancing, "{output}");
            let w = |r: &ProxyRule| {
                r.targets
                    .iter()
                    .map(|t| (t.url.to_string(), t.weight))
                    .collect::<Vec<_>>()
            };
            assert_eq!(w(a), w(b));
            let h = |r: &ProxyRule| {
                r.headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone(), h.remove))
                    .collect::<Vec<_>>()
            };
            assert_eq!(h(a), h(b));
        }
        // A lone weighted target keeps its strategy and its weight.
        assert_eq!(reparsed[1].load_balancing, LoadBalancingStrategy::Weighted);
        assert_eq!(reparsed[1].targets[0].weight, 7);
    }

    /// Every upstream directive survives the trip to disk and back, so an
    /// admin-API edit of an unrelated rule cannot strip a route's `@tls_ca`
    /// (which would fail it closed) or its `@h2` (which would break gRPC).
    #[test]
    fn test_upstream_directives_roundtrip() {
        let conf = "\
grpc.example.com -> h2c://grpc-a:50051, h2c://grpc-b:50051 @retries:2 @timeout:5m @health:/healthz @health_interval:3s
internal.example.com -> https://10.0.0.5:8443 @h2 @tls_ca:/etc/pki/internal-ca.pem @tls_sni:svc.internal @tls_client_cert:/etc/pki/c.pem,/etc/pki/k.pem @connect_timeout:1500ms
legacy.example.com -> https://10.0.0.6 @tls_insecure @health:off
sock.example.com -> unix:/run/app.sock
";
        let (rules, scripts) = crate::config::parse_proxy_config(conf).unwrap();
        assert_eq!(rules[0].upstream.retries, Some(2));
        assert!(rules[1].upstream.h2 && rules[2].upstream.tls_insecure);
        let output = serialize_proxy_conf(&rules, &scripts);
        assert!(output.contains("unix:/run/app.sock\n"), "{output}");
        assert!(
            output.contains("h2c://grpc-a:50051, h2c://grpc-b:50051"),
            "{output}"
        );
        let (reparsed, _) = crate::config::parse_proxy_config(&output).unwrap();
        for (a, b) in rules.iter().zip(&reparsed) {
            assert_eq!(a.upstream, b.upstream, "{output}");
            assert_eq!(a.targets.len(), b.targets.len());
            for (x, y) in a.targets.iter().zip(&b.targets) {
                assert_eq!(x.url, y.url);
            }
        }
    }

    #[test]
    fn test_serialize_regex_rule() {
        let rules = vec![ProxyRule {
            matcher: RuleMatcher::Regex(RegexMatcher::new("^/admin/.*$").unwrap()),
            targets: vec![target("http://admin:8082")],
            headers: vec![],
            scripts: vec![],
            auth: vec![],
            auth_exempt: vec![],
            load_balancing: LoadBalancingStrategy::default(),
            upstream: Default::default(),
        }];

        let output = serialize_proxy_conf(&rules, &[]);
        assert!(output.contains("~^/admin/.*$ -> http://admin:8082/"));
    }
}
