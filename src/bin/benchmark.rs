use soli_proxy::config::RuleMatcher;

fn main() {
    let config_content = r#"
default -> http://localhost:3000
example.com -> http://backend1:8080
api.example.com/users -> http://backend2:8081
/api/* -> http://api:8082
~^/admin/.*$ -> http://admin:8083
"#;

    let rules = parse_proxy_config(config_content).unwrap();

    println!("==========================================");
    println!("Soli Proxy - Routing Performance Benchmark");
    println!("==========================================");
    println!("Rules configured: {}", rules.len());
    println!();

    let test_cases = vec![
        ("example.com", "/", "Domain-only (root)"),
        ("example.com", "/any/path/here", "Domain-only (nested path)"),
        ("api.example.com", "/users", "Domain+exact-path"),
        ("api.example.com", "/foo", "Domain+path prefix fallback"),
        ("other.com", "/api/test", "Path-only (no domain match)"),
        ("test.com", "/admin/dashboard", "Regex match"),
    ];

    let mut results: Vec<(String, u128)> = Vec::new();

    for (host, path, desc) in &test_cases {
        let uri: http::Uri = format!("http://{}{}", host, path).parse().unwrap();

        let iterations = 100_000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = find_target(uri.host(), path, &rules);
        }
        let elapsed = start.elapsed();

        let ns_per_op = elapsed.as_nanos() / iterations;
        let ops_per_sec = 1_000_000_000_000 / elapsed.as_nanos() * iterations;

        results.push((desc.to_string(), ns_per_op));

        println!(
            "{:35} {:>10} ns/op  {:>15} ops/s",
            desc,
            ns_per_op,
            format!("{:?}", ops_per_sec)
        );
    }

    println!();
    println!("==========================================");
    let avg: u128 = results.iter().map(|(_, ns)| ns).sum::<u128>() / results.len() as u128;
    println!("Average: {} ns/op", avg);
    println!("==========================================");
}

fn parse_proxy_config(content: &str) -> Result<Vec<soli_proxy::config::ProxyRule>, regex::Error> {
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
                RuleMatcher::Regex(
                    soli_proxy::config::RegexMatcher::new(pattern)
                        .map_err(|_| regex::Error::Syntax("bad regex".to_string()))?,
                )
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

            let target = url::Url::parse(target_str).unwrap();
            let target = soli_proxy::config::Target {
                url: target,
                weight: 100,
            };

            rules.push(soli_proxy::config::ProxyRule {
                matcher,
                targets: vec![target],
                headers: vec![],
                scripts: vec![],
            });
        }
    }

    Ok(rules)
}

fn find_target(
    host: Option<&str>,
    path: &str,
    rules: &[soli_proxy::config::ProxyRule],
) -> Option<(String, bool)> {
    let host = host?;
    let mut matched_domain = false;

    for rule in rules {
        match &rule.matcher {
            RuleMatcher::Domain(domain) => {
                if domain == host {
                    matched_domain = true;
                    if let Some(target) = rule.targets.first() {
                        let target_url = target.url.to_string();
                        let final_url = format!("{}{}", target_url, path);
                        return Some((final_url, true));
                    }
                }
            }
            RuleMatcher::DomainPath(domain, path_prefix) => {
                if domain == host && path.starts_with(path_prefix) {
                    if let Some(target) = rule.targets.first() {
                        let target_url = target.url.to_string();
                        let suffix = &path[path_prefix.len()..];
                        let final_url = format!("{}{}", target_url, suffix);
                        return Some((final_url, true));
                    }
                }
            }
            _ => {}
        }
    }

    if matched_domain {
        return None;
    }

    for rule in rules {
        match &rule.matcher {
            RuleMatcher::Default => {
                if let Some(target) = rule.targets.first() {
                    let target_url = target.url.to_string();
                    let final_url = format!("{}{}", target_url, path);
                    return Some((final_url, false));
                }
            }
            RuleMatcher::Prefix(prefix) => {
                if path.starts_with(prefix) {
                    if let Some(target) = rule.targets.first() {
                        let target_url = target.url.to_string();
                        let suffix = &path[prefix.len()..];
                        let final_url = format!("{}{}", target_url, suffix);
                        return Some((final_url, false));
                    }
                }
            }
            RuleMatcher::Exact(exact) => {
                if path == exact {
                    if let Some(target) = rule.targets.first() {
                        return Some((target.url.to_string(), false));
                    }
                }
            }
            RuleMatcher::Regex(ref rm) => {
                if rm.is_match(path) {
                    if let Some(target) = rule.targets.first() {
                        return Some((target.url.to_string(), false));
                    }
                }
            }
            _ => {}
        }
    }

    None
}
