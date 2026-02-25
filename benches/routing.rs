use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soli_proxy::config::{LoadBalancingStrategy, ProxyRule, RegexMatcher, RuleMatcher, Target};

fn parse_proxy_config(content: &str) -> Vec<ProxyRule> {
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
                RuleMatcher::Regex(RegexMatcher::new(pattern).expect("bad regex"))
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

            let url = url::Url::parse(target_str).unwrap();
            let target = Target { url, weight: 100 };

            rules.push(ProxyRule {
                matcher,
                targets: vec![target],
                headers: vec![],
                scripts: vec![],
                auth: vec![],
                load_balancing: LoadBalancingStrategy::default(),
            });
        }
    }

    rules
}

fn find_target(
    host: Option<&str>,
    path: &str,
    rules: &[ProxyRule],
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

fn generate_rules(count: usize) -> Vec<ProxyRule> {
    let mut lines = Vec::new();
    for i in 0..count {
        lines.push(format!(
            "app{}.example.com -> http://backend{}:8080",
            i, i
        ));
    }
    lines.push("default -> http://fallback:8080".to_string());
    parse_proxy_config(&lines.join("\n"))
}

fn bench_rule_matching(c: &mut Criterion) {
    let config_content = r#"
default -> http://localhost:3000
example.com -> http://backend1:8080
api.example.com/users -> http://backend2:8081
/api/* -> http://api:8082
~^/admin/.*$ -> http://admin:8083
"#;
    let rules = parse_proxy_config(config_content);

    let mut group = c.benchmark_group("rule_matching");

    group.bench_function("domain_root", |b| {
        b.iter(|| find_target(black_box(Some("example.com")), black_box("/"), &rules))
    });

    group.bench_function("domain_nested", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("example.com")),
                black_box("/any/path/here"),
                &rules,
            )
        })
    });

    group.bench_function("domain_path", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("api.example.com")),
                black_box("/users"),
                &rules,
            )
        })
    });

    group.bench_function("prefix", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("other.com")),
                black_box("/api/test"),
                &rules,
            )
        })
    });

    group.bench_function("regex", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("test.com")),
                black_box("/admin/dashboard"),
                &rules,
            )
        })
    });

    group.bench_function("default_fallback", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("unknown.com")),
                black_box("/some/path"),
                &rules,
            )
        })
    });

    group.finish();
}

fn bench_rule_scaling(c: &mut Criterion) {
    let rules_5 = generate_rules(5);
    let rules_50 = generate_rules(50);
    let rules_500 = generate_rules(500);

    let mut group = c.benchmark_group("rule_scaling");

    // Worst case: match the default rule (last), forcing a full scan
    group.bench_function("5_rules_default", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("nomatch.com")),
                black_box("/path"),
                &rules_5,
            )
        })
    });

    group.bench_function("50_rules_default", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("nomatch.com")),
                black_box("/path"),
                &rules_50,
            )
        })
    });

    group.bench_function("500_rules_default", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("nomatch.com")),
                black_box("/path"),
                &rules_500,
            )
        })
    });

    // Best case: match the first domain rule
    group.bench_function("5_rules_first", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("app0.example.com")),
                black_box("/"),
                &rules_5,
            )
        })
    });

    group.bench_function("50_rules_first", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("app0.example.com")),
                black_box("/"),
                &rules_50,
            )
        })
    });

    group.bench_function("500_rules_first", |b| {
        b.iter(|| {
            find_target(
                black_box(Some("app0.example.com")),
                black_box("/"),
                &rules_500,
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_rule_matching, bench_rule_scaling);
criterion_main!(benches);
