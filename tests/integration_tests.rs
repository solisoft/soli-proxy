use soli_proxy::config::{ConfigManager, RuleMatcher};

#[tokio::test]
async fn test_config_hot_reload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");
    let toml_path = temp_dir.path().join("config.toml");

    std::fs::write(&config_path, "default -> http://localhost:3000\n").unwrap();
    std::fs::write(&toml_path, "").unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();
    assert_eq!(config.rules.len(), 1);

    std::fs::write(
        &config_path,
        "default -> http://localhost:4000\n/api/* -> http://localhost:5000\n",
    )
    .unwrap();

    manager.reload().await.unwrap();
    let new_config = manager.get_config();
    assert_eq!(new_config.rules.len(), 2);
}

#[tokio::test]
async fn test_domain_only_parsing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        default -> http://localhost:3000
        example.com -> http://backend1:8080
        api.example.com -> http://backend2:8081
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 3);

    let domain_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::Domain(_)))
        .collect();
    assert_eq!(domain_rules.len(), 2);
}

#[tokio::test]
async fn test_domain_path_parsing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        default -> http://localhost:3000
        example.com/api/* -> http://api:8080
        app.example.com/admin/* -> http://admin:8081
        example.com/secure/* -> http://secure:8082
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 4);

    let domain_path_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::DomainPath(_, _)))
        .collect();
    assert_eq!(domain_path_rules.len(), 3);
}

#[tokio::test]
async fn test_mixed_domain_and_path_rules() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        default -> http://localhost:3000
        example.com -> http://backend1:8080
        /api/* -> http://api:8081
        ~^/admin/.*$ -> http://admin:8082
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 4);

    let domain_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::Domain(_)))
        .collect();
    assert_eq!(domain_rules.len(), 1);

    let prefix_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::Prefix(_)))
        .collect();
    assert_eq!(prefix_rules.len(), 1);

    let regex_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::Regex(_)))
        .collect();
    assert_eq!(regex_rules.len(), 1);
}

#[tokio::test]
async fn test_ip_address_as_domain() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        default -> http://localhost:3000
        192.168.1.1 -> http://internal:8080
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 2);

    let domain_rules: Vec<_> = config
        .rules
        .iter()
        .filter(|r| matches!(r.matcher, RuleMatcher::Domain(_)))
        .collect();
    assert_eq!(domain_rules.len(), 1);
}
