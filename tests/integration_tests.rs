use soli_proxy::config::{ConfigManager, RuleMatcher};
use tempfile::tempdir;

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

// ---- @script: and [global] config parsing tests ----

#[tokio::test]
async fn test_per_route_script_parsing() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        /api/* -> http://localhost:3000  @script:auth.lua,rate_limit.lua
        /admin/* -> http://localhost:4000  @script:auth.lua
        /public/* -> http://localhost:5000
        default -> http://localhost:8080
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 4);

    // /api/* has 2 scripts
    let api_rule = &config.rules[0];
    assert_eq!(api_rule.scripts, vec!["auth.lua", "rate_limit.lua"]);

    // /admin/* has 1 script
    let admin_rule = &config.rules[1];
    assert_eq!(admin_rule.scripts, vec!["auth.lua"]);

    // /public/* has no scripts
    let public_rule = &config.rules[2];
    assert!(public_rule.scripts.is_empty());

    // default has no scripts
    let default_rule = &config.rules[3];
    assert!(default_rule.scripts.is_empty());
}

#[tokio::test]
async fn test_global_script_parsing() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        [global] @script:cors.lua,logging.lua
        /api/* -> http://localhost:3000  @script:auth.lua
        default -> http://localhost:8080
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.global_scripts, vec!["cors.lua", "logging.lua"]);
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].scripts, vec!["auth.lua"]);
    assert!(config.rules[1].scripts.is_empty());
}

#[tokio::test]
async fn test_no_scripts_backward_compatible() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        example.com -> http://backend1:8080
        /api/* -> http://api:8081
        default -> http://localhost:3000
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert!(config.global_scripts.is_empty());
    for rule in &config.rules {
        assert!(rule.scripts.is_empty());
    }
}

#[tokio::test]
async fn test_domain_rule_with_script() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        r#"
        api.example.com -> http://backend:8080  @script:auth.lua
        default -> http://localhost:3000
    "#,
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();

    assert_eq!(config.rules.len(), 2);
    assert!(matches!(config.rules[0].matcher, RuleMatcher::Domain(_)));
    assert_eq!(config.rules[0].scripts, vec!["auth.lua"]);
}

#[tokio::test]
async fn test_global_script_reload() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");

    std::fs::write(
        &config_path,
        "[global] @script:cors.lua\ndefault -> http://localhost:3000\n",
    )
    .unwrap();

    let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
    let config = manager.get_config();
    assert_eq!(config.global_scripts, vec!["cors.lua"]);

    // Reload with different global scripts
    std::fs::write(
        &config_path,
        "[global] @script:logging.lua,metrics.lua\ndefault -> http://localhost:3000\n",
    )
    .unwrap();

    manager.reload().await.unwrap();
    let new_config = manager.get_config();
    assert_eq!(
        new_config.global_scripts,
        vec!["logging.lua", "metrics.lua"]
    );
}

// ---- Lua engine tests (require scripting feature) ----

#[cfg(feature = "scripting")]
mod scripting_tests {
    use soli_proxy::scripting::{LuaEngine, LuaRequest, RequestHookResult, RouteHookResult};
    use std::collections::HashMap;
    use std::time::Duration;
    use tempfile::tempdir;

    fn make_request(method: &str, path: &str) -> LuaRequest {
        LuaRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            host: "localhost".to_string(),
            content_length: 0,
        }
    }

    fn make_request_with_headers(
        method: &str,
        path: &str,
        headers: Vec<(&str, &str)>,
    ) -> LuaRequest {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
        }
        LuaRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: h,
            host: "localhost".to_string(),
            content_length: 0,
        }
    }

    // -- Built-in module tests --

    #[test]
    fn test_base64_module() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local encoded = base64.encode("hello:world")
                local decoded = base64.decode(encoded)
                if decoded == "hello:world" then
                    req:set_header("x-test", "pass")
                else
                    return req:deny(500, "base64 roundtrip failed: " .. decoded)
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-test").unwrap(), "pass");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_crypto_sha256_module() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local hash = crypto.sha256("hello")
                -- known SHA-256 of "hello"
                local expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                if hash == expected then
                    req:set_header("x-hash", "correct")
                else
                    return req:deny(500, "wrong hash: " .. hash)
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-hash").unwrap(), "correct");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_crypto_hmac_module() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local sig = crypto.hmac_sha256("secret-key", "message")
                -- HMAC output should be a 64-char hex string
                if #sig == 64 then
                    req:set_header("x-hmac-len", "64")
                else
                    return req:deny(500, "wrong hmac length: " .. #sig)
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-hmac-len").unwrap(), "64");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_env_module() {
        // Set an env var for the test
        std::env::set_var("SOLI_TEST_VAR", "test_value_42");

        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local val = env.get("SOLI_TEST_VAR")
                if val == "test_value_42" then
                    req:set_header("x-env", "pass")
                else
                    return req:deny(500, "wrong env value")
                end

                -- Missing var should be nil
                local missing = env.get("SOLI_NONEXISTENT_VAR_12345")
                if missing == nil then
                    req:set_header("x-nil", "pass")
                else
                    return req:deny(500, "expected nil for missing var")
                end
            end
            "#,
        )
        .unwrap();

        // `env.get` only exposes vars on the allowlist passed to the engine.
        let engine = LuaEngine::new(
            dir.path(),
            1,
            Duration::from_millis(100),
            &["SOLI_TEST_VAR".to_string()],
        )
        .unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        // Clean up
        std::env::remove_var("SOLI_TEST_VAR");

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-env").unwrap(), "pass");
                assert_eq!(r.headers.get("x-nil").unwrap(), "pass");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_time_module() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local ms = time.now_ms()
                -- Should be a large number (epoch millis > 1e12)
                if ms > 1000000000000 then
                    req:set_header("x-time", "pass")
                else
                    return req:deny(500, "time too small: " .. ms)
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-time").unwrap(), "pass");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_shared_module() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                -- get on missing key returns nil
                local v = shared.get("counter")
                if v ~= nil then
                    return req:deny(500, "expected nil for missing key")
                end

                -- incr creates and returns 1
                local c1 = shared.incr("counter")
                if c1 ~= 1 then
                    return req:deny(500, "expected 1 after first incr, got " .. c1)
                end

                -- incr again returns 2
                local c2 = shared.incr("counter")
                if c2 ~= 2 then
                    return req:deny(500, "expected 2 after second incr, got " .. c2)
                end

                -- get returns current value
                local c3 = shared.get("counter")
                if c3 ~= 2 then
                    return req:deny(500, "expected 2 from get, got " .. c3)
                end

                -- set overwrites
                shared.set("counter", 100)
                local c4 = shared.get("counter")
                if c4 ~= 100 then
                    return req:deny(500, "expected 100 after set, got " .. c4)
                end

                req:set_header("x-shared", "pass")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-shared").unwrap(), "pass");
            }
            RequestHookResult::Deny { status, body } => {
                panic!("Expected Continue, got Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn test_shared_state_persists_across_calls() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                local count = shared.incr("req_count")
                req:set_header("x-count", tostring(math.floor(count)))
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();

        // First call
        let mut req1 = make_request("GET", "/test");
        let result1 = engine.call_on_request(&mut req1);
        match result1 {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-count").unwrap(), "1");
            }
            _ => panic!("Expected Continue"),
        }

        // Second call — counter persists
        let mut req2 = make_request("GET", "/test");
        let result2 = engine.call_on_request(&mut req2);
        match result2 {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-count").unwrap(), "2");
            }
            _ => panic!("Expected Continue"),
        }
    }

    // -- Per-route script tests --

    #[test]
    fn test_route_script_on_request_deny() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("auth.lua"),
            r#"
            function on_request(req)
                local token = req:header("authorization")
                if not token then
                    return req:deny(401, "Unauthorized")
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["auth.lua".to_string()],
            &[],
        )
        .unwrap();

        assert!(engine.has_route_script("auth.lua"));

        // No auth header → deny
        let mut req = make_request("GET", "/api/test");
        let result = engine.call_route_on_request("auth.lua", &mut req);
        match result {
            RequestHookResult::Deny { status, body } => {
                assert_eq!(status, 401);
                assert_eq!(body, "Unauthorized");
            }
            _ => panic!("Expected Deny"),
        }

        // With auth header → continue
        let mut req =
            make_request_with_headers("GET", "/api/test", vec![("authorization", "Bearer tok")]);
        let result = engine.call_route_on_request("auth.lua", &mut req);
        assert!(matches!(result, RequestHookResult::Continue(_)));
    }

    #[test]
    fn test_route_script_missing_script_continues() {
        let dir = tempdir().unwrap();

        let engine =
            LuaEngine::with_route_scripts(dir.path(), 1, Duration::from_millis(100), &[], &[], &[])
                .unwrap();

        // Calling a non-existent route script should continue
        let mut req = make_request("GET", "/test");
        let result = engine.call_route_on_request("nonexistent.lua", &mut req);
        assert!(matches!(result, RequestHookResult::Continue(_)));
    }

    #[test]
    fn test_route_script_on_route_override() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("canary.lua"),
            r#"
            function on_route(req, target)
                if req:header("x-canary") == "true" then
                    return "http://canary:9000" .. req.path
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["canary.lua".to_string()],
            &[],
        )
        .unwrap();

        // Without canary header → default
        let req = make_request("GET", "/api/test");
        let result = engine.call_route_on_route("canary.lua", &req, "http://backend:8080/api/test");
        assert!(matches!(result, RouteHookResult::Default));

        // With canary header → override
        let req = make_request_with_headers("GET", "/api/test", vec![("x-canary", "true")]);
        let result = engine.call_route_on_route("canary.lua", &req, "http://backend:8080/api/test");
        match result {
            RouteHookResult::Override(url) => {
                assert_eq!(url, "http://canary:9000/api/test");
            }
            _ => panic!("Expected Override"),
        }
    }

    #[test]
    fn test_route_script_on_response() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("cors.lua"),
            r#"
            function on_response(req, resp)
                resp:set_header("x-cors", "yes")
                resp:remove_header("Server")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["cors.lua".to_string()],
            &[],
        )
        .unwrap();

        assert!(
            engine.has_route_script("cors.lua"),
            "cors.lua should be loaded as route script"
        );

        let req = make_request("GET", "/test");
        let mut resp_headers = HashMap::new();
        resp_headers.insert("server".to_string(), "nginx".to_string());
        let mods = engine.call_route_on_response("cors.lua", &req, 200, &resp_headers);

        assert!(
            !mods.set_headers.is_empty(),
            "set_headers should not be empty, got: {:?}",
            mods
        );
        assert_eq!(mods.set_headers.get("x-cors").unwrap(), "yes");
        assert!(mods.remove_headers.contains(&"Server".to_string()));
    }

    #[test]
    fn test_global_and_route_scripts_separate() {
        let dir = tempdir().unwrap();

        // Global script defines on_request
        std::fs::write(
            dir.path().join("global.lua"),
            r#"
            function on_request(req)
                req:set_header("x-global", "yes")
            end
            "#,
        )
        .unwrap();

        // Route script also defines on_request
        std::fs::write(
            dir.path().join("route_auth.lua"),
            r#"
            function on_request(req)
                if not req:header("authorization") then
                    return req:deny(401, "Need auth")
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &["global.lua".to_string()],
            &["route_auth.lua".to_string()],
            &[],
        )
        .unwrap();

        // Global on_request is available
        assert!(engine.has_on_request());
        assert!(engine.has_route_script("route_auth.lua"));

        // Global sets header
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);
        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-global").unwrap(), "yes");
            }
            _ => panic!("Expected Continue from global"),
        }

        // Route denies without auth
        let mut req = make_request("GET", "/api/test");
        let result = engine.call_route_on_request("route_auth.lua", &mut req);
        match result {
            RequestHookResult::Deny { status, .. } => {
                assert_eq!(status, 401);
            }
            _ => panic!("Expected Deny from route"),
        }
    }

    #[test]
    fn test_shared_state_across_global_and_route_scripts() {
        let dir = tempdir().unwrap();

        // Global script increments a counter
        std::fs::write(
            dir.path().join("counter.lua"),
            r#"
            function on_request(req)
                shared.incr("global_hits")
            end
            "#,
        )
        .unwrap();

        // Route script reads the same counter
        std::fs::write(
            dir.path().join("reader.lua"),
            r#"
            function on_request(req)
                local hits = shared.get("global_hits")
                if hits then
                    req:set_header("x-hits", tostring(math.floor(hits)))
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &["counter.lua".to_string()],
            &["reader.lua".to_string()],
            &[],
        )
        .unwrap();

        // Call global on_request twice to increment counter
        let mut req = make_request("GET", "/test");
        engine.call_on_request(&mut req);
        engine.call_on_request(&mut req);

        // Route script should see counter = 2
        let mut req = make_request("GET", "/test");
        let result = engine.call_route_on_request("reader.lua", &mut req);
        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-hits").unwrap(), "2");
            }
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_base64_decode_invalid_input() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                -- Lua convention: bad input yields nil, err rather than raising
                -- (a raise would abort the hook on attacker-controlled input).
                local decoded, err = base64.decode("!!!invalid!!!")
                if decoded == nil and type(err) == "string" then
                    req:set_header("x-error", "caught")
                else
                    return req:deny(500, "should have returned nil, err")
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);

        match result {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-error").unwrap(), "caught");
            }
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_on_request_end_route_script() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("logger.lua"),
            r#"
            function on_request_end(req, resp, duration_ms, target)
                -- Just verify it runs without error
                shared.set("last_status", resp.status)
                shared.set("last_duration", duration_ms)
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["logger.lua".to_string()],
            &[],
        )
        .unwrap();

        let req = make_request("GET", "/test");
        // Should not panic
        engine.call_route_on_request_end("logger.lua", &req, 200, 5.5, "http://backend:8080");
    }

    #[test]
    fn test_empty_scripts_dir() {
        let dir = tempdir().unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();

        assert!(!engine.has_on_request());
        assert!(!engine.has_on_route());
        assert!(!engine.has_on_response());
        assert!(!engine.has_on_request_end());
    }

    #[test]
    fn test_multiple_states_round_robin() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.lua"),
            r#"
            function on_request(req)
                shared.incr("calls")
                req:set_header("x-calls", tostring(math.floor(shared.get("calls"))))
            end
            "#,
        )
        .unwrap();

        // Create with 4 states
        let engine = LuaEngine::new(dir.path(), 4, Duration::from_millis(100), &[]).unwrap();

        for i in 1..=10 {
            let mut req = make_request("GET", "/test");
            let result = engine.call_on_request(&mut req);
            match result {
                RequestHookResult::Continue(r) => {
                    let count: i32 = r.headers.get("x-calls").unwrap().parse().unwrap();
                    assert_eq!(count, i);
                }
                _ => panic!("Expected Continue"),
            }
        }
    }

    #[test]
    fn test_with_route_scripts_nonexistent_dir() {
        let dir = tempdir().unwrap();
        let bad_path = dir.path().join("nonexistent");

        // Should succeed with empty scripts
        let engine =
            LuaEngine::with_route_scripts(&bad_path, 1, Duration::from_millis(100), &[], &[], &[])
                .unwrap();

        assert!(!engine.has_on_request());
    }

    #[test]
    fn on_request_error_denies_instead_of_continuing() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.lua"),
            r#"
            function on_request(req)
                error("intentional error")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        assert!(engine.has_on_request());

        // A hook that raises must fail closed: a 500 deny, never Continue.
        let mut req = make_request("GET", "/test");
        match engine.call_on_request(&mut req) {
            RequestHookResult::Deny { status, .. } => assert_eq!(status, 500),
            RequestHookResult::Continue(_) => panic!("on_request error must not fail open"),
        }
    }

    #[test]
    fn route_on_request_error_denies_instead_of_continuing() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.lua"),
            r#"
            function on_request(req)
                error("intentional error")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["bad.lua".to_string()],
            &[],
        )
        .unwrap();

        let mut req = make_request("GET", "/test");
        match engine.call_route_on_request("bad.lua", &mut req) {
            RequestHookResult::Deny { status, .. } => assert_eq!(status, 500),
            RequestHookResult::Continue(_) => panic!("route on_request error must not fail open"),
        }
    }

    #[test]
    fn on_route_error_denies_instead_of_default() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.lua"),
            r#"
            function on_route(req, target)
                error("intentional error")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &["bad.lua".to_string()],
            &["bad.lua".to_string()],
            &[],
        )
        .unwrap();
        assert!(engine.has_on_route());

        let req = make_request("GET", "/test");
        match engine.call_on_route(&req, "http://backend:8080/test") {
            RouteHookResult::Deny { status, .. } => assert_eq!(status, 500),
            other => panic!("on_route error must deny, got {:?}", other),
        }
    }

    #[test]
    fn hook_timeout_deadline_is_per_call_not_per_state() {
        // Regression: the timeout hook used to capture `deadline` once at state
        // creation and never re-arm the instruction counter, so once the
        // process had been up longer than hook_timeout every pooled state
        // spuriously raised "script execution timeout" from inside real hooks.
        // Each call here runs well over the 10,000-instruction hook interval
        // so the count hook fires (and checks the deadline) on every call.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("busy.lua"),
            r#"
            function on_request(req)
                local x = 0
                for i = 1, 8000 do
                    x = x + i
                end
                req:set_header("x-ok", "1")
            end
            "#,
        )
        .unwrap();

        let hook_timeout = Duration::from_millis(20);
        let engine = LuaEngine::new(dir.path(), 1, hook_timeout, &[]).unwrap();

        // Let the state outlive the (formerly one-shot) deadline.
        std::thread::sleep(hook_timeout * 2);

        for n in 0..5_000 {
            let mut req = make_request("GET", "/test");
            match engine.call_on_request(&mut req) {
                RequestHookResult::Continue(r) => {
                    assert_eq!(
                        r.headers.get("x-ok").map(String::as_str),
                        Some("1"),
                        "call {} did not complete",
                        n
                    );
                }
                RequestHookResult::Deny { status, body } => {
                    panic!("call {} denied: {} {}", n, status, body);
                }
            }
        }
    }

    #[test]
    fn hook_timeout_still_stops_runaway_script() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("spin.lua"),
            r#"
            function on_request(req)
                while true do end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(10), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        let started = std::time::Instant::now();
        let result = engine.call_on_request(&mut req);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout did not fire"
        );
        assert!(matches!(
            result,
            RequestHookResult::Deny { status: 500, .. }
        ));
    }

    #[test]
    fn base64_decode_returns_nil_on_bad_input() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("b64.lua"),
            r#"
            function on_request(req)
                local decoded, err = base64.decode("!!!!")
                if decoded ~= nil then
                    return req:deny(500, "expected nil, got " .. tostring(decoded))
                end
                if type(err) ~= "string" then
                    return req:deny(500, "expected error message")
                end
                req:set_header("x-b64", "nil")
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        let mut req = make_request("GET", "/test");
        match engine.call_on_request(&mut req) {
            RequestHookResult::Continue(r) => {
                assert_eq!(r.headers.get("x-b64").map(String::as_str), Some("nil"));
            }
            RequestHookResult::Deny { status, body } => {
                panic!("base64.decode must not raise: Deny({}, {})", status, body);
            }
        }
    }

    #[test]
    fn auth_lua_denies_malformed_basic_credentials() {
        // The shipped auth.lua must reject an undecodable Basic token with a
        // 401 instead of letting it through (it used to raise inside
        // base64.decode, which was mapped to Continue).
        let scripts_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/lua");
        let engine = LuaEngine::with_route_scripts(
            &scripts_dir,
            1,
            Duration::from_millis(100),
            &[],
            &["auth.lua".to_string()],
            &[],
        )
        .unwrap();
        assert!(engine.has_route_script("auth.lua"));

        let mut req =
            make_request_with_headers("GET", "/api/x", vec![("authorization", "Basic !!!!")]);
        match engine.call_route_on_request("auth.lua", &mut req) {
            RequestHookResult::Deny { status, .. } => assert_eq!(status, 401),
            RequestHookResult::Continue(_) => panic!("malformed Basic token must be denied"),
        }
    }
}

// ---- Route-script end-to-end tests (real proxy + backend) ----

#[cfg(feature = "scripting")]
mod route_script_e2e_tests {
    use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    use soli_proxy::{
        new_challenge_store, new_metrics, ConfigManager, LuaEngine, ProxyServer,
        ShutdownCoordinator,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal HTTP/1.1 backend: answers every request with the value of the
    /// request's `x-user` header as the body.
    async fn spawn_echo_x_user_backend() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let user = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim()
                                .eq_ignore_ascii_case("x-user")
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        user.len(),
                        user
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    async fn wait_for_port(port: u16) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("proxy did not start on port {} within 2 seconds", port);
    }

    #[tokio::test]
    async fn route_script_set_header_overrides_client_supplied_header() {
        // The proxy's TLS connector needs a process-default crypto provider
        // (main.rs installs it at startup; tests must do it themselves).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let backend_port = spawn_echo_x_user_backend().await;

        let dir = tempdir().unwrap();
        let scripts_dir = dir.path().join("lua");
        std::fs::create_dir_all(&scripts_dir).unwrap();
        std::fs::write(
            scripts_dir.join("setuser.lua"),
            r#"
            function on_request(req)
                req:set_header("x-user", "from-script")
            end
            "#,
        )
        .unwrap();

        let proxy_port = portpicker::pick_unused_port().unwrap();
        let conf_path = dir.path().join("proxy.conf");
        std::fs::write(
            &conf_path,
            format!(
                "/api/* -> http://127.0.0.1:{}/ @script:setuser.lua\n",
                backend_port
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[server]\nbind = \"127.0.0.1:{}\"\nhttps_port = 443\n\n\
                 [scripting]\nenabled = true\nscripts_dir = \"{}\"\n",
                proxy_port,
                scripts_dir.display()
            ),
        )
        .unwrap();

        let manager = Arc::new(ConfigManager::new(conf_path.to_str().unwrap()).unwrap());
        let engine = LuaEngine::with_route_scripts(
            &scripts_dir,
            1,
            Duration::from_millis(100),
            &[],
            &["setuser.lua".to_string()],
            &[],
        )
        .unwrap();
        let shutdown = ShutdownCoordinator::new();
        let server = ProxyServer::new(
            manager,
            shutdown.clone(),
            new_metrics(),
            new_challenge_store(),
            Some(engine),
            Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default())),
            None,
            None,
        )
        .unwrap();
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        wait_for_port(proxy_port).await;

        // The client sends its own x-user; the route script's set_header must
        // win at the backend (it used to be discarded, forwarding the
        // client's value verbatim).
        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/api/whoami", proxy_port))
            .header("x-user", "attacker")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "from-script");

        shutdown.initiate();
        // Keep temp_dir alive for the (still running) config watcher.
        std::mem::forget(dir);
    }
}

// ---- Admin API tests ----

mod admin_tests {
    use super::*;
    use soli_proxy::admin::{run_admin_server, AdminState};
    use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    use soli_proxy::new_metrics;
    use std::sync::Arc;
    use std::time::Instant;

    /// Helper: start an admin server on a random port and return (port, config_manager)
    async fn start_admin(proxy_conf_content: &str) -> (u16, Arc<ConfigManager>) {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("proxy.conf");
        let toml_path = temp_dir.path().join("config.toml");

        std::fs::write(&config_path, proxy_conf_content).unwrap();
        let port = portpicker::pick_unused_port().unwrap_or(19090);
        std::fs::write(
            &toml_path,
            format!("[admin]\nenabled = true\nbind = \"127.0.0.1:{}\"\n", port),
        )
        .unwrap();

        let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
        let config_ref = Arc::new(manager);

        let state = Arc::new(AdminState {
            config_manager: config_ref.clone(),
            metrics: new_metrics(),
            start_time: Instant::now(),
            circuit_breaker: Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default())),
            app_manager: None,
            rate_limiter: None,
            tls_manager: None,
            challenge_store: None,
        });

        tokio::spawn(async move {
            let _ = run_admin_server(state).await;
        });

        // Wait for server to accept connections
        wait_for_port(port).await;

        // Keep temp_dir alive by leaking it (test-only)
        std::mem::forget(temp_dir);

        (port, config_ref)
    }

    async fn wait_for_port(port: u16) {
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!(
            "Admin server did not start on port {} within 1 second",
            port
        );
    }

    async fn get(port: u16, path: &str) -> (u16, String) {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let client = reqwest::Client::new();
        let resp = client.get(&url).send().await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap();
        (status, body)
    }

    async fn post(port: u16, path: &str, body: &str) -> (u16, String) {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Requested-With", "test")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        (status, text)
    }

    async fn put(port: u16, path: &str, body: &str) -> (u16, String) {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let client = reqwest::Client::new();
        let resp = client
            .put(&url)
            .header("Content-Type", "application/json")
            .header("X-Requested-With", "test")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        (status, text)
    }

    async fn delete(port: u16, path: &str) -> u16 {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let client = reqwest::Client::new();
        let resp = client
            .delete(&url)
            .header("X-Requested-With", "test")
            .send()
            .await
            .unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn test_admin_get_status() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;

        let (status, body) = get(port, "/api/v1/status").await;
        assert_eq!(status, 200);

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["data"]["version"].is_string());
        assert_eq!(json["data"]["route_count"], 1);
    }

    #[tokio::test]
    async fn test_admin_get_routes() {
        let (port, _mgr) =
            start_admin("default -> http://localhost:3000\n/api/* -> http://localhost:8888\n")
                .await;

        let (status, body) = get(port, "/api/v1/routes").await;
        assert_eq!(status, 200);

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);
        let routes = json["data"].as_array().unwrap();
        assert_eq!(routes.len(), 2);
    }

    #[tokio::test]
    async fn test_admin_get_route_by_index() {
        let (port, _mgr) =
            start_admin("default -> http://localhost:3000\n/api/* -> http://localhost:8888\n")
                .await;

        let (status, body) = get(port, "/api/v1/routes/0").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["data"]["matcher"]["type"], "default");

        let (status, body) = get(port, "/api/v1/routes/1").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["data"]["matcher"]["type"], "prefix");

        // Out of range
        let (status, _) = get(port, "/api/v1/routes/99").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_admin_get_config() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;

        let (status, body) = get(port, "/api/v1/config").await;
        assert_eq!(status, 200);

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(json["data"]["server"].is_object());
        assert!(json["data"]["rules"].is_array());
    }

    #[tokio::test]
    async fn test_admin_settings_default_and_roundtrip() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;

        // Defaults to the emerald preset when no settings file exists.
        let (status, body) = get(port, "/api/v1/settings").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["data"]["theme"], "emerald");

        // A valid preset persists and is read back.
        let (status, _) = put(port, "/api/v1/settings", r#"{"theme":"ocean"}"#).await;
        assert_eq!(status, 200);

        let (status, body) = get(port, "/api/v1/settings").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["data"]["theme"], "ocean");

        // Unknown presets are rejected.
        let (status, _) = put(port, "/api/v1/settings", r#"{"theme":"bogus"}"#).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn test_admin_get_metrics() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;

        let (status, body) = get(port, "/api/v1/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("proxy_requests_total"));
    }

    #[tokio::test]
    async fn test_admin_post_reload() {
        let (port, mgr) = start_admin("default -> http://localhost:3000\n").await;

        assert_eq!(mgr.get_config().rules.len(), 1);

        // Write a new config file
        let config_path = mgr.config_path().to_path_buf();
        std::fs::write(
            &config_path,
            "default -> http://localhost:4000\n/new/* -> http://localhost:5000\n",
        )
        .unwrap();

        let (status, body) = post(port, "/api/v1/reload", "").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);

        assert_eq!(mgr.get_config().rules.len(), 2);
    }

    #[tokio::test]
    async fn test_admin_post_route() {
        let (port, mgr) = start_admin("default -> http://localhost:3000\n").await;
        assert_eq!(mgr.get_config().rules.len(), 1);

        let new_route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/new/" },
            "targets": [{ "url": "http://localhost:9999/", "weight": 100 }],
            "headers": [],
            "scripts": []
        });

        let (status, body) = post(port, "/api/v1/routes", &new_route.to_string()).await;
        assert_eq!(status, 201);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], true);

        assert_eq!(mgr.get_config().rules.len(), 2);
    }

    #[tokio::test]
    async fn test_admin_put_route() {
        let (port, mgr) =
            start_admin("default -> http://localhost:3000\n/api/* -> http://localhost:8888\n")
                .await;

        let updated_route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/api/v2/" },
            "targets": [{ "url": "http://localhost:7777/", "weight": 100 }],
            "headers": [],
            "scripts": []
        });

        let (status, _) = put(port, "/api/v1/routes/1", &updated_route.to_string()).await;
        assert_eq!(status, 200);

        let cfg = mgr.get_config();
        assert_eq!(cfg.rules.len(), 2);
        match &cfg.rules[1].matcher {
            RuleMatcher::Prefix(p) => assert_eq!(p, "/api/v2/"),
            _ => panic!("Expected Prefix matcher"),
        }
    }

    /// Re-parse proxy.conf from disk the way a restart would, so the test
    /// checks what was persisted rather than what is in memory.
    fn reparse(mgr: &ConfigManager) -> soli_proxy::Config {
        let fresh = ConfigManager::new(mgr.config_path().to_str().unwrap()).unwrap();
        (*fresh.get_config()).clone()
    }

    const HASH_A: &str = "$2b$12$YFlnIiACnSaAcxDWQlYjeedxq/3GvhvoGhRTYHMqLifJrETSqOZQa";

    #[tokio::test]
    async fn route_auth_hash_survives_put_and_reparse() {
        // Regression: `#[serde(skip)]` on BasicAuth.hash also skipped
        // deserialization, so every route written through the API had an
        // empty hash, `@auth:user:` went to disk, and the next reload dropped
        // the entry — editing a protected route silently unprotected it.
        let (port, mgr) = start_admin("default -> http://localhost:3000\n").await;

        let route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/db/" },
            "targets": [{ "url": "http://localhost:8080/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "auth": [{ "username": "demo", "hash": HASH_A }]
        });
        let (status, body) = put(port, "/api/v1/routes/0", &route.to_string()).await;
        assert_eq!(status, 200, "{body}");

        let in_memory = mgr.get_config();
        assert_eq!(in_memory.rules[0].auth.len(), 1);
        assert_eq!(in_memory.rules[0].auth[0].hash, HASH_A);

        let on_disk = reparse(&mgr);
        assert_eq!(on_disk.rules[0].auth.len(), 1, "@auth entry lost on disk");
        assert_eq!(on_disk.rules[0].auth[0].hash, HASH_A);

        // The hash must never come back out of the API.
        let (_, body) = get(port, "/api/v1/routes/0").await;
        assert!(!body.contains(HASH_A));
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["data"]["auth"][0].get("hash").is_none());
    }

    #[tokio::test]
    async fn route_put_with_empty_hash_keeps_existing_user_hash() {
        // The UI never sees the hash, so it re-submits existing users with
        // `hash: ""` meaning "keep". The old hash must be carried forward.
        let (port, mgr) = start_admin(&format!(
            "default -> http://localhost:3000\n/db/* -> http://localhost:8080/ @auth:demo:{}\n",
            HASH_A
        ))
        .await;
        assert_eq!(mgr.get_config().rules[1].auth[0].hash, HASH_A);

        let route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/db/" },
            "targets": [{ "url": "http://localhost:8081/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "auth": [{ "username": "demo", "hash": "" }]
        });
        let (status, body) = put(port, "/api/v1/routes/1", &route.to_string()).await;
        assert_eq!(status, 200, "{body}");

        assert_eq!(mgr.get_config().rules[1].auth[0].hash, HASH_A);
        assert_eq!(reparse(&mgr).rules[1].auth[0].hash, HASH_A);

        // A missing `hash` field (exactly what GET returns) means the same.
        let route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/db/" },
            "targets": [{ "url": "http://localhost:8082/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "auth": [{ "username": "demo" }]
        });
        let (status, body) = put(port, "/api/v1/routes/1", &route.to_string()).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(reparse(&mgr).rules[1].auth[0].hash, HASH_A);
    }

    #[tokio::test]
    async fn route_with_new_user_and_empty_hash_is_rejected() {
        let (port, mgr) = start_admin(&format!(
            "default -> http://localhost:3000\n/db/* -> http://localhost:8080/ @auth:demo:{}\n",
            HASH_A
        ))
        .await;

        let route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/db/" },
            "targets": [{ "url": "http://localhost:8080/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "auth": [{ "username": "newcomer", "hash": "" }]
        });

        // PUT on the existing route: "newcomer" is not on it, nothing to keep.
        let (status, body) = put(port, "/api/v1/routes/1", &route.to_string()).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("auth entry for newcomer has no password hash"));

        // POST a new route: there is never anything to inherit from.
        let (status, body) = post(port, "/api/v1/routes", &route.to_string()).await;
        assert_eq!(status, 400, "{body}");

        // PUT /config pairs rules by matcher; the /db/ rule still has demo only.
        let (status, body) = put(
            port,
            "/api/v1/config",
            &serde_json::json!({ "rules": [mgr.get_config().rules[0], route] }).to_string(),
        )
        .await;
        assert_eq!(status, 400, "{body}");

        // Nothing was written: the original entry is intact on disk.
        assert_eq!(reparse(&mgr).rules[1].auth[0].hash, HASH_A);
        assert_eq!(reparse(&mgr).rules.len(), 2);
    }

    /// A whole-table PUT that deletes or reorders rules must not pair a
    /// `hash: ""` entry with whatever rule used to sit at the same index:
    /// that would hand `/b/` the password of `/a/`, or reject the deletion
    /// outright when the usernames differ.
    #[tokio::test]
    async fn config_put_carries_auth_hashes_by_matcher_not_index() {
        const HASH_A: &str = "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const HASH_B: &str = "$2b$12$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let (port, mgr) = start_admin(&format!(
            "default -> http://localhost:3000\n\
             /a/* -> http://localhost:8081 @auth:admin:{HASH_A}\n\
             /b/* -> http://localhost:8082 @auth:ops:{HASH_B}\n"
        ))
        .await;
        let rules = mgr.get_config().rules.clone();
        assert_eq!(rules.len(), 3);

        // Delete /a/ (index 1); /b/ moves to index 1 and is re-submitted with
        // an empty hash, exactly as a client that only ever saw hash-less
        // config from GET would send it.
        let mut b = serde_json::to_value(&rules[2]).unwrap();
        b["auth"] = serde_json::json!([{ "username": "ops", "hash": "" }]);
        let (status, body) = put(
            port,
            "/api/v1/config",
            &serde_json::json!({ "rules": [rules[0], b] }).to_string(),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let on_disk = reparse(&mgr);
        assert_eq!(on_disk.rules.len(), 2);
        assert_eq!(on_disk.rules[1].auth[0].username, "ops");
        assert_eq!(on_disk.rules[1].auth[0].hash, HASH_B);

        // A username the moved rule never had is still rejected, even though
        // the rule formerly at that index knew it.
        let mut b = serde_json::to_value(&rules[2]).unwrap();
        b["auth"] = serde_json::json!([{ "username": "admin", "hash": "" }]);
        let (status, body) = put(
            port,
            "/api/v1/config",
            &serde_json::json!({ "rules": [rules[0], b] }).to_string(),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(reparse(&mgr).rules[1].auth[0].hash, HASH_B);
    }

    #[tokio::test]
    async fn route_rejects_unknown_fields() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;
        let route = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/x/" },
            "targets": [{ "url": "http://localhost:8080/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "smuggled": 1
        });
        let (status, _) = post(port, "/api/v1/routes", &route.to_string()).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn test_admin_delete_route() {
        let (port, mgr) =
            start_admin("default -> http://localhost:3000\n/api/* -> http://localhost:8888\n")
                .await;
        assert_eq!(mgr.get_config().rules.len(), 2);

        let status = delete(port, "/api/v1/routes/1").await;
        assert_eq!(status, 204);

        assert_eq!(mgr.get_config().rules.len(), 1);
    }

    #[tokio::test]
    async fn test_admin_not_found() {
        let (port, _mgr) = start_admin("default -> http://localhost:3000\n").await;

        let (status, body) = get(port, "/nonexistent").await;
        assert_eq!(status, 404);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], false);
    }

    #[tokio::test]
    async fn test_admin_auth_required() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("proxy.conf");
        let toml_path = temp_dir.path().join("config.toml");

        std::fs::write(&config_path, "default -> http://localhost:3000\n").unwrap();
        let port = portpicker::pick_unused_port().unwrap_or(19091);
        std::fs::write(
            &toml_path,
            format!(
                "[admin]\nenabled = true\nbind = \"127.0.0.1:{}\"\napi_key = \"secret123\"\n",
                port
            ),
        )
        .unwrap();

        let manager = ConfigManager::new(config_path.to_str().unwrap()).unwrap();
        let config_ref = Arc::new(manager);
        let state = Arc::new(AdminState {
            config_manager: config_ref,
            metrics: new_metrics(),
            start_time: Instant::now(),
            circuit_breaker: Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default())),
            app_manager: None,
            rate_limiter: None,
            tls_manager: None,
            challenge_store: None,
        });
        tokio::spawn(async move {
            let _ = run_admin_server(state).await;
        });
        wait_for_port(port).await;
        std::mem::forget(temp_dir);

        // No auth header → 401
        let (status, _) = get(port, "/api/v1/status").await;
        assert_eq!(status, 401);

        // With correct auth header → 200
        let url = format!("http://127.0.0.1:{}/api/v1/status", port);
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .header("X-Api-Key", "secret123")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);

        // Wrong key → 401
        let resp = client
            .get(&url)
            .header("X-Api-Key", "wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
    }
}

#[test]
fn test_cli_deploy_command_args() {
    let args = ["soli-proxy", "deploy", "myapp"];
    let cli = clap::Command::new("soli-proxy")
        .subcommand(
            clap::Command::new("deploy")
                .arg(
                    clap::Arg::new("conf")
                        .short('c')
                        .long("conf")
                        .default_value("./proxy.conf"),
                )
                .arg(clap::Arg::new("app_name").required(true)),
        )
        .try_get_matches_from(args.iter())
        .unwrap();

    if let Some(sub) = cli.subcommand_matches("deploy") {
        assert_eq!(sub.get_one::<String>("app_name").unwrap(), "myapp");
        assert_eq!(sub.get_one::<String>("conf").unwrap(), "./proxy.conf");
    } else {
        panic!("deploy subcommand not found");
    }
}

#[test]
fn test_cli_restart_command_args() {
    let args = ["soli-proxy", "restart", "-c", "/path/to/conf", "myapp"];
    let cli = clap::Command::new("soli-proxy")
        .subcommand(
            clap::Command::new("restart")
                .arg(
                    clap::Arg::new("conf")
                        .short('c')
                        .long("conf")
                        .default_value("./proxy.conf"),
                )
                .arg(clap::Arg::new("app_name").required(true)),
        )
        .try_get_matches_from(args.iter())
        .unwrap();

    if let Some(sub) = cli.subcommand_matches("restart") {
        assert_eq!(sub.get_one::<String>("app_name").unwrap(), "myapp");
        assert_eq!(sub.get_one::<String>("conf").unwrap(), "/path/to/conf");
    } else {
        panic!("restart subcommand not found");
    }
}

#[test]
fn test_cli_stop_command_args() {
    let args = ["soli-proxy", "stop", "myapp"];
    let cli = clap::Command::new("soli-proxy")
        .subcommand(
            clap::Command::new("stop")
                .arg(
                    clap::Arg::new("conf")
                        .short('c')
                        .long("conf")
                        .default_value("./proxy.conf"),
                )
                .arg(clap::Arg::new("app_name").required(true)),
        )
        .try_get_matches_from(args.iter())
        .unwrap();

    if let Some(sub) = cli.subcommand_matches("stop") {
        assert_eq!(sub.get_one::<String>("app_name").unwrap(), "myapp");
    } else {
        panic!("stop subcommand not found");
    }
}

#[test]
fn test_cli_logs_command_args() {
    let args = ["soli-proxy", "logs", "-c", "/custom/conf", "myapp"];
    let cli = clap::Command::new("soli-proxy")
        .subcommand(
            clap::Command::new("logs")
                .arg(
                    clap::Arg::new("conf")
                        .short('c')
                        .long("conf")
                        .default_value("./proxy.conf"),
                )
                .arg(clap::Arg::new("app_name").required(true)),
        )
        .try_get_matches_from(args.iter())
        .unwrap();

    if let Some(sub) = cli.subcommand_matches("logs") {
        assert_eq!(sub.get_one::<String>("app_name").unwrap(), "myapp");
        assert_eq!(sub.get_one::<String>("conf").unwrap(), "/custom/conf");
    } else {
        panic!("logs subcommand not found");
    }
}

#[test]
fn test_cli_update_command_with_reinstall() {
    let args = ["soli-proxy", "update", "--reinstall"];
    let cli = clap::Command::new("soli-proxy")
        .subcommand(
            clap::Command::new("update").arg(
                clap::Arg::new("reinstall")
                    .long("reinstall")
                    .action(clap::ArgAction::SetTrue),
            ),
        )
        .try_get_matches_from(args.iter())
        .unwrap();

    if let Some(sub) = cli.subcommand_matches("update") {
        assert!(sub.get_flag("reinstall"));
    } else {
        panic!("update subcommand not found");
    }
}
