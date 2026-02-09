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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();

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
        let mut req = make_request_with_headers("GET", "/api/test", vec![("authorization", "Bearer tok")]);
        let result = engine.call_route_on_request("auth.lua", &mut req);
        assert!(matches!(result, RequestHookResult::Continue(_)));
    }

    #[test]
    fn test_route_script_missing_script_continues() {
        let dir = tempdir().unwrap();

        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &[],
        )
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
                local ok, err = pcall(function()
                    base64.decode("!!!invalid!!!")
                end)
                if not ok then
                    req:set_header("x-error", "caught")
                else
                    return req:deny(500, "should have errored")
                end
            end
            "#,
        )
        .unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
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
        )
        .unwrap();

        let req = make_request("GET", "/test");
        // Should not panic
        engine.call_route_on_request_end("logger.lua", &req, 200, 5.5, "http://backend:8080");
    }

    #[test]
    fn test_empty_scripts_dir() {
        let dir = tempdir().unwrap();

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();

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
        let engine = LuaEngine::new(dir.path(), 4, Duration::from_millis(100)).unwrap();

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
        let engine = LuaEngine::with_route_scripts(
            &bad_path,
            1,
            Duration::from_millis(100),
            &[],
            &[],
        )
        .unwrap();

        assert!(!engine.has_on_request());
    }

    #[test]
    fn test_script_error_continues() {
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

        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100)).unwrap();
        assert!(engine.has_on_request());

        // Script error should not crash, should continue
        let mut req = make_request("GET", "/test");
        let result = engine.call_on_request(&mut req);
        assert!(matches!(result, RequestHookResult::Continue(_)));
    }
}
