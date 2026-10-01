//! The Lua scripts shipped in `scripts/lua/` (and named in config.toml's
//! comments) load, and the ones with security-relevant behaviour do what
//! their comments say.
#![cfg(feature = "scripting")]

use soli_proxy::scripting::{LuaRequest, RequestHookResult};
use soli_proxy::LuaEngine;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

fn scripts_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/lua"))
}

fn engine(script: &str) -> LuaEngine {
    LuaEngine::with_route_scripts(
        scripts_dir(),
        1,
        Duration::from_millis(200),
        &[],
        &[script.to_string()],
        &[],
    )
    .unwrap_or_else(|e| panic!("{script} failed to load: {e}"))
}

fn request(method: &str, headers: &[(&str, &str)]) -> LuaRequest {
    LuaRequest {
        method: method.to_string(),
        path: "/api/items".to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        host: "api.example.com".to_string(),
        content_length: 0,
        ..Default::default()
    }
}

#[test]
fn every_shipped_script_loads() {
    let mut names: Vec<String> = std::fs::read_dir(scripts_dir())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".lua"))
        .collect();
    names.sort();
    // config.toml's comments name these two; they used to not exist.
    for expected in ["cors.lua", "logging.lua", "rate_limit.lua"] {
        assert!(names.iter().any(|n| n == expected), "{expected} missing");
    }
    for name in &names {
        assert!(engine(name).has_route_script(name), "{name} not loaded");
    }
}

#[test]
fn cors_answers_a_preflight_from_an_allowed_origin() {
    let engine = engine("cors.lua");
    let preflight = request(
        "OPTIONS",
        &[
            ("origin", "https://app.example.com"),
            ("access-control-request-method", "PUT"),
        ],
    );
    let mods = engine.call_route_on_response("cors.lua", &preflight, 405, &HashMap::new());
    assert_eq!(mods.override_status, Some(204));
    assert_eq!(
        mods.set_headers
            .get("Access-Control-Allow-Origin")
            .map(String::as_str),
        Some("https://app.example.com")
    );
    assert!(mods
        .set_headers
        .contains_key("Access-Control-Allow-Methods"));
    assert_eq!(
        mods.set_headers.get("Vary").map(String::as_str),
        Some("Origin")
    );

    // A simple request gets the headers but keeps its status.
    let get = request("GET", &[("origin", "https://app.example.com")]);
    let mods = engine.call_route_on_response("cors.lua", &get, 200, &HashMap::new());
    assert_eq!(mods.override_status, None);
    assert!(mods.set_headers.contains_key("Access-Control-Allow-Origin"));
}

#[test]
fn cors_ignores_origins_outside_the_allowlist() {
    let engine = engine("cors.lua");
    let preflight = request(
        "OPTIONS",
        &[
            ("origin", "https://evil.example"),
            ("access-control-request-method", "PUT"),
        ],
    );
    let mods = engine.call_route_on_response("cors.lua", &preflight, 405, &HashMap::new());
    assert!(mods.set_headers.is_empty(), "{mods:?}");
    assert_eq!(mods.override_status, None);
}

/// The limiter used to key on X-Forwarded-For, which the client writes: a
/// fresh value per request was a fresh budget per request.
#[test]
fn rate_limit_cannot_be_reset_with_x_forwarded_for() {
    let engine = engine("rate_limit.lua");
    let mut denied = 0;
    for i in 0..150 {
        let ip = format!("10.0.{}.{}", i / 250, i % 250);
        let mut req = request("GET", &[("x-forwarded-for", ip.as_str())]);
        if matches!(
            engine.call_route_on_request("rate_limit.lua", &mut req),
            RequestHookResult::Deny { status: 429, .. }
        ) {
            denied += 1;
        }
    }
    // 100 per window; a test straddling a window boundary may see a few more.
    assert!(denied >= 40, "only {denied} of 150 denied");
}
