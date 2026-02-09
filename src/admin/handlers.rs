use super::{
    created_response, error_response, no_content_response, ok_response, AdminState, BoxBody,
};
use crate::config::ProxyRule;
use hyper::Response;
use std::sync::Arc;

pub fn get_status(state: &Arc<AdminState>) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    let uptime = state.start_time.elapsed();

    ok_response(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime.as_secs(),
        "route_count": cfg.rules.len(),
        "bind": cfg.server.bind,
        "https_port": cfg.server.https_port,
        "tls_mode": cfg.tls.mode,
        "admin_bind": cfg.admin.bind,
    }))
}

pub fn get_config(state: &Arc<AdminState>) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    match serde_json::to_value(cfg.as_ref()) {
        Ok(val) => ok_response(val),
        Err(e) => error_response(500, &format!("Failed to serialize config: {}", e)),
    }
}

pub fn get_routes(state: &Arc<AdminState>) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    match serde_json::to_value(&cfg.rules) {
        Ok(val) => ok_response(val),
        Err(e) => error_response(500, &format!("Failed to serialize routes: {}", e)),
    }
}

pub fn get_route(state: &Arc<AdminState>, index: usize) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    match cfg.rules.get(index) {
        Some(rule) => match serde_json::to_value(rule) {
            Ok(val) => ok_response(val),
            Err(e) => error_response(500, &format!("Failed to serialize route: {}", e)),
        },
        None => error_response(404, &format!("Route index {} not found", index)),
    }
}

pub fn get_metrics(state: &Arc<AdminState>) -> Response<BoxBody> {
    let metrics_text = state.metrics.format_metrics();
    let bytes = bytes::Bytes::from(metrics_text);
    Response::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body(http_body_util::Full::new(bytes).boxed())
        .unwrap()
}

use http_body_util::BodyExt;

pub async fn post_reload(state: &Arc<AdminState>) -> Response<BoxBody> {
    match state.config_manager.reload().await {
        Ok(()) => ok_response(serde_json::json!({ "message": "Configuration reloaded" })),
        Err(e) => error_response(500, &format!("Reload failed: {}", e)),
    }
}

// Phase 2: Mutation endpoints

pub fn post_route(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let rule: ProxyRule = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("Invalid route JSON: {}", e)),
    };

    match state.config_manager.add_route(rule) {
        Ok(()) => {
            let cfg = state.config_manager.get_config();
            created_response(serde_json::json!({
                "index": cfg.rules.len() - 1,
                "message": "Route added"
            }))
        }
        Err(e) => error_response(500, &format!("Failed to add route: {}", e)),
    }
}

pub fn put_route(state: &Arc<AdminState>, index: usize, body: &str) -> Response<BoxBody> {
    let rule: ProxyRule = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("Invalid route JSON: {}", e)),
    };

    match state.config_manager.update_route(index, rule) {
        Ok(()) => ok_response(serde_json::json!({ "message": "Route updated" })),
        Err(e) => error_response(
            if e.to_string().contains("out of range") {
                404
            } else {
                500
            },
            &e.to_string(),
        ),
    }
}

pub fn delete_route(state: &Arc<AdminState>, index: usize) -> Response<BoxBody> {
    match state.config_manager.remove_route(index) {
        Ok(()) => no_content_response(),
        Err(e) => error_response(
            if e.to_string().contains("out of range") {
                404
            } else {
                500
            },
            &e.to_string(),
        ),
    }
}

pub fn get_circuit_breaker(state: &Arc<AdminState>) -> Response<BoxBody> {
    let states = state.circuit_breaker.get_states();
    match serde_json::to_value(states) {
        Ok(val) => ok_response(val),
        Err(e) => error_response(
            500,
            &format!("Failed to serialize circuit breaker state: {}", e),
        ),
    }
}

pub fn reset_circuit_breaker(state: &Arc<AdminState>) -> Response<BoxBody> {
    state.circuit_breaker.reset();
    ok_response(serde_json::json!({ "message": "Circuit breaker states reset" }))
}

pub fn put_config(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    #[derive(serde::Deserialize)]
    struct ConfigUpdate {
        rules: Vec<ProxyRule>,
        #[serde(default)]
        global_scripts: Vec<String>,
    }

    let update: ConfigUpdate = match serde_json::from_str(body) {
        Ok(u) => u,
        Err(e) => return error_response(400, &format!("Invalid config JSON: {}", e)),
    };

    match state
        .config_manager
        .update_rules(update.rules, update.global_scripts)
    {
        Ok(()) => ok_response(serde_json::json!({ "message": "Configuration updated" })),
        Err(e) => error_response(500, &format!("Failed to update config: {}", e)),
    }
}
