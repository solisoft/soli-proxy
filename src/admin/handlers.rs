use super::{
    created_response, error_response, no_content_response, ok_response, AdminState, BoxBody,
};
use crate::config::ProxyRule;
use hyper::Response;
use std::sync::Arc;

pub fn get_status(state: &Arc<AdminState>) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    let uptime = state.start_time.elapsed();

    let app_count = state
        .app_manager
        .as_ref()
        .map(|m| futures::executor::block_on(m.list_apps()).len())
        .unwrap_or(0);

    ok_response(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime.as_secs(),
        "route_count": cfg.rules.len(),
        "app_count": app_count,
        "bind": cfg.server.bind,
        "https_port": cfg.server.https_port,
        "tls_mode": cfg.tls.mode,
        "admin_bind": cfg.admin.bind,
    }))
}

pub async fn get_apps(state: &Arc<AdminState>) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            let apps = manager.list_apps().await;
            match serde_json::to_value(&apps) {
                Ok(val) => ok_response(val),
                Err(e) => error_response(500, &format!("Failed to serialize apps: {}", e)),
            }
        }
        None => error_response(501, "App management not configured"),
    }
}

pub async fn get_app(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => match manager.get_app(name).await {
            Some(app) => match serde_json::to_value(&app) {
                Ok(val) => ok_response(val),
                Err(e) => error_response(500, &format!("Failed to serialize app: {}", e)),
            },
            None => error_response(404, &format!("App not found: {}", name)),
        },
        None => error_response(501, "App management not configured"),
    }
}

pub async fn post_app_deploy(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            // Determine target slot based on current slot (alternate)
            let target_slot = manager
                .get_app(name)
                .await
                .map_or("blue".to_string(), |app| {
                    if app.current_slot == "blue" {
                        "green".to_string()
                    } else {
                        "blue".to_string()
                    }
                });

            match manager.deploy(name, &target_slot).await {
                Ok(()) => ok_response(serde_json::json!({
                    "message": "Deployment started",
                    "app": name,
                    "slot": target_slot
                })),
                Err(e) => error_response(500, &format!("Deployment failed: {}", e)),
            }
        }
        None => error_response(501, "App management not configured"),
    }
}

pub async fn post_app_restart(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => match manager.restart(name).await {
            Ok(()) => ok_response(serde_json::json!({
                "message": "Restart started",
                "app": name
            })),
            Err(e) => error_response(500, &format!("Restart failed: {}", e)),
        },
        None => error_response(501, "App management not configured"),
    }
}

pub async fn post_app_rollback(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => match manager.rollback(name).await {
            Ok(()) => ok_response(serde_json::json!({
                "message": "Rollback started",
                "app": name
            })),
            Err(e) => error_response(500, &format!("Rollback failed: {}", e)),
        },
        None => error_response(501, "App management not configured"),
    }
}

pub async fn post_app_stop(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => match manager.stop(name).await {
            Ok(()) => ok_response(serde_json::json!({
                "message": "App stopped",
                "app": name
            })),
            Err(e) => error_response(500, &format!("Stop failed: {}", e)),
        },
        None => error_response(501, "App management not configured"),
    }
}

pub async fn get_app_metrics(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            // First check if app exists
            match manager.get_app(name).await {
                Some(_) => {
                    let metrics = state.metrics.get_app_metrics(name);
                    match serde_json::to_value(metrics) {
                        Ok(val) => ok_response(val),
                        Err(e) => {
                            error_response(500, &format!("Failed to serialize metrics: {}", e))
                        }
                    }
                }
                None => error_response(404, &format!("App not found: {}", name)),
            }
        }
        None => error_response(501, "App management not configured"),
    }
}

pub fn get_all_app_metrics(state: &Arc<AdminState>) -> Response<BoxBody> {
    let metrics = state.metrics.get_all_app_metrics();
    match serde_json::to_value(metrics) {
        Ok(val) => ok_response(val),
        Err(e) => error_response(500, &format!("Failed to serialize metrics: {}", e)),
    }
}

pub async fn get_app_logs(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            let blue_log_result = manager
                .deployment_manager
                .get_deployment_log(name, "blue")
                .await;
            let green_log_result = manager
                .deployment_manager
                .get_deployment_log(name, "green")
                .await;

            ok_response(serde_json::json!({
                "app": name,
                "blue": blue_log_result.unwrap_or_default(),
                "green": green_log_result.unwrap_or_default(),
            }))
        }
        None => error_response(501, "App management not configured"),
    }
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
    super::cors_headers(Response::builder())
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
