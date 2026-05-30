use super::{
    created_response, error_response, no_content_response, ok_response, AdminState, BoxBody,
};
use crate::auth;
use crate::config::ProxyRule;
use http_body::Body;
use http_body::Frame;
use hyper::Response;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::broadcast;

pub async fn get_status(state: &Arc<AdminState>) -> Response<BoxBody> {
    let cfg = state.config_manager.get_config();
    let uptime = state.start_time.elapsed();

    let app_count = match state.app_manager.as_ref() {
        Some(m) => m.list_apps().await.len(),
        None => 0,
    };

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
            let mut apps = manager.list_apps().await;
            apps.sort_by(|a, b| a.config.domain.cmp(&b.config.domain));
            match serde_json::to_value(&apps) {
                Ok(val) => ok_response(val),
                Err(e) => error_response(500, &format!("Failed to serialize apps: {}", e)),
            }
        }
        None => error_response(501, "App management not configured"),
    }
}

pub async fn get_apps_by_domain(state: &Arc<AdminState>) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            let apps = manager.list_apps().await;
            use std::collections::BTreeMap;
            let mut grouped: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
            for app in apps {
                let domain = app.config.domain.clone();
                let root_domain = if domain.is_empty() {
                    "ungrouped".to_string()
                } else if let Some(dot_pos) = domain.find('.') {
                    domain[dot_pos + 1..].to_string()
                } else {
                    domain
                };
                match serde_json::to_value(&app) {
                    Ok(val) => grouped.entry(root_domain).or_default().push(val),
                    Err(e) => {
                        return error_response(500, &format!("Failed to serialize app: {}", e))
                    }
                }
            }
            ok_response(serde_json::to_value(grouped).unwrap())
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
                Err(e) => error_response(500, &format!("Deployment failed: {:#}", e)),
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

pub async fn get_app_system_metrics(state: &Arc<AdminState>) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            let metrics = state.metrics.as_ref();
            let result = manager.get_system_metrics(metrics).await;
            ok_response(result)
        }
        None => error_response(501, "App management not configured"),
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

/// Built-in admin UI theme presets. Must stay in sync with the `PRESETS`
/// list in `_admin/public/js/themes.js`.
const VALID_THEMES: &[&str] = &["emerald", "ocean", "indigo", "violet", "amber", "rose"];
const DEFAULT_THEME: &str = "emerald";

/// Path to the admin UI settings file, kept beside the proxy config.
fn settings_path(state: &Arc<AdminState>) -> std::path::PathBuf {
    let cfg = state.config_manager.config_path();
    let dir = cfg.parent().unwrap_or_else(|| std::path::Path::new("."));
    dir.join("admin-settings.json")
}

pub fn get_settings(state: &Arc<AdminState>) -> Response<BoxBody> {
    let stored = std::fs::read_to_string(settings_path(state))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    let theme = stored
        .as_ref()
        .and_then(|v| v.get("theme"))
        .and_then(|t| t.as_str())
        .filter(|t| VALID_THEMES.contains(t))
        .unwrap_or(DEFAULT_THEME);

    ok_response(serde_json::json!({ "theme": theme }))
}

pub fn put_settings(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    #[derive(serde::Deserialize)]
    struct SettingsUpdate {
        theme: String,
    }

    let update: SettingsUpdate = match serde_json::from_str(body) {
        Ok(u) => u,
        Err(e) => return error_response(400, &format!("Invalid settings JSON: {}", e)),
    };

    if !VALID_THEMES.contains(&update.theme.as_str()) {
        return error_response(400, &format!("Unknown theme: {}", update.theme));
    }

    let payload = serde_json::json!({ "theme": update.theme });
    let serialized = match serde_json::to_string_pretty(&payload) {
        Ok(s) => s,
        Err(e) => return error_response(500, &format!("Failed to serialize settings: {}", e)),
    };

    match std::fs::write(settings_path(state), serialized) {
        Ok(()) => {
            ok_response(serde_json::json!({ "message": "Settings updated", "theme": update.theme }))
        }
        Err(e) => error_response(500, &format!("Failed to write settings: {}", e)),
    }
}

#[derive(serde::Deserialize)]
struct HashPasswordRequest {
    password: String,
}

pub fn post_hash_password(_state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let req: HashPasswordRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("Invalid JSON: {}", e)),
    };

    if req.password.is_empty() {
        return error_response(400, "Password cannot be empty");
    }

    if req.password.len() > 1024 {
        return error_response(400, "Password too long (max 1024 bytes)");
    }

    let hash = auth::generate_hash(&req.password);
    ok_response(serde_json::json!({
        "hash": hash,
        "format": "bcrypt"
    }))
}

pub async fn sse_app_events(state: Arc<AdminState>) -> Response<BoxBody> {
    let manager = match &state.app_manager {
        Some(m) => m.clone(),
        None => return error_response(501, "App management not configured"),
    };

    let mut rx = manager.subscribe();

    let (tx, rx_body) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let msg = bytes::Bytes::from(format!("data: {}\n\n", data));
                    if tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("SSE lagged {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    struct MpscBody {
        rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        buffer: Option<bytes::Bytes>,
    }

    impl Body for MpscBody {
        type Data = bytes::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if let Some(data) = self.buffer.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            match Pin::new(&mut self.rx).poll_recv(cx) {
                Poll::Ready(Some(data)) => Poll::Ready(Some(Ok(Frame::data(data)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    let body = MpscBody {
        rx: rx_body,
        buffer: None,
    };

    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(body.boxed())
        .unwrap()
}
