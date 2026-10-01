//! Admin API for maintenance mode (see `response::maintenance`):
//!
//! - `GET /api/v1/maintenance` — what is in maintenance and why;
//! - `PUT /api/v1/maintenance` — the whole proxy;
//! - `PUT /api/v1/apps/{name}/maintenance` — one app.
//!
//! The `PUT`s take `{"enabled": bool, "retry_after"?: seconds, "message"?:
//! string}` and persist the result to `run/maintenance.json`.

use super::{error_response, ok_response, AdminState, BoxBody};
use crate::response::maintenance::{MaintenanceState, Toggle, Window};
use hyper::Response;
use std::sync::Arc;

/// The window a toggle body asks for, or the reason it is refused (a 400).
fn parse_toggle(body: &str) -> Result<Option<Window>, String> {
    let toggle: Toggle = serde_json::from_str(body).map_err(|e| {
        format!(
            "Invalid body: {} (expected {{\"enabled\": bool, \"retry_after\"?: seconds, \
             \"message\"?: string}})",
            e
        )
    })?;
    toggle.into_window()
}

fn state_json(state: &MaintenanceState) -> serde_json::Value {
    serde_json::to_value(state).unwrap_or(serde_json::Value::Null)
}

/// `GET /api/v1/maintenance`.
pub async fn get(state: &Arc<AdminState>) -> Response<BoxBody> {
    let snapshot = state.config_manager.maintenance.snapshot();
    let flagged: Vec<String> = match &state.app_manager {
        Some(manager) => {
            let mut names: Vec<String> = manager
                .list_apps()
                .await
                .into_iter()
                .filter(|app| app.maintenance)
                .map(|app| app.config.name)
                .collect();
            names.sort();
            names
        }
        None => Vec::new(),
    };
    let config = state.config_manager.get_config();
    ok_response(serde_json::json!({
        "global": snapshot.global,
        "apps": snapshot.apps,
        // Apps put in maintenance by their `maintenance.flag` file.
        "flagged": flagged,
        "default_retry_after": config.maintenance.retry_after,
    }))
}

/// `PUT /api/v1/maintenance`.
pub fn put_global(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let window = match parse_toggle(body) {
        Ok(window) => window,
        Err(e) => return error_response(400, &e),
    };
    let enabled = window.is_some();
    match state.config_manager.maintenance.set_global(window) {
        Ok(next) => {
            tracing::warn!(
                "maintenance mode {} for the whole proxy (admin API)",
                if enabled { "ON" } else { "off" }
            );
            ok_response(state_json(&next))
        }
        Err(e) => error_response(500, &format!("Could not save maintenance state: {:#}", e)),
    }
}

/// `PUT /api/v1/apps/{name}/maintenance`.
pub async fn put_app(state: &Arc<AdminState>, name: &str, body: &str) -> Response<BoxBody> {
    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };
    let window = match parse_toggle(body) {
        Ok(window) => window,
        Err(e) => return error_response(400, &e),
    };
    // Switching one off is allowed for an app that has since gone away, so a
    // stale entry can always be cleared; switching one on is not.
    if window.is_some() && manager.get_app(name).await.is_none() {
        return error_response(404, &format!("App '{}' not found", name));
    }
    let enabled = window.is_some();
    match state.config_manager.maintenance.set_app(name, window) {
        Ok(next) => {
            tracing::warn!(
                "maintenance mode {} for app {} (admin API)",
                if enabled { "ON" } else { "off" },
                name
            );
            ok_response(state_json(&next))
        }
        Err(e) => error_response(500, &format!("Could not save maintenance state: {:#}", e)),
    }
}
