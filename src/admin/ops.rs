//! Lifecycle and validation endpoints: `POST /api/v1/apps/stop-all` and
//! `POST /api/v1/config/validate`.

use super::{error_response, ok_response, AdminState, BoxBody};
use hyper::Response;
use std::path::Path;
use std::sync::Arc;

/// `POST /api/v1/apps/stop-all` — stop every app, both slots, and anything
/// else this proxy recorded spawning. The proxy itself keeps running.
///
/// A proxy that stops or restarts leaves its apps running for the next one
/// to adopt (`[apps] stop_on_shutdown = false`); this is the explicit way to
/// take them down — before decommissioning a host, say. `soli-proxy stop
/// --all` calls it.
pub async fn post_stop_all_apps(state: &Arc<AdminState>) -> Response<BoxBody> {
    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };
    let apps = manager.list_apps().await.len();
    manager.stop_all().await;
    ok_response(serde_json::json!({
        "message": "All apps stopped",
        "apps": apps,
    }))
}

/// `POST /api/v1/config/validate` — check a proposed `proxy.conf` and/or
/// `config.toml` without applying either.
///
/// Body: `{"proxy_conf": "<text>", "config_toml": "<text>"}`, both optional;
/// a part left out is read from the files this proxy runs on, so a proposed
/// `proxy.conf` is checked against the live `config.toml` and the other way
/// round. The checks are `soli-proxy check`'s, sites aside. Answers 200 with
/// `valid`, the counts and every problem (`file`, `line`, `severity`,
/// `message`); 400 only when the body itself is unusable.
pub async fn post_config_validate(state: &Arc<AdminState>, body: String) -> Response<BoxBody> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proposal {
        proxy_conf: Option<String>,
        config_toml: Option<String>,
    }
    let proposal: Proposal = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_response(400, &format!("Invalid JSON: {}", e)),
    };
    let conf_path = state.config_manager.config_path().to_path_buf();

    // File reads, and possibly a bcrypt hash of a plaintext ADMIN_PASSWORD
    // during assembly: off the async workers.
    let report = tokio::task::spawn_blocking(move || {
        let config_dir = match conf_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => Path::new(".").to_path_buf(),
        };
        let read = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();
        let (conf_label, conf_text) = match proposal.proxy_conf {
            Some(text) => ("proxy.conf (proposed)".to_string(), text),
            None => (conf_path.display().to_string(), read(&conf_path)),
        };
        let toml_path = config_dir.join("config.toml");
        let (toml_label, toml_text) = match proposal.config_toml {
            Some(text) => ("config.toml (proposed)".to_string(), text),
            None => (toml_path.display().to_string(), read(&toml_path)),
        };
        let mut report = crate::check::Report::default();
        crate::check::check_sources(
            (&conf_label, &conf_text),
            (&toml_label, &toml_text),
            &config_dir,
            &mut report,
        );
        report
    })
    .await;

    match report {
        Ok(report) => ok_response(serde_json::json!({
            "valid": !report.has_errors(),
            "errors": report.errors(),
            "warnings": report.warnings(),
            "problems": report.problems,
        })),
        Err(e) => error_response(500, &format!("validation failed: {}", e)),
    }
}
