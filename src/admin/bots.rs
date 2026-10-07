//! Admin API for `[bots]` (see `response::bots`):
//!
//! - `GET /api/v1/bots` — the bans in force, and what was refused;
//! - `DELETE /api/v1/bots/bans/{ip}` — lift a ban;
//! - `POST /api/v1/bots/traps`, `DELETE /api/v1/bots/traps` with
//!   `{"pattern": "/old-admin/*"}` — add or remove a trap path at run time.

use super::{error_response, ok_response, AdminState, BoxBody};
use hyper::Response;
use std::net::IpAddr;
use std::sync::Arc;

/// `GET /api/v1/bots`.
pub fn get(state: &Arc<AdminState>) -> Response<BoxBody> {
    let config = state.config_manager.get_config();
    let policy = &config.bots;
    let snapshot = state.config_manager.bots.snapshot();
    ok_response(serde_json::json!({
        "bans": snapshot.bans,
        "banned_total": snapshot.banned_total,
        "blocked": snapshot.blocked,
        "custom_traps": state.config_manager.bots.custom_traps(),
        "policy": {
            "enabled": policy.enabled,
            "trap_paths": policy
                .trap_paths
                .clone()
                .unwrap_or_else(|| crate::response::bots::DEFAULT_TRAP_PATHS
                    .iter()
                    .map(|p| p.to_string())
                    .collect()),
            "block_agents": policy.block_agents,
            "traps": policy.traps,
            "max_404_per_minute": policy.max_404_per_minute,
            "ban_secs": policy.ban_secs,
        },
    }))
}

/// `DELETE /api/v1/bots/bans/{ip}`.
pub fn unban(state: &Arc<AdminState>, ip: &str) -> Response<BoxBody> {
    // `2001:db8::/64` as listed by `GET`, or a bare address.
    let addr = ip.split('/').next().unwrap_or(ip);
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return error_response(400, &format!("{ip:?} is not an IP address"));
    };
    if state.config_manager.bots.unban(addr) {
        ok_response(serde_json::json!({ "unbanned": ip }))
    } else {
        error_response(404, &format!("{ip} is not banned"))
    }
}

#[derive(serde::Deserialize)]
struct TrapBody {
    pattern: String,
}

fn trap_body(body: &str) -> Result<String, String> {
    serde_json::from_str::<TrapBody>(body)
        .map(|b| b.pattern)
        .map_err(|e| format!("expected {{\"pattern\": \"/path\"}}: {e}"))
}

/// `POST /api/v1/bots/traps` — `{"pattern": "/old-admin/*"}`.
pub fn add_trap(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let pattern = match trap_body(body) {
        Ok(p) => p,
        Err(e) => return error_response(400, &e),
    };
    match state.config_manager.bots.add_trap(&pattern) {
        Ok(added) => ok_response(serde_json::json!({
            "pattern": pattern.trim(),
            "added": added,
            "traps_on": state.config_manager.get_config().bots.traps,
        })),
        Err(e) => error_response(400, &format!("{e:#}")),
    }
}

/// `DELETE /api/v1/bots/traps` — `{"pattern": "/old-admin/*"}`.
pub fn remove_trap(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let pattern = match trap_body(body) {
        Ok(p) => p,
        Err(e) => return error_response(400, &e),
    };
    match state.config_manager.bots.remove_trap(&pattern) {
        Ok(true) => ok_response(serde_json::json!({ "removed": pattern.trim() })),
        Ok(false) => error_response(
            404,
            &format!("{} is not a trap added at run time", pattern.trim()),
        ),
        Err(e) => error_response(500, &format!("{e:#}")),
    }
}
