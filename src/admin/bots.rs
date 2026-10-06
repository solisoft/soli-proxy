//! Admin API for `[bots]` (see `response::bots`):
//!
//! - `GET /api/v1/bots` — the bans in force, and what was refused;
//! - `DELETE /api/v1/bots/bans/{ip}` — lift a ban (an IPv6 address lifts
//!   its /64's).

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
        "policy": {
            "enabled": policy.enabled,
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
