use super::{
    created_response, error_response, full, no_content_response, ok_response, AdminState, BoxBody,
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
            // `maintenance` is the flag file's; a window opened through the
            // API counts too.
            let maintenance = state.config_manager.maintenance.snapshot();
            for app in &mut apps {
                app.maintenance |=
                    maintenance.global.is_some() || maintenance.apps.contains_key(&app.config.name);
            }
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

/// `POST /api/v1/apps/{name}/sleep` — put an app to sleep now; its next
/// request starts it again.
pub async fn post_app_sleep(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => match manager.put_to_sleep(name).await {
            Ok(()) => ok_response(serde_json::json!({
                "message": "App put to sleep; its next request starts it",
                "app": name
            })),
            Err(e) => error_response(409, &format!("Cannot put {} to sleep: {:#}", name, e)),
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

/// `POST /api/v1/certs/reload` — rescan the certificate directory.
///
/// Picks up certificates added or renewed on disk without restarting, which
/// previously meant dropping every live connection to install one. ACME-issued
/// certificates are injected directly by the renewal task and do not need this;
/// it is for manually managed files — a wildcard from an external DNS-01 client,
/// or a `mkcert` certificate for local development.
pub fn post_certs_reload(state: &Arc<AdminState>) -> Response<BoxBody> {
    let Some(tls) = &state.tls_manager else {
        return error_response(501, "TLS is not enabled on this proxy");
    };
    match tls.load_all_cached_certs() {
        Ok(()) => ok_response(serde_json::json!({
            "message": "Certificates reloaded",
            "cache_dir": tls.cache_dir().display().to_string()
        })),
        Err(e) => error_response(500, &format!("Certificate reload failed: {}", e)),
    }
}

/// `GET /api/v1/aliases` — the whole alias table (domain -> app).
pub async fn get_aliases(state: &Arc<AdminState>) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            let aliases = manager.get_aliases().await;
            match serde_json::to_value(aliases) {
                Ok(value) => ok_response(value),
                Err(e) => error_response(500, &format!("Failed to serialize aliases: {}", e)),
            }
        }
        None => error_response(501, "App management not configured"),
    }
}

/// `PUT /api/v1/routing-table` — routes this proxy serves but does not run.
///
/// The cluster's side of the migration: `soli-oned` pushes the complete set of
/// domains it is serving on other nodes, and the proxy routes them without
/// supervising them.
///
/// ```json
/// { "index": 42,
///   "routes": { "x.soli.app": [ { "url": "http://10.0.0.12:20001", "weight": 100 } ] },
///   "auth":   { "x.soli.app": { "users": { "admin": "$2b$12$..." },
///                               "noauth": ["/webhooks/*"] } } }
/// ```
///
/// Each target is an `http`/`https` URL with a host — the same rule as a
/// static route's target — and a `weight` of 0..=255 (default 100). Anything
/// else is refused rather than reinterpreted: `weight: 256` used to wrap to 0.
///
/// `auth` is optional, and keyed by domains present in `routes`. It is the
/// app's `[auth]` section, in the same shape and under the same validation as
/// in `app.infos` (bcrypt hashes at cost 4..=13). **This proxy is what enforces
/// it**: a pushed target is the workload's raw port, with nothing in front of
/// it on the node that runs it, so a protected app pushed without its `auth`
/// is served open.
///
/// **Complete set, not a delta.** A missed push then self-corrects on the next
/// one, and removing a route needs no separate call. The `index` must increase
/// strictly — any index is accepted for the first table after a start, then
/// each push must exceed the one in place, 0 included: a retry overtaking the
/// write that superseded it would otherwise reinstate routes that were
/// deliberately removed, which looks exactly like a rollback nobody asked for.
/// A stale push answers 409 rather than being silently ignored, so the pusher
/// can tell "refused" from "applied".
pub async fn put_routing_table(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    use crate::app::external::ExternalRoutes;

    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return error_response(400, &format!("Invalid JSON: {}", e)),
    };
    let Some(index) = parsed.get("index").and_then(|v| v.as_u64()) else {
        return error_response(400, "Missing index");
    };
    let Some(routes) = parsed.get("routes").and_then(|v| v.as_object()) else {
        return error_response(400, "Missing routes");
    };

    let mut table = std::collections::HashMap::new();
    for (host, targets) in routes {
        let Some(list) = targets.as_array() else {
            return error_response(400, &format!("routes[{}] is not an array", host));
        };
        let mut parsed_targets = Vec::new();
        for target in list {
            let Some(raw) = target.get("url").and_then(|v| v.as_str()) else {
                return error_response(400, &format!("routes[{}] has a target with no url", host));
            };
            // Parsed here, not at use. A malformed URL rejected at push time is
            // one error message for the pusher; the same URL rejected at
            // request time is a 502 for a real user with no explanation.
            let Ok(url) = raw.parse::<url::Url>() else {
                return error_response(
                    400,
                    &format!("routes[{}] has an invalid url: {}", host, raw),
                );
            };
            // The same rule a static route's target obeys: the proxy speaks
            // HTTP to it, so `file://`, `unix:` or a host-less URL is a
            // mistake (or an attempt) to refuse now, not a 502 to explain later.
            if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
                return error_response(
                    400,
                    &format!(
                        "routes[{}] target {} must be an http:// or https:// URL with a host",
                        host, raw
                    ),
                );
            }
            let weight = match target.get("weight") {
                None => 100,
                Some(w) => match w.as_u64().and_then(|w| u8::try_from(w).ok()) {
                    Some(w) => w,
                    None => {
                        return error_response(
                            400,
                            &format!(
                                "routes[{}] target {} has weight {}, expected an integer 0..=255",
                                host, raw, w
                            ),
                        )
                    }
                },
            };
            parsed_targets.push(crate::config::Target { url, weight });
        }
        table.insert(host.to_lowercase(), parsed_targets);
    }

    let mut auth = std::collections::HashMap::new();
    if let Some(raw) = parsed.get("auth").filter(|v| !v.is_null()) {
        let Some(entries) = raw.as_object() else {
            return error_response(400, "auth must be an object keyed by domain");
        };
        for (host, section) in entries {
            let host = host.to_lowercase();
            if !table.contains_key(&host) {
                return error_response(
                    400,
                    &format!("auth[{}] names a domain absent from routes", host),
                );
            }
            let section: crate::app::AppAuth = match serde_json::from_value(section.clone()) {
                Ok(section) => section,
                Err(e) => return error_response(400, &format!("auth[{}]: {}", host, e)),
            };
            if let Err(e) = section.validate() {
                return error_response(400, &format!("auth[{}]: {}", host, e));
            }
            if section.is_active() {
                auth.insert(host, section);
            }
        }
    }

    let count = table.len();
    if manager
        .external_routes
        .push(ExternalRoutes { index, table, auth })
    {
        ok_response(serde_json::json!({ "applied": true, "index": index, "domains": count }))
    } else {
        // 409, not 200-with-a-flag: the pusher has to be able to tell
        // "refused" from "applied" without parsing a body, because the
        // difference decides whether it retries with a higher index.
        error_response(409, "an equal or newer routing table is already in place")
    }
}

/// `GET /api/v1/acme-challenges` — the tokens this proxy currently needs proven.
///
/// The read that makes distribution possible. The node ordering a certificate is
/// the only one that knows its own tokens, and Let's Encrypt validates over the VIP
/// and lands wherever routing sends it — so something has to collect them from every
/// node and hand the union back to all of them. That collector is outside the proxy,
/// which knows nothing about its peers.
///
/// Returns the same shape `PUT` accepts, so a distributor reads from one node and
/// writes to another without translating anything. A shape that differed between the
/// two would be a translation step, and a translation step is somewhere to lose a
/// token.
///
/// The key authorization is not a secret worth withholding here: it is served to
/// anyone who asks for the challenge URL, by design — that is how HTTP-01 works. The
/// admin API is authenticated anyway.
pub async fn get_acme_challenges(state: &Arc<AdminState>) -> Response<BoxBody> {
    let Some(store) = &state.challenge_store else {
        return error_response(501, "ACME challenge serving is not configured");
    };
    let tokens: std::collections::BTreeMap<String, String> = match store.read() {
        Ok(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        // A poisoned lock means a panic happened while holding it. Reporting an
        // empty set would make a distributor drop every token in the cluster on the
        // next push, so this fails loudly instead.
        Err(_) => return error_response(500, "the challenge store is unreadable"),
    };
    ok_response(serde_json::json!({ "tokens": tokens }))
}

/// `PUT /api/v1/acme-challenges` — HTTP-01 tokens this proxy will answer for.
///
/// The other half of the elected-orderer design. One node in the cluster orders
/// certificates; **every** node has to be able to prove the challenge, because
/// Let's Encrypt fetches the validation URL over the VIP and lands wherever
/// routing sends it. A proxy that does not know the token answers 404, the
/// order fails, and the failure is charged against that hostname's budget of
/// five failed validations per hour.
///
/// ```json
/// { "tokens": { "<token>": "<key authorization>" } }
/// ```
///
/// **Replace, not merge**, exactly like the routing table: the pusher sends the
/// complete live set, so a token the orderer has abandoned stops being
/// answerable on the next push rather than lingering. Merging would leave a
/// proxy able to satisfy a challenge the cluster no longer controls, and
/// nothing would ever remove it.
///
/// There is no monotonic index here, unlike the routing table. A stale push
/// costs at most one retried validation — Let's Encrypt retries, and the
/// orderer re-probes before proving — whereas a stale *routing* push silently
/// restores routes that were deliberately removed. Different blast radius,
/// different guard.
pub async fn put_acme_challenges(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let Some(store) = &state.challenge_store else {
        return error_response(501, "ACME challenge serving is not configured");
    };
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return error_response(400, &format!("Invalid JSON: {}", e)),
    };
    let Some(tokens) = parsed.get("tokens").and_then(|v| v.as_object()) else {
        return error_response(400, "Missing tokens");
    };

    let mut next = std::collections::HashMap::with_capacity(tokens.len());
    for (token, key_auth) in tokens {
        // Validated at push time, not at request time. A malformed token
        // rejected here is one clear error for the pusher; the same token
        // accepted and then never matched is a validation failure whose cause
        // is invisible from both ends.
        if !plausible_acme_token(token) {
            return error_response(400, &format!("implausible ACME token: {:?}", token));
        }
        let Some(value) = key_auth.as_str().filter(|v| !v.is_empty()) else {
            return error_response(400, &format!("tokens[{}] has no key authorization", token));
        };
        next.insert(token.clone(), value.to_string());
    }

    let count = next.len();
    match store.write() {
        Ok(mut guard) => {
            *guard = next;
            tracing::info!(tokens = count, "ACME challenge set replaced by the cluster");
            ok_response(serde_json::json!({ "applied": true, "tokens": count }))
        }
        Err(_) => error_response(500, "challenge store lock is poisoned"),
    }
}

/// ACME tokens are base64url and at least 22 characters.
///
/// The token becomes part of a lookup key reached from an unauthenticated
/// request path, so it is checked rather than trusted — "the CA would never
/// send that" is the assumption every traversal bug is built on.
fn plausible_acme_token(token: &str) -> bool {
    token.len() >= 22
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `GET /api/v1/routing-table` — what the cluster last pushed.
pub async fn get_routing_table(state: &Arc<AdminState>) -> Response<BoxBody> {
    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };
    let snapshot = manager.external_routes.snapshot();
    let routes: serde_json::Map<String, serde_json::Value> = snapshot
        .table
        .iter()
        .map(|(host, targets)| {
            (
                host.clone(),
                serde_json::Value::Array(
                    targets
                        .iter()
                        .map(|t| serde_json::json!({ "url": t.url.as_str(), "weight": t.weight }))
                        .collect(),
                ),
            )
        })
        .collect();
    // `AppAuth` serializes usernames, `noauth` and forward-auth, never the hashes.
    ok_response(serde_json::json!({
        "index": snapshot.index,
        "routes": routes,
        "auth": snapshot.auth,
    }))
}

/// `POST /api/v1/apps/{name}/aliases` with `{"domain": "..."}`.
///
/// Point another domain at an already-running app. Repointing an existing alias
/// is the same call with a different app, and takes effect on the next request
/// without restarting anything — this is the rollback primitive.
pub async fn post_app_alias(state: &Arc<AdminState>, name: &str, body: &str) -> Response<BoxBody> {
    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };

    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return error_response(400, &format!("Invalid JSON: {}", e)),
    };
    let Some(domain) = parsed.get("domain").and_then(|d| d.as_str()) else {
        return error_response(400, "Missing \"domain\"");
    };

    match manager.set_alias(domain, name).await {
        Ok(()) => ok_response(serde_json::json!({
            "message": "Alias set",
            "domain": domain.trim().to_lowercase(),
            "app": name
        })),
        Err(e) => error_response(400, &format!("{}", e)),
    }
}

/// `DELETE /api/v1/apps/{name}/aliases/{domain}`.
pub async fn delete_app_alias(
    state: &Arc<AdminState>,
    name: &str,
    domain: &str,
) -> Response<BoxBody> {
    let Some(manager) = &state.app_manager else {
        return error_response(501, "App management not configured");
    };

    // Deleting through the wrong app would silently succeed and remove an alias
    // the caller does not own, so verify ownership before touching the table.
    let normalized = domain.trim().to_lowercase();
    match manager.get_aliases().await.get(&normalized) {
        Some(owner) if owner == name => {}
        Some(owner) => {
            return error_response(
                409,
                &format!(
                    "Alias {} belongs to app {}, not {}",
                    normalized, owner, name
                ),
            )
        }
        None => return error_response(404, &format!("No such alias: {}", normalized)),
    }

    if manager.remove_alias(&normalized).await {
        ok_response(serde_json::json!({
            "message": "Alias removed",
            "domain": normalized,
            "app": name
        }))
    } else {
        error_response(404, &format!("No such alias: {}", normalized))
    }
}

pub async fn get_app_metrics(state: &Arc<AdminState>, name: &str) -> Response<BoxBody> {
    match &state.app_manager {
        Some(manager) => {
            // First check if app exists
            match manager.get_app(name).await {
                Some(app) => {
                    // Same join as the collection endpoint, for one app: an
                    // `AppMetricsJson` whose memory field is always null is
                    // worse than one that is absent, because it reads as a
                    // measurement that came back empty.
                    let mut metrics = state.metrics.get_app_metrics(name).unwrap_or(
                        crate::metrics::AppMetricsJson {
                            // Never requested is `None`, not the epoch — an
                            // idleness policy reading 0 as a timestamp would
                            // suspend every app on its first pass.
                            last_request_ms: None,
                            requests: 0,
                            bytes_received: 0,
                            bytes_sent: 0,
                            avg_response_time_ms: 0.0,
                            errors: 0,
                            memory_rss_bytes: None,
                            cpu_percent: None,
                            asleep: false,
                        },
                    );
                    metrics.asleep = manager.is_asleep(name);

                    let slots: Vec<_> = [&app.blue, &app.green]
                        .iter()
                        .filter_map(|instance| instance.pid)
                        .filter_map(|pid| state.metrics.get_process_stats(pid))
                        .collect();
                    let totals = crate::metrics::sum_slot_metrics(&slots);
                    metrics.memory_rss_bytes = totals.memory_rss_bytes;
                    metrics.cpu_percent = totals.cpu_percent;

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

/// Traffic **and** resources for every app, in one answer.
///
/// The two halves come from different places and used to be two endpoints:
/// bytes and requests are counted by the proxy as it serves, memory and CPU
/// are read from `/proc` for the app's own processes. `memory_rss_bytes` and
/// `cpu_percent` were hardcoded `None` here, so the field existed, serialised,
/// and told every caller the platform could not measure memory per app — while
/// `/api/v1/app-metrics/system` was measuring exactly that, one endpoint away.
///
/// Joining them matters beyond convenience: metered billing needs bandwidth and
/// memory for the *same* app over the *same* interval, and two endpoints
/// sampled a second apart do not give that.
pub async fn get_all_app_metrics(state: &Arc<AdminState>) -> Response<BoxBody> {
    let mut metrics = state.metrics.get_all_app_metrics();

    if let Some(manager) = &state.app_manager {
        for (name, pids) in manager.running_pids().await {
            // Only apps the proxy has served appear in the traffic map. An app
            // that is running but has had no request yet still has memory, and
            // omitting it would make "no traffic" look like "not running".
            let entry = metrics
                .entry(name)
                .or_insert_with(|| crate::metrics::AppMetricsJson {
                    last_request_ms: None,
                    requests: 0,
                    bytes_received: 0,
                    bytes_sent: 0,
                    avg_response_time_ms: 0.0,
                    errors: 0,
                    memory_rss_bytes: None,
                    cpu_percent: None,
                    asleep: false,
                });

            let slots: Vec<_> = pids
                .iter()
                .filter_map(|pid| state.metrics.get_process_stats(*pid))
                .collect();
            let totals = crate::metrics::sum_slot_metrics(&slots);
            entry.memory_rss_bytes = totals.memory_rss_bytes;
            entry.cpu_percent = totals.cpu_percent;
        }
        // A sleeping app has no process, so the loop above never sees it.
        for name in manager.asleep_apps() {
            metrics.entry(name).or_default().asleep = true;
        }
    }

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
        .body(full(bytes))
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

/// Refuse a rule whose `@auth` hashes bcrypt could not, or should not, verify:
/// malformed, or at a cost outside 4..=13 (see `auth::validate_hash`). Run
/// after `carry_forward_auth_hashes`, so kept hashes are checked too.
fn validate_auth_hashes(rule: &ProxyRule) -> Result<(), String> {
    for entry in &rule.auth {
        auth::validate_hash(&entry.hash)
            .map_err(|e| format!("auth entry for {}: {}", entry.username, e))?;
    }
    Ok(())
}

pub fn post_route(state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
    let mut rule: ProxyRule = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("Invalid route JSON: {}", e)),
    };

    // A new route has nothing to inherit from: every auth entry needs a hash.
    if let Err(e) = rule.carry_forward_auth_hashes(None) {
        return error_response(400, &e.to_string());
    }
    if let Err(e) = validate_auth_hashes(&rule) {
        return error_response(400, &e);
    }
    if let Err(e) = rule.validate() {
        return error_response(400, &e.to_string());
    }

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
    let mut rule: ProxyRule = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("Invalid route JSON: {}", e)),
    };

    // `hash: ""` on a username the route already has means "keep"; the API
    // never returns hashes, so this is how the UI re-submits existing users.
    let cfg = state.config_manager.get_config();
    if let Err(e) = rule.carry_forward_auth_hashes(cfg.rules.get(index)) {
        return error_response(400, &e.to_string());
    }
    if let Err(e) = validate_auth_hashes(&rule) {
        return error_response(400, &e);
    }
    if let Err(e) = rule.validate() {
        return error_response(400, &e.to_string());
    }

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

    let mut update: ConfigUpdate = match serde_json::from_str(body) {
        Ok(u) => u,
        Err(e) => return error_response(400, &format!("Invalid config JSON: {}", e)),
    };

    // Whole-table replace: a `hash: ""` entry keeps the hash of the rule it
    // replaces. That rule is identified by its matcher, not its position — a
    // PUT that deletes, inserts or reorders rules shifts every index, and
    // pairing by index would hand a route the password of whichever rule
    // used to sit there (or reject a legitimate deletion). The same-index
    // rule is preferred when its matcher matches, so duplicate matchers
    // still pair up one-to-one.
    if let Err(e) = crate::config::validate_global_scripts(&update.global_scripts) {
        return error_response(400, &e.to_string());
    }
    let cfg = state.config_manager.get_config();
    for (index, rule) in update.rules.iter_mut().enumerate() {
        let existing = cfg
            .rules
            .get(index)
            .filter(|old| old.matcher == rule.matcher)
            .or_else(|| cfg.rules.iter().find(|old| old.matcher == rule.matcher));
        if let Err(e) = rule.carry_forward_auth_hashes(existing) {
            return error_response(400, &format!("rule {}: {}", index, e));
        }
        if let Err(e) = validate_auth_hashes(rule) {
            return error_response(400, &format!("rule {}: {}", index, e));
        }
        if let Err(e) = rule.validate() {
            return error_response(400, &format!("rule {}: {}", index, e));
        }
    }

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

/// `POST /api/v1/hash-password` — bcrypt a password at the default cost (12).
///
/// Runs on the bounded bcrypt pool like every credential check: hashing is the
/// same quarter-second of CPU, and done inline it parked a tokio worker per
/// call. Answers 503 when the pool stays saturated.
pub async fn post_hash_password(_state: &Arc<AdminState>, body: &str) -> Response<BoxBody> {
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

    let password = req.password;
    let Some(hash) = auth::run_bcrypt(move || auth::generate_hash(&password)).await else {
        return error_response(503, "password hashing is busy, retry shortly");
    };
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
        type Error = crate::pool::BoxError;

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

#[cfg(test)]
mod acme_challenge_tests {
    use super::plausible_acme_token;

    #[test]
    fn a_real_token_is_accepted() {
        // What Let's Encrypt actually issues: base64url, 43 characters.
        assert!(plausible_acme_token(
            "cVpQ4jNJb2xVZk1sTHBRc2RmZ2hqa2wxMjM0NTY3ODkw"
        ));
        assert!(plausible_acme_token("A-b_C-d_E-f_G-h_I-j_K1"));
    }

    #[test]
    fn a_token_that_could_walk_the_keyspace_is_refused_at_push_time() {
        // The token is used to build a lookup key reached from an
        // unauthenticated request path. Rejecting it here gives the pusher one
        // clear error; accepting it and never matching gives both ends a
        // validation failure with no visible cause.
        for token in [
            "../../etc/passwd",
            "a/b/../../../secret",
            "tok en with spaces here",
            "token.with.dots.aaaaaaaaa",
            "%2e%2e%2fetc%2fpasswd%2e",
        ] {
            assert!(!plausible_acme_token(token), "accepted {token:?}");
        }
    }

    #[test]
    fn length_is_bounded_at_both_ends() {
        // Too short is not an ACME token; unbounded length is an unbounded
        // key in a map any peer can push to.
        assert!(!plausible_acme_token(""));
        assert!(!plausible_acme_token("tooshort"));
        assert!(!plausible_acme_token(&"a".repeat(21)));
        assert!(plausible_acme_token(&"a".repeat(22)));
        assert!(plausible_acme_token(&"a".repeat(128)));
        assert!(!plausible_acme_token(&"a".repeat(129)));
    }
}

#[cfg(test)]
mod routing_table_tests {
    use super::*;
    use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    use std::time::Instant;

    /// An admin state with an app manager over empty `sites/`, which is all
    /// the routing-table endpoints need.
    fn state(dir: &tempfile::TempDir) -> Arc<AdminState> {
        let sites = dir.path().join("sites");
        std::fs::create_dir_all(&sites).unwrap();
        let conf = dir.path().join("proxy.conf");
        std::fs::write(&conf, "default -> http://localhost:3000\n").unwrap();
        let config_manager =
            Arc::new(crate::config::ConfigManager::new(conf.to_str().unwrap()).unwrap());
        let port_manager = Arc::new(
            crate::app::PortManager::new(dir.path().join("run").to_str().unwrap()).unwrap(),
        );
        let app_manager = crate::app::AppManager::new(
            sites.to_str().unwrap(),
            port_manager,
            config_manager.clone(),
            false,
        )
        .unwrap();
        Arc::new(AdminState {
            config_manager,
            metrics: crate::metrics::new_metrics(),
            start_time: Instant::now(),
            circuit_breaker: Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default())),
            app_manager: Some(Arc::new(app_manager)),
            rate_limiter: None,
            tls_manager: None,
            challenge_store: None,
        })
    }

    fn hash() -> String {
        crate::auth::hash_password("pw", 4)
    }

    async fn push(state: &Arc<AdminState>, body: serde_json::Value) -> u16 {
        put_routing_table(state, &body.to_string())
            .await
            .status()
            .as_u16()
    }

    #[tokio::test]
    async fn only_http_targets_with_a_host_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        for url in [
            "file:///etc/passwd",
            "unix:/run/app.sock",
            "ftp://10.0.0.1/",
            "data:text/plain,hi",
        ] {
            let body = serde_json::json!({
                "index": 1,
                "routes": { "x.soli.app": [ { "url": url } ] }
            });
            assert_eq!(push(&state, body).await, 400, "{url} was accepted");
        }
        let body = serde_json::json!({
            "index": 1,
            "routes": { "x.soli.app": [ { "url": "https://10.0.0.1:20001" } ] }
        });
        assert_eq!(push(&state, body).await, 200);
    }

    #[tokio::test]
    async fn a_weight_above_255_is_refused_not_wrapped() {
        // `as u8` turned 256 into 0 and 300 into 44, silently.
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        for weight in [
            serde_json::json!(256),
            serde_json::json!(-1),
            serde_json::json!("10"),
        ] {
            let body = serde_json::json!({
                "index": 1,
                "routes": { "x.soli.app": [ { "url": "http://10.0.0.1:1", "weight": weight } ] }
            });
            assert_eq!(
                push(&state, body).await,
                400,
                "weight {weight} was accepted"
            );
        }
        let body = serde_json::json!({
            "index": 1,
            "routes": { "x.soli.app": [ { "url": "http://10.0.0.1:1", "weight": 255 } ] }
        });
        assert_eq!(push(&state, body).await, 200);
    }

    #[tokio::test]
    async fn a_replayed_push_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let body = serde_json::json!({
            "index": 0,
            "routes": { "x.soli.app": [ { "url": "http://10.0.0.1:1" } ] }
        });
        assert_eq!(push(&state, body.clone()).await, 200);
        assert_eq!(push(&state, body).await, 409);
    }

    /// The request path asks `resolve_app_request` for a host's target, and
    /// gates the request on the `auth` that comes back with it: a pushed
    /// domain that carries auth must get it there, not only from
    /// `auth_for_host`.
    #[tokio::test]
    async fn pushed_auth_comes_back_with_the_pushed_target() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let manager = state.app_manager.clone().unwrap();
        let body = serde_json::json!({
            "index": 1,
            "routes": {
                "locked.soli.app": [ { "url": "http://10.0.0.1:1" } ],
                "open.soli.app": [ { "url": "http://10.0.0.2:1" } ]
            },
            "auth": { "locked.soli.app": { "users": { "admin": hash() } } }
        });
        assert_eq!(push(&state, body).await, 200);

        let locked = manager
            .resolve_app_request("locked.soli.app", &|_| true)
            .await
            .expect("a pushed domain resolves");
        assert!(
            locked.app.is_none(),
            "a pushed route belongs to no local app"
        );
        assert_eq!(locked.target.url.host_str(), Some("10.0.0.1"));
        let auth = locked
            .auth
            .expect("the pushed domain's auth must come with its target");
        assert_eq!(auth.users[0].username, "admin");
        assert!(auth.requires_auth("/"));

        let open = manager
            .resolve_app_request("open.soli.app", &|_| true)
            .await
            .expect("a pushed domain resolves");
        assert!(open.auth.is_none(), "a domain pushed without auth is open");
    }

    /// Every string the serializer writes verbatim is refused when it could
    /// not come back as the same token: a `\n` in a JSON field used to land
    /// in proxy.conf as a line of its own — a whole route, injected.
    #[test]
    fn admin_route_json_cannot_inject_proxy_conf_lines() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let conf = dir.path().join("proxy.conf");
        let before = std::fs::read_to_string(&conf).unwrap();
        let injected = "\nevil.example.com -> http://10.0.0.66/";
        let rule = |matcher: serde_json::Value, extra: serde_json::Value| {
            let mut rule = serde_json::json!({
                "matcher": matcher,
                "targets": [{ "url": "https://localhost:9999/", "weight": 100 }],
                "headers": [],
                "scripts": []
            });
            for (k, v) in extra.as_object().unwrap() {
                rule[k] = v.clone();
            }
            rule
        };
        let prefix = serde_json::json!({ "type": "prefix", "value": "/a/" });
        let bad = [
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "tls_ca": format!("/etc/ca.pem{injected}") } }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "tls_ca": "/etc/my ca.pem" } }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "tls_ca": "/etc/ca.pem\\" } }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "tls_client_cert": "/c.pem", "tls_client_key": "/k,x.pem" } }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "tls_sni": format!("a.example{injected}") } }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "upstream": { "health": format!("/up{injected}") } }),
            ),
            rule(
                serde_json::json!({ "type": "prefix", "value": format!("/b/{injected}") }),
                serde_json::json!({}),
            ),
            rule(
                serde_json::json!({ "type": "exact", "value": "/c->http://10.0.0.66/" }),
                serde_json::json!({}),
            ),
            rule(
                serde_json::json!({ "type": "regex", "value": format!("^/d{injected}") }),
                serde_json::json!({}),
            ),
            rule(
                serde_json::json!({ "type": "domain", "value": "#x.example" }),
                serde_json::json!({}),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({
                    "auth": [{ "username": "a", "hash": hash() }],
                    "auth_exempt": [format!("/hook{injected}")]
                }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "auth": [{ "username": format!("a{injected}"), "hash": hash() }] }),
            ),
            rule(
                prefix.clone(),
                serde_json::json!({ "scripts": [format!("a.lua{injected} ok.lua")] }),
            ),
        ];
        for rule in &bad {
            assert_eq!(
                post_route(&state, &rule.to_string()).status(),
                400,
                "accepted {rule}"
            );
            let table = serde_json::json!({ "rules": [rule] });
            assert_eq!(
                put_config(&state, &table.to_string()).status(),
                400,
                "accepted {rule}"
            );
        }
        let scripts =
            serde_json::json!({ "rules": [], "global_scripts": [format!("g.lua{injected}")] });
        assert_eq!(put_config(&state, &scripts.to_string()).status(), 400);
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), before);
    }

    /// A route whose TLS file cannot be loaded is refused *before* proxy.conf
    /// is written: it used to be on disk already when the 500 came back, and
    /// the next reload failed on it.
    #[test]
    fn a_route_whose_tls_file_fails_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let conf = dir.path().join("proxy.conf");
        let before = std::fs::read_to_string(&conf).unwrap();
        let rule = serde_json::json!({
            "matcher": { "type": "prefix", "value": "/a/" },
            "targets": [{ "url": "https://localhost:9999/", "weight": 100 }],
            "headers": [],
            "scripts": [],
            "upstream": { "tls_ca": "/nonexistent/soli-proxy-test-ca.pem" }
        });
        let resp = post_route(&state, &rule.to_string());
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), before);
        assert_eq!(state.config_manager.get_config().rules.len(), 1);
    }

    /// A route arriving as JSON is checked like a `proxy.conf` line before it
    /// is written: a bad `headers` entry or a regex capture the pattern lacks
    /// is a 400, not a file the next reload refuses.
    #[test]
    fn admin_routes_are_fully_validated_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let before = state.config_manager.get_config().rules.len();
        let bad = [
            serde_json::json!({
                "matcher": { "type": "prefix", "value": "/a/" },
                "targets": [{ "url": "http://localhost:9999/", "weight": 100 }],
                "headers": [{ "name": "Connection", "value": "close" }],
                "scripts": []
            }),
            serde_json::json!({
                "matcher": { "type": "prefix", "value": "/a/" },
                "targets": [{ "url": "http://localhost:9999/", "weight": 100 }],
                "headers": [{ "name": "X-Who", "value": "$nobody" }],
                "scripts": []
            }),
            serde_json::json!({
                "matcher": { "type": "regex", "value": "^/u/(\\d+)$" },
                "targets": [{ "url": "http://localhost:9999/users/$2", "weight": 100 }],
                "headers": [],
                "scripts": []
            }),
        ];
        for rule in &bad {
            assert_eq!(
                post_route(&state, &rule.to_string()).status(),
                400,
                "accepted {rule}"
            );
            assert_eq!(
                put_route(&state, 0, &rule.to_string()).status(),
                400,
                "accepted {rule}"
            );
            let table = serde_json::json!({ "rules": [rule] });
            assert_eq!(
                put_config(&state, &table.to_string()).status(),
                400,
                "accepted {rule}"
            );
        }
        assert_eq!(state.config_manager.get_config().rules.len(), before);

        let good = serde_json::json!({
            "matcher": { "type": "regex", "value": "^/u/(\\d+)$" },
            "targets": [{ "url": "http://localhost:9999/users/$1", "weight": 100 }],
            "headers": [{ "name": "X-Client", "value": "$client_ip" }],
            "scripts": []
        });
        assert_eq!(post_route(&state, &good.to_string()).status(), 201);
    }

    #[tokio::test]
    async fn pushed_auth_is_validated_then_enforced_for_its_domain() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let manager = state.app_manager.clone().unwrap();
        let routes = serde_json::json!({ "x.soli.app": [ { "url": "http://10.0.0.1:1" } ] });

        // Un locataire ne choisit pas le facteur de cout du proxy.
        let slow = format!("$2b$31${}", "a".repeat(53));
        for auth in [
            serde_json::json!({ "x.soli.app": { "users": { "admin": slow } } }),
            serde_json::json!({ "x.soli.app": { "users": { "admin": "not-a-hash" } } }),
            serde_json::json!({ "y.soli.app": { "users": { "admin": hash() } } }),
            serde_json::json!({ "x.soli.app": { "users": { "admin": hash() }, "bogus": 1 } }),
        ] {
            let body = serde_json::json!({ "index": 1, "routes": routes, "auth": auth });
            assert_eq!(push(&state, body).await, 400, "{auth} was accepted");
        }
        assert!(manager.auth_for_host("x.soli.app").await.is_none());

        let body = serde_json::json!({
            "index": 1,
            "routes": routes,
            "auth": { "X.soli.app": { "users": { "admin": hash() }, "noauth": ["/hooks/*"] } }
        });
        assert_eq!(push(&state, body).await, 200);
        let auth = manager
            .auth_for_host("x.soli.app")
            .await
            .expect("a pushed domain's auth must be enforced by this proxy");
        assert_eq!(auth.users[0].username, "admin");
        assert!(auth.requires_auth("/"));
        assert!(!auth.requires_auth("/hooks/github"));

        // The read side never returns a hash.
        let response = get_routing_table(&state).await;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("\"usernames\":[\"admin\"]"), "{text}");
        assert!(!text.contains("$2b$"), "{text}");
    }

    /// A pushed domain may carry forward-auth alone (no Basic accounts): it
    /// is kept, checked like `app.infos`, and enforced here.
    #[tokio::test]
    async fn pushed_forward_auth_is_validated_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let manager = state.app_manager.clone().unwrap();
        let routes = serde_json::json!({ "x.soli.app": [ { "url": "http://10.0.0.1:1" } ] });

        for auth in [
            serde_json::json!({ "x.soli.app": { "forward": "file:///etc/passwd" } }),
            serde_json::json!({ "x.soli.app": { "forward_headers": ["X-User"] } }),
            serde_json::json!({ "x.soli.app": {
                "forward": "http://auth:4180/", "forward_headers": ["Host"] } }),
        ] {
            let body = serde_json::json!({ "index": 1, "routes": routes, "auth": auth });
            assert_eq!(push(&state, body).await, 400, "{auth} was accepted");
        }

        let body = serde_json::json!({
            "index": 1,
            "routes": routes,
            "auth": { "x.soli.app": {
                "forward": "http://auth:4180/", "forward_headers": ["X-Auth-Request-User"] } }
        });
        assert_eq!(push(&state, body).await, 200);
        let auth = manager
            .auth_for_host("x.soli.app")
            .await
            .expect("forward-auth alone must be kept");
        assert_eq!(auth.forward.as_ref().unwrap().url(), "http://auth:4180/");
        assert!(!auth.requires_auth("/"), "no Basic accounts");
    }

    /// A route's forward-auth is checked on the way in and survives the
    /// admin API's rewrite of `proxy.conf`.
    #[test]
    fn admin_routes_carry_forward_auth() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let rule = |url: &str| {
            serde_json::json!({
                "matcher": { "type": "domain", "value": "app.example.com" },
                "targets": [{ "url": "http://localhost:9999/", "weight": 100 }],
                "headers": [],
                "scripts": [],
                "auth_exempt": ["/up"],
                "forward_auth": { "url": url, "headers": ["X-Auth-User"] }
            })
        };
        assert_eq!(
            post_route(&state, &rule("ftp://auth/v").to_string()).status(),
            400
        );
        assert_eq!(
            post_route(&state, &rule("http://u:p@auth/v").to_string()).status(),
            400
        );
        assert_eq!(
            post_route(&state, &rule("http://auth:4180/v").to_string()).status(),
            201
        );

        let written = std::fs::read_to_string(dir.path().join("proxy.conf")).unwrap();
        assert!(
            written.contains(
                "@noauth:/up @forward_auth:http://auth:4180/v @forward_auth_headers:x-auth-user"
            ),
            "{written}"
        );
        let cfg = state.config_manager.get_config();
        let added = cfg.rules.last().unwrap();
        assert_eq!(
            added.forward_auth.as_ref().unwrap().url(),
            "http://auth:4180/v"
        );
    }
}
