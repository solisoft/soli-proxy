//! Admin API tests that need HTTP Basic credentials configured.
//!
//! Kept in its own test binary on purpose: `[admin].username` and
//! `password_hash` are `#[serde(skip)]` and only ever come from `ADMIN_USER`
//! / `ADMIN_PASSWORD_HASH`, which are process-wide. Setting them here cannot
//! leak into the unauthenticated `admin_tests` harness in another binary.

use soli_proxy::admin::{run_admin_server, AdminState};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::config::ConfigManager;
use soli_proxy::new_metrics;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tempfile::tempdir;

const USER: &str = "admin";
const PASSWORD: &str = "correct horse";
const API_KEY: &str = "secret123";

static HASH: LazyLock<String> = LazyLock::new(|| soli_proxy::auth::generate_hash(PASSWORD));

/// Start an admin server with both an API key and Basic credentials.
async fn start_admin() -> (u16, Arc<ConfigManager>) {
    // Every test in this binary sets the same values, so concurrent tests
    // cannot observe each other's writes as anything but the same value.
    std::env::set_var("ADMIN_USER", USER);
    std::env::set_var("ADMIN_PASSWORD_HASH", HASH.as_str());

    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("proxy.conf");
    let toml_path = temp_dir.path().join("config.toml");

    std::fs::write(&config_path, "default -> http://localhost:3000\n").unwrap();
    let port = portpicker::pick_unused_port().unwrap_or(19095);
    std::fs::write(
        &toml_path,
        format!(
            "[admin]\nenabled = true\nbind = \"127.0.0.1:{}\"\napi_key = \"{}\"\n",
            port, API_KEY
        ),
    )
    .unwrap();

    let manager = Arc::new(ConfigManager::new(config_path.to_str().unwrap()).unwrap());
    let admin = &manager.get_config().admin;
    assert_eq!(admin.username.as_deref(), Some(USER));
    assert_eq!(admin.password_hash.as_deref(), Some(HASH.as_str()));

    let state = Arc::new(AdminState {
        config_manager: manager.clone(),
        metrics: new_metrics(),
        start_time: Instant::now(),
        circuit_breaker: Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default())),
        app_manager: None,
        rate_limiter: None,
        tls_manager: None,
        challenge_store: None,
    });
    tokio::spawn(async move {
        let _ = run_admin_server(state).await;
    });

    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            std::mem::forget(temp_dir);
            return (port, manager);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Admin server did not start on port {}", port);
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{}{}", port, path)
}

#[tokio::test]
async fn basic_auth_mutation_without_x_requested_with_is_rejected() {
    // A browser replays cached Basic credentials on a form post from any
    // origin; the form cannot add X-Requested-With, so its absence is the
    // signal. This is exactly the request a CSRF page would make.
    let (port, _mgr) = start_admin().await;

    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .basic_auth(USER, Some(PASSWORD))
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("cross-site request rejected"), "{body}");
}

#[tokio::test]
async fn basic_auth_mutation_with_x_requested_with_passes_the_gate() {
    let (port, _mgr) = start_admin().await;

    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .basic_auth(USER, Some(PASSWORD))
        .header("X-Requested-With", "soli-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // What a same-origin browser fetch sends.
    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .basic_auth(USER, Some(PASSWORD))
        .header("X-Requested-With", "soli-admin")
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn basic_auth_mutation_from_another_site_is_rejected_even_with_header() {
    let (port, _mgr) = start_admin().await;

    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .basic_auth(USER, Some(PASSWORD))
        .header("X-Requested-With", "soli-admin")
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn api_key_mutation_needs_no_extra_header() {
    // The TUI and CLI send only X-Api-Key; a browser never attaches that on
    // its own, so there is nothing to defend against and nothing to require.
    let (port, _mgr) = start_admin().await;

    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .header("X-Api-Key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn basic_auth_reads_need_no_extra_header() {
    let (port, _mgr) = start_admin().await;

    let resp = client()
        .get(url(port, "/api/v1/status"))
        .basic_auth(USER, Some(PASSWORD))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // And a wrong password is still a 401, not a 403: the CSRF gate sits
    // behind authentication, never in front of it.
    let resp = client()
        .post(url(port, "/api/v1/reload"))
        .basic_auth(USER, Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}
