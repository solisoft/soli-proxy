# Changelog

## [0.29.1](https://github.com/solisoft/soli-proxy/compare/v0.29.0...v0.29.1) (2026-07-28)

### Added

* **apps:** touching `restart.txt` at the root of a site triggers a zero-downtime blue/green deploy of that app, so a deploy script can end with `touch <site>/restart.txt` instead of an SSH-side `soli-proxy restart <app>`. The file is **polled** (2s by default) rather than watched: sites are typically symlinks into out-of-tree repositories and inotify does not traverse symlinks, so the existing sites watcher never sees files inside them. The first poll after startup only records a baseline, so an already-present trigger file does not redeploy every site on daemon restart. Configurable via `[apps].restart_trigger_file` and `[apps].restart_trigger_poll_secs` (`0` disables it).

### Security

* **security(apps):** an app that **fails to start** — spawn error, or a new slot that never passes its health check — is now quarantined instead of being restarted forever. Previously `check_health()` called `failover()` every 30s on any unreachable app with **no failure cap** (`failure_count` was only incremented by the process-exit monitor), so a broken deploy left the app flapping indefinitely, respawning processes and churning ports. The failed slot is killed and marked `Failed`, the previous slot keeps serving, and the health loop, process-exit monitor, and request-triggered failover all skip the app until an **explicit** deploy (trigger file, CLI, or admin API) clears the quarantine. Exposed as `"quarantined": true` on `GET /api/v1/apps[/{name}]` plus a `StatusChanged` SSE event; the deploy-failure path also emits a `failed` status event, which it previously did not.

* **security(proxy):** request-body size limits are now enforced on chunked / HTTP-2 bodies by streaming the inbound body through `http_body_util::Limited` (`proxy_request_body`) and returning **413** on overflow, instead of blanket-rejecting `Transfer-Encoding: chunked` — a body that omits `Content-Length` (or lies about it) can no longer slip past the fast-path check and buffer without bound. The admin proxy path buffers with the same hard cap.
* **security(circuit_breaker):** a backend request that fails because the client's body exceeded `max_request_size` no longer records a circuit-breaker failure or triggers async failover — the backend never saw a completed request, so an attacker sending repeated oversized uploads can no longer trip a healthy backend's breaker open and take it offline for everyone. The limit condition is detected by downcasting to `http_body_util::LengthLimitError` (Display-string match kept only as a backstop).
* **security(proxy/websocket):** the raw WebSocket upgrade request and every forwarded header are guarded against CR/LF — a header value, host, path, query, `Sec-WebSocket-*` value, or rewritten `Origin` carrying `\r`/`\n` can no longer smuggle extra request lines or headers into the backend handshake.
* **security(proxy/lua):** proxy target URLs from config and from Lua `on_route` overrides are validated — only `http://`, `https://`, and `redirect://` with a non-empty host are allowed; `file://`, `gopher://`, `ftp://`, and CRLF-bearing targets are refused (**502** / ignored override), closing an SSRF/scheme-smuggling avenue through a compromised route script.
* **security(proxy):** the `force_https` HTTP→HTTPS redirect only redirects to a host/path the proxy actually serves (a matching routing rule or a managed app domain); an unserved forged `Host` gets **400** instead of a 308 to an attacker-chosen origin — closing an open-redirect / Host-header injection vector.
* **security(admin):** the admin API logs a loud warning when it binds a loopback address with no authentication configured — any other local process could otherwise deploy apps, stop apps, and edit routes. Set `ADMIN_USER`/`ADMIN_PASSWORD` or `[admin].api_key`.
* **security(config):** a plaintext `ADMIN_PASSWORD` is now bcrypt-hashed at startup (both the `Default` and env-loaded paths) instead of being stored as-is — previously such a value was kept verbatim and every login attempt failed. `ADMIN_PASSWORD_HASH` is preferred and takes precedence.
* **security(tls/acme):** self-signed and ACME private-key files are tightened to `0600` on load if an earlier install left them group/world-readable.
* **security(admin/deploy):** the Docker container command is spawned without a shell — it uses the same argv parsing (`parse_start_command`) as the native spawn path, so a compromised `start_script` can no longer inject through `/bin/sh -c`.
* **security(admin):** deployment-log responses are capped at the last **256 KiB** so a multi-GB app log can't OOM the proxy; admin request bodies are capped at **1 MB** (`Limited`).

### Performance

* **perf(proxy):** all HTTP and HTTPS accept loops now share **one** connection pool (cheap clones, shared idle keep-alive sockets) with a per-host idle cap of **64** — previously every listener built its own pool, and a multi-tenant deploy with many origins could grow unbounded keep-alive pools.
* **perf(proxy/routing):** host matching in `find_matching_rule` is a single case-insensitive linear scan for any rule count. A previous "optimization" rebuilt a throwaway `HashMap` domain index on **every** request (O(rules) allocations for one lookup), which was slower than the scan it replaced; it's removed.
* **perf(circuit_breaker):** known backends are pre-registered (`prewarm`) at startup so the first request under load doesn't take the `targets` write lock on a cold map.

### Fixed

* **fix(systemd):** the shipped `scripts/soli-proxy.service` could never start — `ExecStart` invoked a `daemon` subcommand that does not exist (`error: unrecognized subcommand 'daemon'`; the flag is `-d`/`--daemon`) and hardcoded a developer's home directory. It now uses `--conf` + `--sites-dir` with a `WorkingDirectory`, and documents that `--conf` takes **`proxy.conf`** (not `config.toml`, which is read from the same directory), that `--sites-dir` is the only way to set the sites location, and that `-d` must not be combined with `Type=simple`. The README's systemd section gained a table of where `run/logs/<app>/<slot>.log`, `run/app_state.json`, `run/ports.lock`, and `certs/` actually land — all relative to `WorkingDirectory`, and unaffected by `SOLI_LOG_DIR`.
* **fix(proxy/lb):** per-rule round-robin / weighted counters that grow on demand — hot-reloaded routes beyond the startup rule count previously all shared `counters[0]`, so their load balancing was coupled; each route now advances an independent counter.
* **fix(proxy/lb):** the weighted strategy with all-zero target weights falls back to the first available target instead of recursing into itself forever (stack overflow).
* **fix(proxy/lua):** Lua `on_request` header edits are actually applied to the forwarded request (they were previously computed and discarded), and only headers whose value genuinely changed are rewritten — so duplicate-valued and non-UTF8 original headers are preserved rather than collapsed to the lossy Lua snapshot.

### Changed

* **config:** `include_request_body` / `include_response_body` are documented as reserved (currently no effect) and default to `false`; the unused `redis_url` is dropped from `[rate_limiting]` (the token bucket is in-process).

## [0.5.0](https://github.com/solisoft/soli-proxy/compare/v0.4.0...v0.5.0) (2026-02-12)


### Features

* **ci:** add macOS build target for cross-compilation ([6242c6c](https://github.com/solisoft/soli-proxy/commit/6242c6cca5f7dee41001ab83237d49a6d82b079f))
* **ci:** add system dependencies installation to CI workflow ([c5e3e48](https://github.com/solisoft/soli-proxy/commit/c5e3e48bf869a779bbbd6242cca4a1f76ba2ce91))

## [0.4.0](https://github.com/solisoft/soli-proxy/compare/v0.3.0...v0.4.0) (2026-02-10)


### Features

* **ci:** add build-binaries job for cross-compilation and release asset upload ([87bc970](https://github.com/solisoft/soli-proxy/commit/87bc9701b1aff4756010145bb3195e162dc6a236))


### Bug Fixes

* **ci:** update PR merge command to remove auto flag for better control ([5f078d5](https://github.com/solisoft/soli-proxy/commit/5f078d5de6f1f66099dd8ae7deb89e983c06bc68))

## [0.3.0](https://github.com/solisoft/soli-proxy/compare/v0.2.0...v0.3.0) (2026-02-10)


### Features

* **app:** enhance AppInfo configuration with auto-detection and fallback logic ([852fc03](https://github.com/solisoft/soli-proxy/commit/852fc030781846859d29cbfc1b697a56e2325224))
* **metrics:** enhance application metrics tracking and add API endpoints for retrieving app metrics ([c5f93b8](https://github.com/solisoft/soli-proxy/commit/c5f93b8278abd37ed4f3f811598a624f16008b6c))

## [0.2.0](https://github.com/solisoft/soli-proxy/compare/v0.1.0...v0.2.0) (2026-02-10)


### Features

* **admin:** initialize _admin module with MVC structure, controllers, and views ([9023363](https://github.com/solisoft/soli-proxy/commit/9023363f2e151d8081038c9f06a07e7b91b49cb6))


### Bug Fixes

* **app:** modify AppInfo::from_path to return default AppConfig if app.infos is not found ([a850a70](https://github.com/solisoft/soli-proxy/commit/a850a705661099954543eaa785fc747082ded2a0))

## 0.1.0 (2026-02-10)


### Features

* **admin:** implement admin REST API with configuration and metrics endpoints ([0061028](https://github.com/solisoft/soli-proxy/commit/006102838192d752ffd72554178d2bd9a7cbd04c))
* **app:** introduce app management with deployment, restart, and rollback endpoints ([4d24521](https://github.com/solisoft/soli-proxy/commit/4d245214c415c2a2ccd129d35aae175e3ab1ad71))
* **circuit_breaker:** implement circuit breaker functionality with configuration and admin endpoints ([8794584](https://github.com/solisoft/soli-proxy/commit/8794584dc6c26ca9767263ebd9fd4e47c528a209))
* **config:** enhance proxy configuration parsing with line continuation support and add tests ([44737ea](https://github.com/solisoft/soli-proxy/commit/44737eab1c1ad7b6283d5542555fadba56a46e8a))
* **lua:** add configuration and integration for Lua scripting support ([1024df5](https://github.com/solisoft/soli-proxy/commit/1024df5b732fafbcc6bc6b65531b87d104bc7547))
