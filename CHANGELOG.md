# Changelog

## [0.35.1](https://github.com/solisoft/soli-proxy/compare/v0.35.0...v0.35.1) (2026-09-23)

### Performance Improvements

* **A credential is verified once, not once per request.** bcrypt at cost 12 takes ~300 ms
  by design — that slowness is what makes guessing passwords expensive. The Basic-auth gate
  ran it on *every* request, so a page paid it, then its stylesheet paid it, then each of
  its images. Measured on a protected production site: **15 ms of application behind 360 ms
  of doorman**, and the same page served through Cloudflare took 470 ms end to end.

  `auth::verify_once` now remembers a verdict for five minutes, keyed by a SHA-256 of the
  `Authorization` header **and** of the accounts configured on the route — so rotating a
  password invalidates what was remembered instead of leaving the old one working. Digesting
  also keeps the plaintext credential out of the process memory.

  ```
  right password:  483 ms, then 3.9 ms · 5.0 ms · 4.5 ms
  wrong password:  237 ms · 232 ms, still 401
  ```

  ⚠️ **Only successes are remembered, and that is the whole design.** Caching failures would
  hand an attacker a fast path to millions of guesses. A wrong password still pays full
  price, every time.

### Bug Fixes

* **The timing equalizer follows the accounts' cost.** `dummy_hash()` was pinned to
  `DEFAULT_COST` while its own comment required it to match the configured hashes. An
  operator lowering a gate to cost 8 — a staging password needs no key stretching — would
  have made an unknown username measurably *slower* than a known one, handing back the user
  enumeration the equalizer exists to prevent. `dummy_hash_at(cost)` reads the cost from the
  accounts and memoizes one dummy per cost.

### Features

* **`hash-password --cost N`** (4–31, default 12), without which no operator could lower
  that cost in the first place.

## [0.35.0](https://github.com/solisoft/soli-proxy/compare/v0.34.0...v0.35.0) (2026-09-15)

### Bug Fixes

* **A path carve-out is no longer deleted from `proxy.conf`.** `sync_routes` prunes static
  rules for app-managed domains so they cannot shadow blue-green routing, and it matched
  `host/path/* -> …` as well as `host -> …`. A carve-out shadows nothing — it claims one
  prefix, and the router already relies on that: `override_with_app` defers to the
  `AppManager` only for whole-domain rules, precisely so an explicit path rule still wins.
  The pruner was deleting the rules the router documents as intentional.

  The cost was quiet and recurring. Pruning rewrites `proxy.conf`, and `sync_routes` runs
  from three places — adding an alias, app auto-start (**every restart**) and the traffic
  switch (**every deploy**). So a hand-written route vanished, most often mid-deploy, with
  only an info line to say why; re-adding it worked until the next deploy, which is what
  disguised it as anything other than a proxy behaviour.

  ```
  # Deleted on every deploy before this release; kept now.
  site.example.com/_eui/* -> https://backend.example.com/_eui/
  ```

  Whole-domain rules are still pruned, unchanged: those really do shadow an app.

## [0.34.0](https://github.com/solisoft/soli-proxy/compare/v0.33.0...v0.34.0) (2026-09-15)

### Features

* **Scale to zero: `idle_timeout` in `app.infos`.** Most fleets are mostly idle — on a box
  hosting thirty small sites a day's traffic typically touches a handful, and every other one
  holds its full runtime in memory for nothing. An app past its threshold is stopped the way
  `soli-proxy stop` stops it, so the exit is not mistaken for a crash: no failover, no
  quarantine. The next request for one of its domains is **held** while the app starts on its
  current slot and is polled for health, then forwarded as usual — the first visitor waits about
  a second, everyone else finds it running, and concurrent first requests share one start.

  ```toml
  idle_timeout = 900   # sleep after 15 minutes without a request
  ```

  A sleeping app keeps its certificate registered and keeps winning over static `proxy.conf`
  rules for its domains, exactly as a running one does. The default is `0` — never sleep — which
  is the right value for anything that does work without being asked: cron jobs, background
  workers, WebSocket rooms, a cache that takes more than a moment to rebuild. `[apps]
  idle_timeout` in `config.toml` sets a fleet-wide default; `_admin` never sleeps regardless.

* **`[development]` and `[production]` sections in `app.infos`.** An app has one manifest, and
  the environment the proxy runs in picks the values — instead of a dev copy and a prod copy
  drifting apart in two files nobody diffs:

  ```toml
  workers = 4
  idle_timeout = 1800

  [development]
  workers = 1          # one worker, and no sleeping, while developing
  idle_timeout = 0
  ```

  `--dev` selects `[development]`; every other run selects `[production]`. The chosen section
  is applied key by key over the top level, and a nested table merges into its counterpart
  rather than replacing it, so `[production.auth.users]` adds accounts without discarding the
  `noauth` list written above it. The section that is not selected is dropped unread, so a
  `[production]` block written for a newer proxy never stops a developer's machine from
  starting the app. Both sections are optional and a manifest carrying neither parses exactly
  as before.

* **Discovery logs the `app.infos` keys it does not recognise.** Serde has always ignored them
  without a word — `worker = 4` ran the app with one worker and said nothing — and the overlay
  sections raise the stakes, since a key that lands in the wrong section is ignored just as
  quietly. Unknown keys are still ignored rather than fatal: refusing the manifest would take a
  running app off the routing table over a typo.

## [0.33.0](https://github.com/solisoft/soli-proxy/compare/v0.32.0...v0.33.0) (2026-09-10)

### Features

* **HTTP Basic Auth per app, in `app.infos`.** Apps are routed by the app manager rather than
  by `proxy.conf` rules — `sync_routes` prunes static rules for app-managed domains — so a
  route's `@auth` could never protect an app. An app now declares its own:

  ```toml
  [auth]
  noauth = ["/webhooks/stripe", "/hooks/*"]

  [auth.users]
  admin = "$2b$12$..."
  ```

  `noauth` takes the same syntax as the `@noauth:` route directive (exact path, or a prefix
  ending in `*`) and the same fail-closed rule: a path carrying percent-encoding or a `..`
  segment is never exempt. Auth covers the app's derived domains (`www.`-stripped, `.test` in
  dev) and any admin-managed alias pointing at it, and is enforced on WebSocket upgrades as
  well as plain requests. A `[auth]` section the proxy cannot enforce as written — an empty
  hash, a pattern that does not compare literally — makes the app fail to load rather than
  come up unprotected. `GET /api/v1/apps` reports the configured usernames and carve-outs,
  never the hashes, and the admin UI shows an `auth` badge on protected apps.

### Fixes

* **`app_name_for_host` settles a contested domain the same way routing does.** It iterated a
  `HashMap`, so when two apps declared one domain the app it returned could differ from the
  one `running_app_domains` actually routes to (which picks by name order). Per-app metrics
  could be attributed to the wrong app; with per-app auth reading the same lookup, it would
  have meant answering a protected app's traffic with another app's credentials, or none.

## [0.32.0](https://github.com/solisoft/soli-proxy/compare/v0.31.0...v0.32.0) (2026-09-09)

### Features

* **`@noauth:` exempts paths from a route's Basic Auth.** A whole domain can be
  password-protected while the endpoints that machines call — a Stripe webhook, a health
  probe — stay reachable without credentials:
  `app.example.com -> http://app:8080 @auth:admin:$2b$12$... @noauth:/webhooks/stripe,/hooks/*`.
  Entries are comma-separated and each is either an exact path or a prefix ending in `*`
  (which also matches the bare prefix). Paths are matched against the URL as the client sent
  it, before any prefix stripping, so what you write is what you see in the browser.
  `@noauth` without `@auth` does nothing. Editable from the admin UI (Routes → Basic Auth)
  and the TUI route form, and exposed as `auth_exempt` on the admin API.

  The match is deliberately literal and fails closed: a path carrying percent-encoding or a
  `..`/`.` segment is never exempt, so a request cannot walk out of the carve-out into a
  protected path that a normalising backend would resolve differently. Patterns that cannot
  be compared literally (relative, traversing, percent-encoded) are refused by the admin API
  and dropped with a warning by the `.conf` parser, leaving the path protected.

## [0.31.0](https://github.com/solisoft/soli-proxy/compare/v0.30.0...v0.31.0) (2026-09-04)

### Security

* **Request paths with dot segments are rejected before routing.** Rules match on the raw
  path and per-route auth binds to the matched rule, so `/api/../admin/users` could pass an
  open `/api/` rule and land on `/admin/users` at any backend that normalises. Literal and
  `%2e`-encoded dots are caught, terminated by `/`, end of path, a `;` path parameter
  (`/api/..;/admin`, as Tomcat/Jetty/Spring strip it) or a backslash (`..\`, as IIS treats
  it). An encoded slash (`%2F`) anywhere is rejected as well, since a backend that decodes it
  before routing would see a path the proxy never matched. Backends whose API paths carry
  `%2F` as data (GitLab's `group%2Fproject`, S3-style keys) can set
  `[server] allow_encoded_slash = true`; `..%2F` and `%2F..` stay rejected.
* **`docker_network` is validated.** The value went straight to `docker run --network`, so
  `docker_network = "host"` bypassed the namespace denylist that only looked at
  `docker_options`. `host` and `container:<id>` are refused in every mode, the name must be
  one docker accepts, and the manifest is fully validated before the network is created, so
  a rejected deploy no longer leaves a tenant-named network behind.
* **The single-tenant `docker_options` denylist reads docker's syntax.** It split on `=` and
  whitespace and inspected the next token, so `-v/:/host`, `--mount type=bind,source=/`,
  `/./:/host`, `--pid container:x`, `--volumes-from`, `--env-file` and `--group-add` all
  passed. Flags are now parsed the way docker parses them (attached shorthand, `--mount`
  key=value specs), mount sources are normalised and canonicalised before the root / docker
  socket check, and the namespace, volumes-from, env-file and group-add flags are on the list.
* **Multi-tenant bind mounts may only be the site directory itself, emitted canonicalised.**
  A sub-path such as `<site>/data` was validated by canonicalising it, but the tenant's raw
  token reached `docker run`, which resolves the path again at mount time — and every
  component under the site directory is writable by the tenant's still-running previous slot,
  which could swap `data` for a symlink to `/` in between. The site directory's own path has
  no tenant-writable component; it is the only permitted source, and its canonical path is
  what reaches docker.
* **`PUT /api/v1/config` pairs auth hashes by matcher, not index.** A `hash: ""` entry (the
  API never returns hashes) was resolved against whichever old rule sat at the same index, so
  deleting or reordering rules handed a route the password of another (same username) or
  rejected the change with 400 (different username).
* **Empty admin credentials count as unset.** `[admin] api_key = ""` (a templated config with
  an unresolved variable) made the server log "no authentication configured" and then 401
  every request, and `ADMIN_USER="" ADMIN_PASSWORD=""` was hashed into a credential that
  `Authorization: Basic Og==` satisfied. Empty strings are dropped at load time.
* **Admin mutations need `X-Requested-With`.** Any non-GET request without `X-Api-Key` must
  carry an `X-Requested-With` header of any value, or it is answered 403. An HTML form cannot
  set it, which is what stops a page the operator visits from driving the API with cached
  Basic credentials or the open loopback default. A bare `curl -X POST` against loopback
  needs `-H X-Requested-With:curl` now.

### Changed

* **`base64.decode` in Lua returns `nil, err` on malformed input instead of raising.** Hook
  errors now fail closed (500 "script error"), so a raise on an attacker-controlled
  `Authorization` header would have turned every malformed credential into a 500. Scripts
  written against the old contract (`pcall(base64.decode, s)`) keep working for valid input,
  but the failure branch must change to check the return value:

  ```lua
  local decoded = base64.decode(token)
  if not decoded then return req:deny(401, "Malformed credentials") end
  ```

  The bundled `scripts/lua/auth.lua` is updated.
* **`name` and `domain` in `app.infos` are validated in every mode.** Hostname characters
  plus `_` (an existing `sites/my_app.example.com` keeps loading), a leading `_` only for
  bundled apps, and `health_check` must be an absolute URL path. A directory whose manifest
  fails is skipped and logged at warn level.
* **The environment allowlist reaches Docker apps too.** `HTTP(S)_PROXY`/`NO_PROXY`,
  `SOLI_RELEASE_BASE_URL` and `SOLI_NO_PIN` are passed as `-e` flags into the container;
  the host-path entries (`XDG_CACHE_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`) are native-only.

### Fixed

* **Apps got the proxy's `HOME`, not their own.** The proxy drops privileges to
  the app's `user` but handed the child the environment variable it inherited
  itself — `/root` under systemd. Every `~`-resolved path therefore pointed at a
  directory the app could not read, silently breaking soli's package cache
  (`~/.soli/packages`), its registry credentials and the Tailwind CLI it
  downloads to `~/.soli/bin`. `HOME` is now read from the passwd entry of the
  user the app actually runs as.

### Added

* **A short environment allowlist survives `env_clear()`.** Apps still start
  with a cleared environment, but `XDG_CACHE_HOME`, `SOLI_RELEASE_BASE_URL`,
  `SOLI_NO_PIN`, the `HTTP(S)_PROXY`/`NO_PROXY` family and `SSL_CERT_FILE` /
  `SSL_CERT_DIR` now pass through when set on the proxy. Without them an app
  behind an egress proxy could not make outbound HTTPS requests, and could not
  be pointed at a shared cache.

  Together these let a Soli app pin its interpreter version
  (`soli_version = "=2.0.3"` in `soli.toml`) and have the proxy start it on that
  version. No proxy configuration is needed — the app already starts with its
  own directory as the working directory, which is where soli looks for the pin.

## [0.29.2](https://github.com/solisoft/soli-proxy/compare/v0.29.1...v0.29.2) (2026-07-29)

Website and admin UI only — the proxy binary is unchanged from 0.29.1.

### Added

* **www:** a Changelog page at `/changelog`, linked from the docs sidebar, the mobile navigation, and the footer.
* **admin:** a Changelog page in the admin UI, linked from the sidebar.

### Fixed

* **fix(www):** the Tailwind content glob was `./app/views/**/*.{erb,html,html.erb}`. Brace expansion matches the whole extension, so `*.html.slv` never matched and every class used only in a `.slv` view was dropped from the build — silently affecting the two pre-existing `.slv` pages (`benchmark`, `dev_https`). Building with the old glob yields 45029 bytes and drops `bg-purple-500/10` and `list-decimal`; with `slv` added, 45853.
* **fix(admin):** the committed `output.css` predated several views and Tailwind is not run at request time, so the changelog page's badge classes resolved to nothing. Rebuilt, and restricted to colour families the palette already carries.

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
