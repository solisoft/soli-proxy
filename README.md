# Soli Proxy

A high-performance reverse proxy built in Rust, with HTTP/2 support, automatic HTTPS, hot config
reload, Lua scripting, and blue-green deploys for the apps it hosts.

## Features

- **HTTP/2+ Support**: Native HTTP/2 with automatic fallback to HTTP/1.1
- **Automatic HTTPS**: Self-signed certificates for development, Let's Encrypt for production
- **Hot Config Reload**: Routing rules swap atomically, without dropping connections (see [Hot Reload](#hot-reload) for what needs a restart)
- **Simple Configuration**: Custom config format with comments support
- **Load Balancing**: Round-robin, weighted and failover, with a per-backend circuit breaker,
  retries on the next target when that is safe, and active health checks
- **Upstream Protocols**: HTTP/1.1, HTTP/2 (`@h2`, `h2c://`) with gRPC trailers, Unix sockets,
  per-route upstream TLS (private CA, SNI, client certificates) and timeouts
- **WebSocket Support**: Full WebSocket proxy capabilities, with idle/lifetime/size limits
- **Middleware**: HTTP Basic auth (per route, per app, admin API), [forward authentication](#forward-authentication) to an SSO service (oauth2-proxy, Authelia, Authentik, …), per-IP rate limiting, request header rules, Lua hooks, JSON or text logging
- **Behind a CDN or load balancer**: real client IP from trusted proxies (`X-Forwarded-For`, `CF-Connecting-IP`, PROXY protocol v1/v2), request IDs, and an access log (JSON or combined)
- **Not included**: JWT/OIDC validation or API-key checks inside the proxy itself — delegate them to an SSO service with [forward authentication](#forward-authentication), or use a Lua `on_request` hook or the backend
- **Responses**: gzip / brotli / zstd compression (opt-in), custom HTML error pages, maintenance mode (global or per app)
- **Health Checks**: Kubernetes-compatible liveness and readiness probes
- **App Health Monitoring**: Automatic health checks with auto-restart for managed apps
- **High Performance**: Built on Tokio and Hyper for maximum throughput

## Quick Start

### Development Mode

```bash
# Build and run in dev mode
cargo run --bin soli-proxy -- --dev

# With custom config and sites directory
cargo run --bin soli-proxy -- --conf ./my-proxy.conf --sites-dir ./my-sites
```

### Production Mode

```bash
# Build release
cargo build --release

# Run in production mode (requires Let's Encrypt config)
./target/release/soli-proxy

# Run as daemon
./target/release/soli-proxy -d

# With custom paths
./target/release/soli-proxy -c /etc/proxy.conf --sites-dir /var/sites
```

### CLI Options

```
soli-proxy [OPTIONS] [COMMAND]

Options:
  -c, --conf <CONF>            Routing rules; config.toml and .env are read from the same
                               directory [default: ./proxy.conf]
  -d, --daemon                 Fork into the background (proxy.pid, proxy.log)
      --dev                    Development mode (.test aliases, one worker, apps get --dev)
      --watch <WATCH>          Reload proxy.conf and rescan sites on change [default: true]
      --sites-dir <SITES_DIR>  One sub-directory per app, named after its domain [default: ./sites]
  -h, --help                   Print help
  -V, --version                Print version
```

There are no `dev`/`prod` positional modes and no `--config` flag: production vs development is
`--dev` plus `[tls] mode` in `config.toml`.

### Subcommands

App lifecycle commands operate on apps discovered in `--sites-dir` and can be
run while the proxy is running (they read shared state from `./run`):

```
soli-proxy deploy  [-c <conf>] <app_name>   # Blue-green deploy: build & switch to the other slot
soli-proxy restart [-c <conf>] <app_name>   # Restart the currently active slot
soli-proxy stop    [-c <conf>] <app_name>   # Stop the app
soli-proxy stop    [-c <conf>] --all        # Stop every app (the proxy keeps running)
soli-proxy logs    [-c <conf>] <app_name>   # Print deployment logs for both slots
```

Other subcommands:

```
soli-proxy tui [-c <conf>] [--sites-dir <DIR>] [--dev]   # Interactive terminal UI
soli-proxy update [--reinstall] [--allow-unverified]     # Self-update from GitHub releases
soli-proxy check [-c <conf>] [--sites-dir <DIR>] [--dev] # Validate config.toml, proxy.conf, every app.infos
soli-proxy hash-password [--cost N]                      # bcrypt hash for @auth / [auth.users] / ADMIN_PASSWORD_HASH
```

`check` loads everything a start would — `config.toml` (and `.env`), `proxy.conf` with the
strict parser, every site's `app.infos` with the discovery rules (multi-tenant ones included) —
and then makes the checks a start makes later or only logs: listener and admin addresses, the
admin API's refusal to run on a public address without a credential, bcrypt hashes and their
cost, port ranges, Lua script files, whether each app can be launched (`docker run` options,
users). It starts nothing, binds no port and writes no file. Each problem is printed as
`file:line: error|warning: message`; every bad `proxy.conf` line is reported, not just the
first. Exit status 1 on any error, so it fits a deploy script or CI:
`soli-proxy check -c /etc/soli-proxy/proxy.conf --sites-dir /srv/sites && systemctl restart soli-proxy`.
The admin API has the same check for a proposed file: `POST /api/v1/config/validate`.

`stop --all` asks the running daemon to stop every app (`POST /api/v1/apps/stop-all`); with no
daemon running it stops them itself — containers by name, native processes only if
`run/spawned.json` proves the proxy started them. See [Restarts and upgrades](#restarts-and-upgrades)
for why apps outlive the proxy.

`hash-password` prompts twice without echo (or reads the first line of stdin when it is not a
terminal — `echo "$PW" | soli-proxy hash-password`), prints only the hash on stdout, and never
takes the password from the command line. `--cost` defaults to 12 and is bounded to 4–13: the
proxy refuses hashes outside that range (see "How Basic Auth is checked"). The standalone
`hash-password` binary shipped next to `soli-proxy` does the same, and the admin API offers it as
`POST /api/v1/hash-password` (`{"password": "..."}`).

The TUI is a separate process: traffic metrics and circuit-breaker state come from the running
proxy's admin API (`/api/v1/metrics`, `/api/v1/app-metrics`, `/api/v1/circuit-breaker`,
`/api/v1/status`), and show as unavailable — never as an empty list — when it cannot be reached.
What just happened (deploy stages, apps falling asleep and waking up) comes from the daemon's
event stream, `GET /api/v1/events/apps`. It authenticates with `[admin].api_key` when set;
otherwise, with admin Basic auth (`ADMIN_USER` + hash), the password typed at its login prompt
is reused as the Basic credential, and it polls every 5 s instead of every second because each
request costs the daemon a bcrypt check.

**Dashboard.** A strip of figures (requests, req/s with a sparkline, latency, error rate, open
circuits, the *daemon's* uptime, apps, routes), then the traffic panel: each active app is a
branch of the proxy, with packets travelling down it as densely as it receives requests, red
ones for 5xx, a still dotted line when it is asleep or stopped. An app stays on the panel for a
while after its last request; the others are summed up on one line ("46 without traffic · 3
asleep"). A deploy unrolls its stages under its app — `start › health › switch › drain` with
the drain counting down, then "live on green in 4.1 s" — and a wake-up reads "waking", then
"awake in 1.0 s". On the right (underneath on a narrow terminal), the HTTP status mix and a
journal of what just happened: deploys, traffic switches, sleeps, wake-ups, and new request
failures, each lit up for a moment when it arrives.

**Apps.** Sorted by traffic (smoothed over about ten seconds, so rows do not trade places every
second); `s` cycles through traffic, name, memory and errors, and the cursor stays on its app
when the order changes. Each row shows the app's state as a glyph (a spinner while it deploys or
wakes, `◐` asleep, `✕` failed), its last minute of traffic as a sparkline, req/s, memory, the
**Soli version** its process runs and its uptime. The detail panel draws the app's two slots:
packets flow to the one that serves, the other shows `starting…`, `health check…`, `draining 7s`
or `free`, with the deploy stepper above and CPU and memory bars on the right. `D` deploys, `R`
restarts, `L` opens the logs, `Enter` lists every action.

The version comes from the binary the process actually runs, asked once per binary file
(`<exe> --version`, only for an executable named `soli*`). A process keeps the binary it started
with: after `soli` is upgraded in place, an app that has not restarted still runs the old
version, shown in yellow with `↻ restart` until a restart picks up the new one.

**Errors.** 5xx per minute for each app (from the daemon's counters, so with no configuration)
and for each host of `proxy.conf` routes (from the log), then the individual failures, newest
first, with path, cause and duration. The individual failures need `[logging] log_endpoints =
true` in `config.toml` and the log in JSON (the default); a new one lights up and fades.

**Motion.** Numbers glide to their new value, packets move, new rows fade in. All of it is
computed from the clock, repaints at 15 frames a second only while something on screen moves,
and stops entirely on an idle screen (measured: 0.2 % of a core idle, 0.6 % animating). `m`
turns motion off and on; `NO_MOTION=1` starts with it off. Every frame is complete and readable
standing still.

**Narrow terminals.** Below 140 columns the screens are tabs on the top line instead of a
sidebar; at 80×24 every screen still fits, figures that do not fit are dropped whole rather than
cut, and the dashboard's journal moves under the traffic panel.

## Configuration

### Main Config (config.toml)

```toml
[server]
bind = "0.0.0.0:8080"   # HTTP listener; "[::]:8080" is dual-stack (IPv6 + IPv4)
https_port = 8443       # HTTPS listens on this port at the same address as `bind`
worker_threads = "auto"
# Paths with a dot segment (`/api/../admin`, `%2e%2e`, `..;`, `..\`) are answered 400 before
# any rule matches. So is an encoded slash (`%2F`) anywhere, unless the backend needs them as
# data (GitLab's `group%2Fproject`, S3-style keys); `..%2F` stays rejected either way.
allow_encoded_slash = false
shutdown_grace_period = 10  # seconds in-flight requests get on stop/restart (max 3600)
# Behind a CDN or balancer: whose forwarding headers to believe (see "Client IP behind a proxy").
trusted_proxies = []                   # e.g. ["cloudflare"], ["10.0.0.0/8", "2400:cb00::/32"]
real_ip_header = "X-Forwarded-For"     # or "CF-Connecting-IP", "X-Real-IP", "True-Client-IP"
proxy_protocol = "off"                 # "v1" | "v2" | "any", or { http = "off", https = "v2" }
request_id_header = "X-Request-Id"     # "" turns request IDs off

[tls]
mode = "auto"  # "auto" for dev, "letsencrypt" for production
force_https = true    # plaintext requests for known hosts get a 308 to https://
min_version = "1.2"   # or "1.3"; TLS session resumption (tickets + cache) is always on

[letsencrypt]
email = "admin@example.com"
staging = false

[logging]
level = "info"        # or a tracing filter: "info,soli_proxy::server=debug"
format = "json"       # or "text"
output = "stdout"     # "stderr", or "file:/var/log/soli-proxy/proxy.log"
max_size = "100MB"    # file output: rotate past this size ("0" = never)
max_files = 5         # file output: rotated files kept (proxy.log.1 … proxy.log.5)
log_endpoints = true  # log one line per request (method, path, host, status, latency)
access_log = "off"    # "stdout", "stderr" or a path: one line per completed request
access_log_format = "json"  # or "combined"

[metrics]
enabled = true
endpoint = "/metrics"

[health]
enabled = true
liveness_path = "/health/live"
readiness_path = "/health/ready"

[rate_limiting]
enabled = true            # per client IP, token bucket, shared by the proxy and admin API
requests_per_second = 1000
burst_size = 2000

[limits]
max_connections = 10000   # simultaneous client connections; further ones wait up to 10 s for a slot
max_request_size = "10MB" # request bodies above this get 413
keep_alive_timeout = 30   # seconds to receive a request's headers (closes idle keep-alives)
request_timeout = 60      # seconds for the upstream exchange before a 504 (default 60; @timeout per route)
websocket_idle_timeout_secs = 300           # close a forwarded WebSocket silent this long
websocket_max_lifetime_secs = 3600          # absolute cap per WebSocket
websocket_max_bytes_per_direction = 1073741824

[upstream]
retries = 1                     # retry a failed attempt on another target, when safe (0 = off)
retry_on = ["connect", "error"] # may add "500", "502", "503", "504"
# try_duration = "5s"           # no new attempt this long after the first

[health_checks]                 # active checks of proxy.conf targets (@health:/path per route)
# default_path = "/healthz"     # check every rule's targets (a rule opts out with @health:off)
interval = "10s"
timeout = "2s"
unhealthy_threshold = 3
healthy_threshold = 2

[scripting]
enabled = true
scripts_dir = "./scripts/lua"   # cors.lua, logging.lua, rate_limit.lua ship here
hook_timeout_ms = 10
exposed_env = ["BACKEND_TOKEN"] # the only variables Lua's `env` module can read
```

`[tls] force_https` (default `true`) answers plaintext requests for hosts the proxy serves with
a `308` to `https://` — except when the request comes from one of `[server] trusted_proxies` and
its `X-Forwarded-Proto` says `https`: a CDN that terminates TLS and reaches the proxy over plain
HTTP (Cloudflare "Flexible") would otherwise be redirected to where it already is, forever. From
any other peer the header is the client's own claim and changes nothing. The full key-by-key
reference is on the
[configuration page](https://proxy.solisoft.net/docs/configuration).

### Logging

`[logging]` controls the proxy's own log (apps log to `run/logs/<app>/<slot>.log`):

- `level` — `trace` … `error`, `off`, or a `tracing` filter such as
  `info,soli_proxy::server=debug`. When unset, `RUST_LOG` is used, then `info`. A bare word that
  is not a level is refused rather than read as a module name (which would silence everything).
- `format` — `json` (default; the TUI's error screen parses it) or `text`.
- `output` — `stdout` (default), `stderr`, or `file:/path`. Under `-d` the process has no
  terminal, so `stdout`/`stderr` mean `${SOLI_LOG_DIR:-.}/proxy.log`, as before.
- `max_size` / `max_files` — file output rotates by size: once the file would pass `max_size`
  (default `100MB`, `"0"` = never), `proxy.log` becomes `proxy.log.1`, `.1` becomes `.2`, and
  the oldest beyond `max_files` (default 5) is deleted. New log files are created `0640`.

Writes go through a background thread (`tracing_appender::non_blocking`), so a slow disk never
stalls a request; if it falls far behind, lines are dropped rather than blocking traffic.
`level`, `format`, `output` and the rotation keys are read at startup; `log_endpoints` follows
hot reloads. An invalid value is a startup error.

#### Access log

`access_log` (`off` by default; `stdout`, `stderr`, or a file path — `file:/path` works too)
writes one line per request, separately from the proxy's own log. A file rotates by the same
`max_size`/`max_files`; under `-d`, `stdout`/`stderr` mean `${SOLI_LOG_DIR:-.}/access.log`.
The line is written once the response body has been sent — or abandoned — so it has the bytes
actually sent and the whole duration:

```json
{"ts":"2026-10-01T12:34:56.789Z","client_ip":"203.0.113.9","method":"GET","host":"example.com",
 "path":"/a?b=1","protocol":"HTTP/2.0","status":200,"bytes_in":0,"bytes_out":5120,
 "duration_ms":12.345,"upstream":"http://127.0.0.1:3000/a?b=1","app":"blog",
 "request_id":"5f0c…","user_agent":"curl/8.9","referer":null,"tls":true,"complete":true}
```

(one line in the file). `client_ip` is the real client (see [Client IP behind a
proxy](#client-ip-behind-a-proxy-or-cdn)); `upstream` and `app` are set for proxied requests
only; `complete` is `false` when the client went away or the backend failed mid-body;
`bytes_in` is the request's `Content-Length` (0 for a chunked upload); for a WebSocket the line
is the `101` — the tunnel's lifetime and traffic are not in it.
`access_log_format = "combined"` writes the Apache/nginx combined format, followed by the
proxy's own fields:

```
203.0.113.9 - - [01/Oct/2026:12:34:56 +0000] "GET /a?b=1 HTTP/2.0" 200 5120 "-" "curl/8.9" host="example.com" rt=0.012345 rid=5f0c… upstream="http://127.0.0.1:3000/a?b=1" app="blog" tls=y in=0
```

Lines are formatted into a per-thread buffer reused from request to request and queued to the
same kind of background writer; like the proxy's log, the access log drops lines rather than
slow traffic down if the disk cannot keep up. Both keys are read at startup.

### Admin credentials

The admin API (`[admin]`, loopback `127.0.0.1:9090` by default) accepts either an API key
(`[admin].api_key` in `config.toml`, sent as `X-Api-Key`) or HTTP Basic credentials taken from
the environment:

| Variable | Meaning |
|---|---|
| `ADMIN_USER` | Basic-auth user name. |
| `ADMIN_PASSWORD_HASH` | Its bcrypt hash (`soli-proxy hash-password`). |
| `ADMIN_PASSWORD` | Legacy: a bcrypt hash, or plaintext that is hashed at startup with a warning. |

The same three keys may instead be put in a `.env` file **in the directory that holds
`proxy.conf` and `config.toml`**. That one file is read, and only those three keys are taken from
it — anything else in it is ignored with a warning, and nothing is exported into the proxy's
environment, so a `.env` can never set `HTTP_PROXY` for the apps the proxy spawns. A variable
set in the real environment wins over the file. A `.env` that does not parse is a startup error
(and a no-op on reload), like a malformed `config.toml`. Parent directories are never searched:
earlier versions did, so a stray `.env` in `/srv` or `$HOME` could supply admin credentials.

### TLS Certificates

The proxy stores certificates flat in `tls.cache_dir` (default `./certs`).

| Filename pattern | What it is | Example |
| --- | --- | --- |
| `<domain>.cert.pem` + `<domain>.key.pem` | Per-domain cert. Matches SNI exactly. The cert MUST list `<domain>` in its SANs. | `crm.example.com.cert.pem` |
| `_wildcard.<parent>.cert.pem` + `_wildcard.<parent>.key.pem` | Wildcard cert covering `*.<parent>`. Matches one label deep per RFC 6125. The cert MUST list `*.<parent>` in its SANs. | `_wildcard.example.com.cert.pem` covers `crm.example.com`, `api.example.com`, etc. |
| `self-signed.cert.pem` + `self-signed.key.pem` | Reserved fallback name. Used when no per-domain or wildcard match. Don't use for a real domain. | (auto-generated) |

Resolution order on a TLS handshake: exact-match `certs/<sni>.cert.pem` → wildcard `certs/_wildcard.<parent>.cert.pem` (one label deep) → self-signed fallback. Cert files are scanned at startup and whenever `POST /api/v1/certs/reload` asks the admin API to rescan them; `SIGUSR1` and `POST /api/v1/reload` only refresh routing. A cert file you *delete* stays registered until the process restarts.

For local dev with [mkcert](https://github.com/FiloSottile/mkcert) — install the local CA on your machine (`mkcert -install`) and drop wildcard certs in:

```bash
mkcert "*.example.test"
mv _wildcard.example.test.pem      ./certs/_wildcard.example.test.cert.pem
mv _wildcard.example.test-key.pem  ./certs/_wildcard.example.test.key.pem
curl -fsS -X POST -H 'X-Requested-With: cli' http://127.0.0.1:9090/api/v1/certs/reload
```

Every `*.example.test` alias is then served with a Mac/Linux-trusted cert (no browser warning).

When the CA, the proxy and the browser are all on this machine, `scripts/local-test-certs.sh` does the whole thing — CA, both trust stores, one wildcard per `.test` parent in `sites/`, reload, verification.

See [`docs/tls-mkcert.md`](docs/tls-mkcert.md) for the full mkcert workflow, the CA-rotation pitfall (identical issuer string, different key → `bad signature`), and the `scripts/diag-mkcert-mac.sh` / `scripts/regen-mkcert-and-deploy.sh` helpers.

For a single Arch/Omarchy workstation — wildcard `.test` DNS, binding 80/443 as a normal user, and getting Chrome/Brave to trust the dev CA — see [`docs/omarchy-dev-setup.md`](docs/omarchy-dev-setup.md).

### Proxy Rules (proxy.conf)

```proxy
# Comments are supported (whole lines only)
default -> http://localhost:3000

/api/* -> http://localhost:8080
/ws -> ws://localhost:9000

# Load balancing (round-robin by default)
/api/* -> http://10.0.0.10:8080, http://10.0.0.11:8080, http://10.0.0.12:8080

# Weighted routing: 70% / 30%, interleaved
/api/heavy -> weight:70 http://heavy:8080, weight:30 http://light:8080

# Regex routing with capture substitution
~^/users/(\d+)$ -> http://user-service:8080/users/$1

# External https backend (Host/Origin are rewritten to the target's own
# authority; the client's host is forwarded via X-Forwarded-Host)
mirror.example.com -> https://origin.example.net

# Permanent redirect to a new canonical domain (301, path and query preserved)
old.example.com -> redirect://new.example.com

# gRPC over cleartext HTTP/2, probed every 5 s; an app on a Unix socket
grpc.example.com -> h2c://10.0.0.7:50051, h2c://10.0.0.8:50051 @health:/healthz @health_interval:5s
app.example.com -> unix:/run/app/puma.sock @timeout:2m

# An internal HTTPS service: private CA, SNI for an IP target, mTLS
billing.example.com -> https://10.0.0.9:8443 @tls_ca:/etc/soli-proxy/internal-ca.pem \
                       @tls_sni:billing.internal @tls_client_cert:/etc/soli-proxy/proxy.pem,/etc/soli-proxy/proxy.key

# Request headers for the rule right above
api.example.com -> http://localhost:8080
headers {
    X-Real-IP: $client_ip
    X-Forwarded-Proto: $scheme
    -X-Debug-Token
}

# HTTP Basic Auth on a route (hash from `soli-proxy hash-password`; bcrypt cost 4..=13)
secure.example.com -> http://localhost:9000 @auth:admin:$2b$12$...

# ...with carve-outs for callers that cannot send credentials.
# Exact path, or a prefix ending in *. Only meaningful next to @auth.
app.example.com -> http://localhost:8080 @auth:admin:$2b$12$... \
                   @noauth:/webhooks/stripe,/hooks/*

# Forward authentication: an SSO service decides, before every request
# (see "Forward authentication" below). @noauth works here too.
dashboard.example.com -> http://localhost:3000 \
                   @forward_auth:http://127.0.0.1:4180/ \
                   @forward_auth_headers:X-Auth-Request-User,X-Auth-Request-Email
```

#### How Basic Auth is checked

- **bcrypt never runs on the request workers.** Each check goes to a blocking pool bounded to
  half the cores (at least two), so a flood of wrong passwords costs at most that share of the
  CPU and every other site keeps answering. A check waits up to 10 s for a slot, so a burst of
  real logins on a small machine is served; but the queue holds at most 16 checks per slot, and
  past that a request gets **`503` with `Retry-After: 1`** at once rather than queueing without
  bound (not 401: the client did nothing wrong, and a browser would prompt for a password it
  already has).
- **Successes are remembered for five minutes, failures never.** A page and its sub-resources
  pay bcrypt once; a wrong password pays it every time. The cache key covers the configured
  hashes, so rotating a password takes effect immediately, and a remembered credential gets in
  even while the pool is saturated.
- **Only bcrypt hashes at cost 4 to 13 are accepted** (`$2a$`/`$2b$`/`$2x$`/`$2y$`, 60
  characters). The cost is a work factor whoever writes the hash chooses for *your* CPU — each
  step doubles it, and `$2b$31$` is days per request — so anything else is refused where it enters:
  an app with such a hash in `[auth.users]` fails to load, the admin API and a cluster push answer
  400, and a `@auth` entry in `proxy.conf` is a load error naming its line (fatal at startup;
  on reload the previous configuration, and its protection, stay in force). Hashes above cost 13 made before this rule must be regenerated.

Rules, `@auth` and `@noauth` match a canonical form of the path: percent-encoded
unreserved characters (`A-Z a-z 0-9 - . _ ~`) are decoded and repeated `/` collapse,
so `//admin/x` and `/%61dmin/x` meet an `/admin/*` rule like `/admin/x` does. The
backend still receives the path as sent.

### Forward authentication

One SSO service — [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/),
[Authelia](https://www.authelia.com/), [Authentik](https://goauthentik.io/), a Soli app —
can gate any route (`@forward_auth:`) or app (`[auth] forward`, see
[`app.infos`](#app-configuration-appinfos)). It is the model of Traefik's ForwardAuth,
nginx's `auth_request` and Caddy's `forward_auth`: before proxying a request, the proxy asks
the auth service, and the auth service's answer decides.

```
# proxy.conf
dashboard.example.com -> http://localhost:3000 \
    @forward_auth:http://127.0.0.1:4180/ \
    @forward_auth_headers:X-Auth-Request-User,X-Auth-Request-Email \
    @noauth:/up,/assets/*
```

**What the auth service is sent**: a `GET` to the URL exactly as configured (query string
included), with no body and these headers only —

| Header | Value |
|---|---|
| `Cookie`, `Authorization` | The client's, as sent: the session the service checks. (`Authorization` is withheld when the same route or app also has Basic Auth — it then carries the Basic password, which is the proxy's business.) |
| `Accept`, `User-Agent`, `X-Requested-With` | The client's: what Authelia and Authentik read to choose between a 401 and a login redirect. |
| `X-Forwarded-Method` | The request's method. |
| `X-Forwarded-Uri` | The request's path and query exactly as the client sent them — not the canonical form routes are matched on, nor the path after a prefix rule strips its prefix: what the auth service needs to send the browser back to after a login. Do not authorize on it. |
| `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP` | The proxy's own (see [What reaches the backend](#what-reaches-the-backend)) — never the client's. |
| `Host` | The auth service's own authority. |

**What its answer does**:

| Answer | Result |
|---|---|
| **2xx** | The request proceeds. Each header named in `@forward_auth_headers:` is copied from the answer onto the upstream request (every value). Nothing else from the answer is used. |
| **3xx, 4xx, 5xx** | Sent to the client as the auth service wrote it — status, headers (`Location`, `Set-Cookie`, `WWW-Authenticate`, …, minus hop-by-hop ones) and body up to 64 KiB (a larger body is dropped, the status and headers still go). The upstream is never contacted. |
| **No answer** — refused, reset, or not within `[forward_auth] timeout_secs` (default 5 s, body included) | **503**. Fail closed: a request is never let through because the auth service was away. |

- ⚠️ **The headers named in `@forward_auth_headers:` are removed from the client's request
  first, on every request** — before the auth service is asked, whatever it answers, and on
  `@noauth` paths too. The upstream trusts `X-Auth-Request-User` because only the auth service
  can set it; a client sending its own copy must not have it arrive next to the real one, or in
  its place on a path the auth service never saw. Hop-by-hop and framing headers, `Host` and the
  forwarding headers cannot be named (a load error), and at most 32 can.
- **Nothing is cached.** Every request asks; a session revoked at the auth service stops working
  on the next request. The subrequest goes through the proxy's shared upstream connection pool,
  so the connection to the auth service stays open between requests.
- **With `@auth` on the same rule**, Basic Auth runs first and both must pass: a request without
  the password gets the Basic 401 and the auth service is not asked. `@noauth:` paths skip both.
- **WebSocket upgrades** are checked the same way, before anything is tunnelled, and the copied
  headers reach the WebSocket backend.
- **The URL** must be `http://` or `https://` with a host, and carry neither credentials nor a
  `#fragment`. An `https://` auth service is verified against the public web PKI, like an
  `https://` backend — on a private network, use `http://` on loopback or a private address, or
  a publicly trusted certificate.
- A `Set-Cookie` on a **2xx** answer (a refreshed session) is not passed to the client: only
  denials are relayed.

```toml
# config.toml
[forward_auth]
timeout_secs = 5          # connect + answer; 0 or unset = 5. Applied on the next request after a reload.
# allowed_urls = [...]    # multi-tenant mode only, see below
```

#### Example: oauth2-proxy

oauth2-proxy in its "static upstream" mode answers `202` with the user's identity for a valid
session, and redirects anyone else to the identity provider. One instance serves every protected
domain under a shared cookie domain; its own callback lives on `auth.example.com`:

```bash
oauth2-proxy --http-address=127.0.0.1:4180 \
  --reverse-proxy=true --upstream=static://202 --set-xauthrequest=true \
  --skip-provider-button=true \
  --redirect-url=https://auth.example.com/oauth2/callback \
  --cookie-domain=.example.com --whitelist-domain=.example.com \
  --provider=oidc --oidc-issuer-url=https://idp.example.com \
  --client-id=... --client-secret=... --cookie-secret=... --email-domain=example.com
```

```
# proxy.conf
auth.example.com -> http://127.0.0.1:4180

grafana.example.com -> http://127.0.0.1:3000 \
    @forward_auth:http://127.0.0.1:4180/ \
    @forward_auth_headers:X-Auth-Request-User,X-Auth-Request-Email

wiki.example.com -> http://127.0.0.1:8081 \
    @forward_auth:http://127.0.0.1:4180/ \
    @forward_auth_headers:X-Auth-Request-User
```

`--reverse-proxy` makes oauth2-proxy read `X-Forwarded-Host`/`-Uri`/`-Proto`, so after the
login the browser comes back to the page it asked for. Configure the backends to trust
`X-Auth-Request-User` (Grafana: `[auth.proxy] header_name = X-Auth-Request-User`) — and only
from the proxy, which is the one place the header can come from.

Authelia (4.38+) works the same way with its forward-auth endpoint:
`@forward_auth:http://127.0.0.1:9091/api/authz/forward-auth
@forward_auth_headers:Remote-User,Remote-Groups,Remote-Email,Remote-Name`.

#### Multi-tenant mode: `allowed_urls`

In [multi-tenant mode](#multi-tenant-mode-untrusted-apps) an app's `[auth] forward` is written
by the tenant, and the proxy fetches it — with the visitor's cookies — and relays a denial's
body back. Left open, that is a server-side request forgery: `forward =
"http://169.254.169.254/latest/meta-data/"`, or an internal admin port. So a tenant may only
name an auth service the operator listed:

```toml
[forward_auth]
allowed_urls = [
  "http://127.0.0.1:4180/",                   # this path and everything below it
  "http://127.0.0.1:9091/api/authz/forward-auth",  # exactly this path
]
```

An entry matches a URL with the same scheme, host and port and, when the entry's path ends in
`/`, any path below it; otherwise exactly that path. The query string is not compared. Paths are
compared after normalisation, so `/api/../admin` is `/admin`. An app whose `forward` no entry
covers fails to load (logged and skipped, like any other manifest error); with the list empty —
the default — no tenant can use forward-auth. The list is read at each app discovery. Outside
multi-tenant mode `app.infos` is the operator's, and is not checked against it. Routes in
`proxy.conf`, the admin API and cluster pushes are operator input and are not checked either.

### What reaches the backend

- **Forwarding headers come from the proxy, never the client.** Any `Forwarded`,
  `X-Forwarded-*` or `X-Real-IP` the client sent is dropped, then `X-Forwarded-For` and
  `X-Real-IP` (the connecting address), `X-Forwarded-Proto` and `X-Forwarded-Host` (the
  Host the client asked for) are set — on rule routes, app domains and WebSocket
  upgrades alike, before any Lua script sees the request, and on the admin API's
  passthrough to the `_admin` app. The one exception is a peer listed in
  `trusted_proxies`: see below.
- **Every request carries a request ID** in `X-Request-Id` (or `request_id_header`), also
  returned to the client on the response. A client's own `X-Request-Id` is replaced; one from
  a trusted proxy is kept when it is 1–128 visible ASCII characters. W3C `traceparent` /
  `tracestate` pass through untouched.
- **Hop-by-hop headers are removed at the door**, including every header the client
  names in `Connection`, so a client cannot use `Connection: x-user` to delete a header
  a script set.
- **Malformed requests are refused up front**: `CONNECT` (405), authority-form and
  asterisk-form targets (400; `OPTIONS *` is answered directly), more than one `Host`
  header, on HTTP/2 a `Host` that differs from `:authority`, or userinfo (`user@`) in the
  authority or in `Host` (400).
- **WebSocket upgrades are routed like any other request**: the same target choice (the
  rule's balancing, past targets whose breaker is open or that health checks marked down —
  a failed connect or handshake counts against the breaker), the same gates (the rule's
  `@auth`/`@forward_auth`, or only the app's when an app takes the domain over), the route's
  Lua hooks (`on_request`, `on_route`), its `headers { }` block and its `@connect_timeout`.
  An open tunnel keeps counting against the connection limits.

### Client IP behind a proxy or CDN

By default the proxy is the edge: the TCP peer is the client. Put it behind Cloudflare or a
load balancer and every client becomes the balancer — one rate-limit bucket for everyone, the
balancer's address in logs and in `X-Real-IP`. List the peers whose word you take:

```toml
[server]
trusted_proxies = ["cloudflare"]       # presets: "cloudflare", "private", "loopback"
# trusted_proxies = ["10.0.0.0/8", "2400:cb00::/32", "192.0.2.10"]
real_ip_header = "X-Forwarded-For"     # default; or "CF-Connecting-IP", "X-Real-IP", …
```

For a request from a trusted peer, the client is found by walking `X-Forwarded-For` from the
right, skipping addresses that are themselves trusted: the first one that is not is the client
(when every hop is trusted, the leftmost). Entries to its left were written by the client, and
are not believed. With `real_ip_header` naming a single-address header such as
`CF-Connecting-IP`, that header is read instead. A forwarded address that cannot be a remote
client — loopback, unspecified, link-local, multicast, broadcast — is a forgery, and the peer is
taken as the client instead. That client is then used everywhere the proxy used the peer: the
rate limiter, `[maintenance] allow_ips`, `X-Real-IP`, `$client_ip` in `headers { }`, Lua's
`req.client_ip`, logs, and the admin API's budgets. What is local-only (`/metrics`) is judged on
the connection itself: the TCP peer (or the PROXY header's source) must be loopback, and so must
the client — a front proxy on this host relaying a remote client does not open it. Its forwarding
headers are kept rather than replaced: `X-Forwarded-For` is the incoming chain with the peer
appended, `X-Forwarded-Proto` stays as the trusted proxy set it (`http`/`https` only; of several
values the last — the nearest proxy's — is the one kept, and the one `force_https` reads). A peer
that is not trusted is handled exactly as before, and a `real_ip_header` such as
`CF-Connecting-IP` it sends is removed.

The `cloudflare` preset is Cloudflare's published ranges, compiled in
(`CLOUDFLARE_IPV4`/`CLOUDFLARE_IPV6` in `src/edge.rs`; to refresh, compare with
<https://www.cloudflare.com/ips-v4> and `/ips-v6`). The preset is only as good as that list: if
your proxy is reachable without going through Cloudflare, firewall it to those ranges, or
anyone can send a forged chain from an address you trust.

**Multi-tenant mode: do not trust your tenants' networks.** A tenant's native app connects from
loopback, and its container from a Docker bridge (by default in `172.16.0.0/12` or
`192.168.0.0/16`). With `trusted_proxies` covering either — the `"private"` and `"loopback"`
presets do — a tenant is a "trusted proxy": the `X-Forwarded-For`, request ID and
`X-Forwarded-Proto` it sends are believed, so it can pose as any client to the rate limiter,
`[maintenance] allow_ips` and the backends. List your balancer's own addresses instead;
`soli-proxy check` warns about every such entry when `multi_tenant` is on.

**PROXY protocol.** A TCP balancer (AWS NLB, HAProxy in TCP mode) can prepend the client
address to the connection instead:

```toml
[server]
trusted_proxies = ["10.0.0.0/8"]
proxy_protocol = "v2"                  # "v1", "v2", "any"; or { http = "off", https = "v2" }
```

On a listener with PROXY protocol on, every connection must start with a v1 or v2 header
(within 5 s and 1 KiB) and come from a `trusted_proxies` address; anything else is closed. The
header is read before TLS and HTTP, and the address it carries is the connection's peer from
then on — including for `max_connections_per_ip`. A header that names no client (v2 `LOCAL`,
v1 `UNKNOWN`, an unspecified or Unix address — the balancer's own health check) keeps the
balancer as the peer, counted against `max_connections_per_ip` like a client, and the forwarding
headers, request ID and `X-Forwarded-Proto` on that connection are not believed: the balancer
did not write them. Enabling `proxy_protocol` with no `trusted_proxies` is a
configuration error.

**The per-IP connection cap** is applied when a connection is accepted, before any header is
read, so without PROXY protocol it is keyed on the TCP peer. A trusted proxy is exempt from it —
it carries everyone's connections — and stays bounded by `max_connections`; the clients behind
it are still rate limited individually, per request.

These keys are read for every connection and request, so a reload applies them.

### Connection limits

```toml
[limits]
max_connections = 10000        # whole process
max_connections_per_ip = 256   # per client address (IPv6: per /64); 0 = off
keep_alive_timeout = 30        # header read / idle keep-alive (HTTP/1), idle (HTTP/2)
```

`max_connections` is one pool for both listeners. A connection takes its slot once accepted;
when none is free the accept loop waits (up to 10 s, then closes that connection) and stops
accepting meanwhile, so further connections queue in the kernel's listen backlog. A connection
over `max_connections_per_ip` is closed at once. The per-IP cap is keyed on the TCP peer (or the
PROXY protocol address), and a `trusted_proxies` peer is exempt from it — see [Client IP behind
a proxy](#client-ip-behind-a-proxy-or-cdn).

`[rate_limiting]` also keys IPv6 clients by /64: a subscriber can pick a new source
address inside its /64 for every request, and per-address buckets were no limit at all.

#### Sources (left of `->`)

| Source | Matches |
|---|---|
| `default` or `*` | Anything no other rule matched. Like an exact rule, the target is used as-is: the request path is **not** appended (only the query string is). |
| `example.com` | Every request whose `Host` is that domain; the full path is appended to the target. |
| `example.com/api/*`, `example.com/api` | That domain, under that path prefix; the prefix is stripped before forwarding. |
| `/api/*` | That path prefix on any host; the prefix is stripped. |
| `/health` | Exactly that path, on any host; the target is used as-is. |
| `~^/users/(\d+)$` | A regular expression on the path ([Rust `regex` syntax](https://docs.rs/regex)). |

Domain rules are tried first, then exact/prefix/regex rules in file order, then `default`.

#### Targets (right of `->`)

Comma-separated URLs (`http://`, `https://`, `h2c://`, `unix:`, `ws://`, `redirect://`), each
optionally preceded by `weight:N`. `h2c://host:port` speaks HTTP/2 with prior knowledge;
`unix:/absolute/path.sock` connects to a Unix socket (the path names the socket — requests carry the
path the rule resolves and the client's `Host`; see [Upstreams](#upstreams)). A line ending in `\` continues on the next one. After a stripped prefix, the rest of
the path is always joined to the target as a path (`/api/x` on `/api/* -> http://h/v2` goes to
`http://h/v2/x`), and a target's own query string gets the client's appended with `&`.

**Regex captures.** A regex rule's target may use `$1`, `${1}` or `${name}` (for
`(?P<name>...)` groups) in its path and query; the client's query string is appended. A group
that did not take part in the match expands to nothing, and naming a group the pattern does not
have is a load error. Captures are substituted into the path and query only — the scheme and
host are taken verbatim from the target.

**Directives**, anywhere after the arrow:

| Directive | Effect |
|---|---|
| `@lb:round-robin` / `@lb:weighted` / `@lb:failover` | Load-balancing strategy for multi-target rules. Default `round-robin`, or `weighted` when any target has a `weight:`. `failover` sends everything to the first available target. |
| `weight:N` (before a target) | Share of traffic under `@lb:weighted`, 0–255, default 100. Weights are reduced by their common divisor and spread evenly (70:30 sends A B A A B A A B A A, not 70 then 30). **`weight:0` drains** a target: it gets no traffic while any weighted target is available, and serves only as a last resort when every other one's circuit breaker is open. |
| `@script:a.lua,b.lua` | Lua scripts for this route (see `[scripting]`). |
| `@auth:user:bcrypt-hash` | HTTP Basic Auth; repeat for several users. |
| `@noauth:/path,/prefix/*` | Paths on a protected rule served without credentials (Basic Auth and forward-auth alike). |
| `@forward_auth:URL` | Ask this auth service before every request; see [Forward authentication](#forward-authentication). |
| `@forward_auth_headers:A,B` | Response headers of the auth service copied onto the upstream request (and always stripped from the client's). Needs `@forward_auth:`. |
| `@compress:on` / `@compress:off` | Compress this route's responses, or never, whatever `[compression] enabled` says. See [Compression](#compression). |
| `@retries:N` | Retries on another target, 0–10 (default `[upstream] retries`, 1). |
| `@timeout:120s` | Time to the response headers, instead of `[limits] request_timeout`. |
| `@connect_timeout:2s` | Connect timeout (default 5 s). |
| `@h2` | Speak HTTP/2 to every target: ALPN `h2` over TLS, prior knowledge otherwise. |
| `@tls_ca:/path/ca.pem` | Trust this CA bundle instead of the public roots (`https://` targets). |
| `@tls_sni:name` | SNI sent, and name the certificate is verified for. |
| `@tls_client_cert:/cert.pem,/key.pem` | Client certificate for mTLS. |
| `@tls_insecure` | Do not verify the upstream certificate (logged as a warning on every load). |
| `@health:/path` / `@health:off` | Probe each target at this path / opt out of `[health_checks] default_path`. |
| `@health_interval:10s` | Time between probes. |

Durations take a unit: `500ms`, `2s`, `5m`. Paths cannot contain spaces, control characters or
a trailing backslash (and the certificate and key of `@tls_client_cert` no comma): the proxy
writes them back to `proxy.conf` as they are when a route is saved through the admin API or the
TUI, so such a value is refused there too, with a 400.

Every target is also tracked by the circuit breaker (`[circuit_breaker]`): a target whose
breaker is open — or that an active health check marked down — is skipped by every strategy, and
a rule whose targets are all out answers 503.

#### `headers { }` blocks

A `headers {` line opens a block that applies to the **rule right above it**, closed by `}` on a
line of its own. Each line is either `Name: value`, which sets the header on the request sent
upstream (replacing whatever the client sent), or `-Name`, which removes it. The block is applied
after the proxy has set `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, so it can
override or remove those too. Values may use:

| Variable | Value |
|---|---|
| `$client_ip` | The client's address: the TCP peer, or the client a trusted proxy names (never a header from an untrusted client). |
| `$scheme` | `http` or `https`, as the client connected. |
| `$host` | The host the request was routed on, without port. |

`$$` is a literal `$`. Hop-by-hop and framing headers (`Connection`, `Keep-Alive`,
`Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Content-Length`, `Proxy-Connection`) cannot
be set. Blocks apply to proxied HTTP requests and to WebSocket upgrades (the upgrade is an
ordinary request until the backend's `101`; a block may not touch its `Upgrade`, `Connection` or
`Sec-WebSocket-*` lines). App-managed domains are not affected.

#### Errors

A line the parser does not understand is an error naming its line number — an unknown
directive, an invalid `weight:`, a malformed `@auth` entry, an unknown `@lb` strategy, an invalid
`@forward_auth:` URL or header name, a script
name that is not a plain `*.lua` file, an unterminated `headers` block. At startup that is fatal;
on a hot reload the previous configuration stays in force and the error is logged. (Earlier
versions skipped such lines, which could silently drop a route or the `@auth` protecting it.)

### Upstreams

**Retries.** When an attempt fails before any response byte, the request goes to the rule's next
available target, in rule order, up to `retries` times (`[upstream] retries`, default 1;
`@retries:N` per rule):

- a **connect failure** (refused, unreachable, connect timeout, TLS handshake) is always retried,
  request body included — nothing reached the backend, and the body was never read;
- **any other failure** (a reset, a connection closed mid-request), and a status listed in
  `retry_on`, only for an idempotent method (`GET HEAD OPTIONS PUT DELETE TRACE`) without a body:
  the backend may have acted on anything else.

Every failed attempt still counts in the circuit breaker. A managed app retries on its other slot
while a blue/green deploy has one running (and the failed slot is failed over at once, not on the
next request); a cluster-pushed domain on another instance. A request a Lua `on_route` hook sent
somewhere is not retried elsewhere. `try_duration` stops retrying once that long has passed. A
rule with several targets keeps a copy of the request head for a possible retry (one header-map
clone per request); `retries = 0` avoids it.

**Active health checks.** `@health:/path` probes each of the rule's targets (`GET`, `User-Agent:
soli-proxy-health-check`, through the rule's own TLS/HTTP-2/socket settings) every
`@health_interval` or `[health_checks] interval`; `[health_checks] default_path` does it for every
rule but those saying `@health:off`. Any answer below 500 within `timeout` is a success. After
`unhealthy_threshold` failures in a row the target is skipped like an open breaker, until
`healthy_threshold` successes in a row. A target several rules name is probed once. The probes
follow reloads: a check that disappears stops, and its target's verdict is forgotten.
`GET /api/v1/circuit-breaker` adds `"health": "up"` / `"down"` for checked targets.

**HTTP/2 and gRPC.** `h2c://` targets and rules with `@h2` speak HTTP/2 to the upstream (`@h2`
offers only `h2` in ALPN, so a TLS upstream that cannot speak it fails the handshake rather than
receive HTTP/2 frames). `TE: trailers` reaches the upstream — every other `TE` value is dropped,
and HTTP/1.1 upstreams get none — and response trailers (`grpc-status`, `grpc-message`) reach the
client: over HTTP/2 always, over HTTP/1.1 when the upstream announces them in `Trailer`. HTTP/2
forbids a `Host` that contradicts `:authority`, so on an HTTP/2 upstream the client's host travels
in `X-Forwarded-Host` only (a Unix-socket upstream gets it as `:authority`). gRPC clients reach the
proxy over TLS (ALPN `h2`); the plain listener speaks HTTP/1.1. WebSocket upgrades are always
tunnelled over HTTP/1.1, whatever `@h2` says.

**Upstream TLS.** `@tls_ca` replaces the public roots with the given PEM bundle (an internal PKI);
`@tls_sni` sets the SNI and the name verified, for targets addressed by IP; `@tls_client_cert`
presents a client certificate. `@tls_insecure` turns verification off — anyone on the path to the
upstream can then read and change the traffic, so the proxy warns each time it loads such a rule;
prefer `@tls_ca`. Files are read when the configuration loads, so a missing or invalid one is a load
error (fatal at startup, the previous configuration stays on reload; a route saved through the
admin API is refused and `proxy.conf` is left untouched), and a replaced file is picked up on the
next reload. Each must be a regular file of at most 1 MiB, read once. The error names the file but
not the reason — the admin API relays it, and "missing", "unreadable" or "not a certificate" would
let an API client probe the proxy's filesystem — the reason is in the proxy's log (on stderr for
`soli-proxy check`). Rules with the same options share one client and its connection pool. A
WebSocket upgrade to the rule's `https://` target uses the same TLS settings. A Lua `on_route`
override keeps the rule's TLS settings (and `@h2`, `@connect_timeout`) only when it goes to one
of the rule's own origins (scheme, host, port); anywhere else it gets the defaults — a script
sending a request elsewhere does not present the rule's client certificate there, nor skip
verification because the rule's own backend needed `@tls_insecure`.

**Unix sockets.** `unix:/run/app.sock` must be an absolute path. The request URI is built on a
placeholder origin (`http://unix.invalid/`), the client's `Host` is forwarded untouched, and
WebSocket upgrades are tunnelled to the socket too. A Lua `on_route` override can never point a
request at a socket.

**Timeouts.** `@timeout` replaces `[limits] request_timeout` (time to the response headers, retries
included) for its rule, longer or shorter; `@connect_timeout` replaces the 5 s connect timeout.

## Responses: compression, error pages, maintenance

### Compression

```toml
[compression]
enabled = true                       # default false
algorithms = ["zstd", "br", "gzip"]  # offered, in this order of preference on a tie
gzip_level = 5                       # 1–9
brotli_level = 4                     # 0–11
zstd_level = 3                       # 1–19
min_length = 1024                    # smaller responses are sent as they are
types = ["text/*", "application/json", "application/javascript", "image/svg+xml", "*+json", "*+xml"]
```

The proxy compresses a backend's response when the client asks for it in `Accept-Encoding`
(q-values honoured: `q=0` refuses a coding, `identity;q=…` or `*` ranks identity against
them; a tie goes to the order of `algorithms`) and all of these hold: the backend did not
already set `Content-Encoding`; the status is not 1xx, 204, 206 or 304; the `Content-Type` is in
`types` (`type/*` for a whole type, `*+json` for a suffix; the default list covers text, JSON,
JavaScript, XML, SVG, wasm, icons and TrueType/OpenType fonts) and is not `text/event-stream`;
the `Content-Length`, when there is one, is at least `min_length`; and the response does not say
`Cache-Control: no-transform`. A compressed response gets `Content-Encoding`, loses
`Content-Length` and `Accept-Ranges`, and a strong `ETag` becomes weak (`W/"…"`). Every response
that *could* be compressed carries `Vary: Accept-Encoding`, even when this client did not ask —
caches must keep the variants apart. A `HEAD` is never compressed (there is no body) but still
gets `Vary`. WebSocket tunnels are never touched.

Per route, `@compress:on` / `@compress:off` override `enabled`; per app, `compress = false` in
`app.infos` opts out (`compress = true` opts in, except in multi-tenant mode, where spending the
proxy's CPU is the operator's call). On a path-prefix mount whose HTML is rewritten, the rewrite
happens first and the rewritten page is what gets compressed.

**Why it is off by default.** Passthrough moves gigabytes per second per core; compression does
not — on real HTML, roughly 150–190 MB/s per core for gzip at 5, 100–140 MB/s for brotli at 4,
500 MB/s for zstd at 3 (see the table below). An
upgrade that switched it on would multiply the proxy's CPU per text byte by one to two orders of
magnitude without anyone deciding to. It also changes what caches see (`Vary`, weak ETags), and
compressing a page that reflects request input next to a secret is what BREACH exploits — an
app that does not compress may not by accident. Caddy (`encode`), nginx (`gzip on`) and Traefik
(the `compress` middleware) are opt-in too. Encoding runs on the request's worker, at most
64 KiB of input per poll before it yields, so a large body never holds a worker for more than a
fraction of a millisecond; and the encoder is flushed when the backend pauses for 10 ms, so a
streamed or progressively rendered response reaches the client as it is produced, at most 10 ms
late. (It used to flush at every pause, including the gap between two socket reads, which cut a
large page into small deflate blocks: 2–6 % larger, and ~10 % slower to compress.) Each response
being compressed holds an encoder: about 256 KiB for gzip, 1–2 MiB for brotli (1 MiB window) or
zstd.

**Choosing levels.** Time to compress and size reached, on one core of a recent desktop CPU, for
two real pages — the single-page HTML Standard (15.6 MB) and RFC 9110 (1.2 MB):

| Level | HTML Standard | RFC 9110 |
|---|---|---|
| gzip 1 | 31 ms, 4.40× | 2.8 ms, 3.60× |
| gzip 5 (default) | 79 ms, 7.07× | 7.4 ms, 5.54× |
| gzip 6 | 115 ms, 7.15× | 11.0 ms, 5.58× |
| br 1 | 40 ms, 5.46× | 3.9 ms, 4.52× |
| br 4 (default) | 109 ms, 6.54× | 10.7 ms, 5.90× |
| br 5 | 190 ms, 4.91× | 17.2 ms, 6.44× |
| zstd 1 | 23 ms, 6.53× | 2.0 ms, 5.21× |
| zstd 3 (default) | 28 ms, 6.97× | 2.4 ms, 5.69× |
| zstd 6 | 93 ms, 8.49× | 7.4 ms, 6.36× |

zstd at 3 compresses about as well as gzip at 5 in a third of the time, and as well as brotli
at 4 in a quarter of it — hence `zstd` first in the default `algorithms`: Chrome, Edge and
Firefox accept it, and Safari, which does not, gets brotli. Past gzip 5 and brotli 4 each step
costs far more than it saves. The numbers depend on the page: measure your own with
`SOLI_BENCH_HTML=page.html cargo bench --bench compression`, which also times a body arriving in
16 KiB frames, as it does off a socket.

### Custom error pages

```toml
[error_pages]
dir = "/etc/soli-proxy/errors"     # relative paths are from the working directory
intercept_upstream_errors = false  # true: replace backends' error responses too
```

The proxy's own errors — 502 for a backend it cannot reach, 503 when every target's circuit is
open, 504 on a timeout, 421 for a host it does not serve, 401, 413, 429… — are short plain-text
bodies. A browser (any client whose `Accept` lists `text/html`) gets a page from `dir` instead:
`502.html` for that status, else `5xx.html` / `4xx.html`, else `default.html`; with no page, the
plain text. Clients that do not ask for HTML — APIs, `curl` — keep the plain text. The status
and the other headers (`Retry-After`, `WWW-Authenticate`…) are kept.

Only errors the proxy generated are replaced: a backend's own 404 page, a forward-auth service's
denial (its login form or 401 body), or the body of a Lua `deny`, is left as it is (unless
`intercept_upstream_errors = true`, which extends the pages to backends' and auth services'
4xx/5xx). Templates may use `{{status}}`, `{{reason}}`, `{{host}}` and
`{{request_id}}` — the response's `X-Request-Id` if the proxy set one, else the request's — and
every value is HTML-escaped. The pages are read when the configuration is loaded (at startup, on
`SIGUSR1` or `POST /api/v1/reload`), never per request; each is capped at 64 KiB, and a missing
directory or an oversized page is a configuration error.

An app can bring its own pages in `<site>/error_pages/` (same names), used first for requests to
its hosts. They are read at discovery — when the site appears or its `app.infos` or
`maintenance.flag` changes — capped at 64 KiB each and 256 KiB together. In multi-tenant mode the
directory and the pages must not be symlinks: the directory is opened without following one and
the pages are read through that open descriptor, so a tenant cannot swap in a link to a file of
the operator's and get it served back as an error page.

### Maintenance mode

```toml
[maintenance]
retry_after = 300                 # Retry-After, when a toggle does not say (seconds, max a week)
allow_ips = ["203.0.113.7", "10.0.0.0/8"]   # served normally (IP or CIDR, v4 or v6)
allow_paths = ["/up", "/status/*"]          # served normally (exact, or prefix ending in *)
```

In maintenance, requests get **503** with `Retry-After` and a page: `maintenance.html` from the
app's `error_pages/`, else from `[error_pages] dir`, else a built-in one (`{{message}}` is the
toggle's message). Non-HTML clients get `Service Unavailable: <message>` as text. Requests from
`allow_ips`, to `allow_paths`, to `/.well-known/acme-challenge/` and to the proxy's own health and
metrics endpoints go through as usual. `allow_ips` is matched against the client's address — the
TCP peer, or behind `trusted_proxies` the client they forward for; `allow_paths`
compares the path literally (a percent-encoded or dot-segment spelling is not allowed through).

Two ways to switch it:

- **The admin API**, for the whole proxy or one app, persisted to `run/maintenance.json` so a
  restart in the middle of a window does not reopen the site:

  ```bash
  curl -X PUT http://127.0.0.1:9090/api/v1/maintenance -H 'X-Requested-With: cli' \
       -d '{"enabled": true, "retry_after": 600, "message": "Back at 14:00 UTC"}'
  curl -X PUT http://127.0.0.1:9090/api/v1/apps/shop.example.com/maintenance \
       -H 'X-Requested-With: cli' -d '{"enabled": false}'
  curl http://127.0.0.1:9090/api/v1/maintenance     # what is closed, and why
  ```

- **A flag file**, for deploy scripts on the box that have no admin credentials (a tenant's, in
  multi-tenant mode): `touch sites/<domain>/maintenance.flag` closes that app, `rm` reopens it.
  The sites watcher picks the change up within a couple of seconds.

There is deliberately no `app.infos` key: maintenance is a state a site is in for an hour, not
part of its configuration, and a script creating or removing a file is simpler and safer than one
rewriting TOML. A `run/maintenance.json` that does not parse stops the proxy from starting rather
than silently reopening every site. `GET /api/v1/apps` reports `"maintenance": true` for an app
closed either way (or by the global window).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Soli Proxy Server                      │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │ Config      │  │ TLS/HTTPS   │  │ HTTP/2+      │ │
│  │ Manager     │  │ Handler     │  │ Listener     │ │
│  │ (hot reload)│  │ (rcgen/LE)  │  │ (tokio/hyper)│ │
│  └─────────────┘  └─────────────┘  └──────────────┘ │
│         │                │               │          │
│         └────────────────┼───────────────┘          │
│                          │                          │
│                   ┌──────▼──────┐                   │
│                   │   Router    │                   │
│                   │ (matching)  │                   │
│                   └─────────────┘                   │
│                          │                          │
│         ┌────────────────┼────────────────┐         │
│         │                │                │         │
│    ┌────▼────┐     ┌─────▼─────┐     ┌────▼────┐    │
│    │ Auth    │     │ Rate      │     │ Logging │    │
│    │ Middle  │     │ Limit     │     │ JSON    │    │
│    └─────────┘     └───────────┘     └─────────┘    │
└─────────────────────────────────────────────────────┘
```

## Environment Variables

| Variable | Effect |
|---|---|
| `ADMIN_USER`, `ADMIN_PASSWORD_HASH`, `ADMIN_PASSWORD` | Admin API Basic credentials (see [Admin credentials](#admin-credentials)); also read from `<config dir>/.env`. |
| `RUST_LOG` | Log filter when `[logging] level` is not set. |
| `SOLI_LOG_DIR` | Directory of `proxy.log` under `-d` when `[logging] output` names no file (default `.`). |
| `SOLI_PID_DIR` | Directory of `proxy.pid` under `-d` (default `.`). |
| `XDG_CACHE_HOME`, `SOLI_RELEASE_BASE_URL`, `SOLI_NO_PIN`, `HTTP(S)_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR` | Passed through to spawned apps (see [The app's environment](#the-apps-environment)). |

The config location is set with `--conf` only.

## Project Structure

```
soli-proxy/
├── Cargo.toml
├── config.toml               # Main configuration (example)
├── proxy.conf.sample         # Routing rules (example)
├── src/
│   ├── main.rs               # CLI, startup, signals and drain, self-update, hash-password
│   ├── lib.rs                # Library root
│   ├── bin/
│   │   ├── httptest.rs       # End-to-end proxy throughput test
│   │   └── hash-password.rs  # Standalone hasher (same as `soli-proxy hash-password`)
│   ├── config/               # config.toml + proxy.conf parsing, serializer, hot reload
│   ├── server/               # HTTP/HTTPS listeners, routing, forwarding, WebSockets
│   ├── admin/                # Admin REST API (+ proxy to the bundled _admin UI app)
│   ├── app/                  # App discovery, blue-green deploys, ports, cluster routes
│   ├── auth/                 # bcrypt hashing and Basic-auth verification cache
│   ├── scripting/            # Lua engine and hooks (feature "scripting")
│   ├── tui/                  # `soli-proxy tui` terminal UI
│   ├── check.rs              # `soli-proxy check` / POST /api/v1/config/validate
│   ├── acme.rs               # ACME / Let's Encrypt, certificate resolver, rustls config
│   ├── tls.rs                # Certificate loading and the TLS server config
│   ├── logging.rs            # [logging]: subscriber, non-blocking writer, rotation
│   ├── access_log.rs         # [logging] access_log: one line per completed request
│   ├── edge.rs               # Client IP (trusted proxies, PROXY protocol), request IDs
│   ├── forward_auth.rs       # @forward_auth / [auth] forward: SSO subrequest gate
│   ├── circuit_breaker.rs
│   ├── metrics.rs            # Prometheus-format metrics
│   ├── pool.rs               # Upstream connection pool
│   ├── upstream/             # Retries, health checks, HTTP/2, upstream TLS, Unix sockets
│   ├── proxy_headers.rs      # Forwarding headers, hop-by-hop stripping, cookies, Origin
│   ├── response/             # Compression, custom error pages, maintenance mode
│   └── shutdown.rs           # Shutdown signal, connection tracking, drain
├── tests/                    # Integration tests (admin auth, routing, Lua, edge, forward auth, responses, upstreams, restart adoption)
├── benches/
│   ├── routing.rs            # Rule matching & scaling benchmarks
│   ├── components.rs         # Circuit breaker, load balancer, metrics
│   └── config_parsing.rs     # Config file parsing benchmarks
├── scripts/                  # systemd unit, Lua examples (scripts/lua), helper scripts
├── deploy/                   # sudoers grant for setcap
├── docs/                     # Workstation setup, mkcert
└── www/                      # Documentation site (a Soli app)
```

## Performance

Built on Tokio and Hyper with SO_REUSEPORT multi-listener architecture.

### End-to-End Throughput (50k requests, 200 concurrent)

| Endpoint | Throughput | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Proxy (default route → backend) | 228,196 req/s | 0.64 ms | 0.92 ms | 1.20 ms |
| Admin API (GET /api/v1/status) | 508,049 req/s | 0.37 ms | 0.58 ms | 0.71 ms |

### Micro-benchmarks (criterion)

| Component | Operation | Time |
|---|---|---:|
| **Routing** | Domain match | 54 ns |
| **Routing** | Regex match | 57 ns |
| **Routing** | 500 rules worst-case | 587 ns |
| **Circuit breaker** | is_available (1k targets) | 18 ns |
| **Load balancer** | select_index (round-robin) | 1.6 ns |
| **Metrics** | record_request | 29 ns |
| **Metrics** | format_metrics (1k requests) | 601 ns |
| **Config parsing** | 5 rules | 6.9 µs |
| **Config parsing** | 100 rules | 45 µs |

### Running benchmarks

```bash
# Criterion micro-benchmarks (routing, components, config parsing)
cargo bench

# End-to-end proxy throughput test
cargo run --release --bin httptest -- --requests 50000 --concurrency 200
```

## Hot Reload

What triggers a reload:

1. A change to `proxy.conf`, picked up by a file watcher (on by default; `--watch false`
   disables it). `config.toml` is **not** watched.
2. `SIGUSR1` (`systemctl reload soli-proxy`), or `POST /api/v1/reload` on the admin API — both
   re-read `proxy.conf` **and** `config.toml`.
3. Admin API route edits, which rewrite `proxy.conf` and swap the rules in directly.

What happens: both files are parsed into a new configuration, which replaces the old one in a
single atomic swap. Each request reads the configuration once, when it starts, so requests
already in flight finish under the old rules and the next request on the same connection sees
the new ones. No connection is closed or drained — the listeners do not depend on the rules. If
either file fails to parse, nothing changes: the error is logged (or returned by the admin
endpoint) and the previous configuration stays in force.

What a reload does **not** change — these are set up once at startup and need a restart:
listener addresses (`[server] bind`, `https_port`, `worker_threads`), the admin API's
`enabled`/`bind`, TLS certificates (use `POST /api/v1/certs/reload` instead) and
`[tls] min_version`, the Lua engine and its scripts, the rate limiter, `max_connections`, and
`[logging]` `level`/`format`/`output`/`access_log`/`access_log_format`. Per-request settings —
routes, `force_https`, HSTS, timeouts, body-size limit, `log_endpoints`, admin credentials,
`[forward_auth] timeout_secs`, `trusted_proxies`, `real_ip_header`, `request_id_header`,
`[compression]`, `[maintenance]` allowlists, `[error_pages]` (whose pages are re-read),
`[upstream]` retries and the per-route upstream options (`@h2`, `@tls_*`, ...) — take effect on
the next request, `proxy_protocol` on the next connection, `[forward_auth] allowed_urls` at the
next app discovery, and health checks are restarted to match within a second. Maintenance
mode's on/off state is not configuration: a reload leaves it alone.

## Restarts and upgrades

A proxy restart — an upgrade, `systemctl restart`, `soli-proxy -d` replacing a daemon, a crash
and `Restart=always` — no longer takes the apps down. Earlier versions stopped every managed app
on SIGTERM, so each restart was a fleet-wide outage followed by a cold start of every app.

**On SIGTERM or SIGINT** the proxy stops accepting connections, closes idle keep-alive
connections, ends in-flight HTTP/1 responses with `Connection: close` and sends HTTP/2 `GOAWAY`,
then waits for the requests still running to finish — at most `[server] shutdown_grace_period`
(default 10 s); the wait ends as soon as the last one does, so a restart under normal traffic
takes a fraction of a second. Then it exits, **leaving every app running**. (A WebSocket is not
waited for: it is closed with the process. A second signal exits at once.)

**At startup the proxy adopts what is still running** instead of restarting it. For each app,
starting with the slot `run/app_state.json` says was serving, an instance is adopted only when
all of this holds:

| | Native process | Container |
|---|---|---|
| It is ours | `run/spawned.json` records the PID for this app and slot, and the PID is alive with the **recorded start time** (a PID alone is reused) | `<app>-<slot>` is running and carries the proxy's labels for this app, this container name and this port |
| It runs today's launch | a digest of program, arguments, working directory, environment and uid/gid matches the one recorded | the `soli-proxy.launch` label — a digest of the whole `docker run` argv — matches what the proxy would run now |
| It is on the slot's port | the recorded port is the slot's port (`run/ports.lock`), and the process listening on it is that PID or a member of its process group | the `soli-proxy.port` label is the slot's port |
| It is healthy | its `health_check` answers 2xx (or 4xx: the app is up, the path is wrong) within three tries | same |

An adopted instance goes straight into the routing table, before the listeners open, and is
supervised as if this proxy had started it (an unexpected exit triggers failover as usual). What
fails a check is handled as follows:

- **ours, but changed, on the wrong port, not listening or unhealthy** — stopped, and the app
  starts afresh as it always did. So a restart still applies a changed start command,
  `workers`, image, `docker_options`, user or environment (routing settings such as `domain`
  or `[auth]` never needed a restart);
- **ours, in the other slot** — a deploy the restart interrupted: stopped;
- **not provably ours** (a PID with no record or another start time, a process the proxy cannot
  inspect) — neither adopted nor signalled. The fresh start then meets it as before: a port
  held by a stranger is logged and the slot fails rather than kill it;
- **started by a proxy older than 1.0** (which kept no spawn registry) — recognised by what it
  is rather than by a record: the leader of its own session, running as the app's user, from the
  app's own site directory, with the app's start program. It is stopped and the app starts
  afresh, so the first start after upgrading from 0.35 restarts each app once. Native apps only,
  never in multi-tenant mode;
- **a container without the labels** (started by an older version) — replaced, as a fresh start
  always replaced `<app>-<slot>`.

Apps survive because nothing ties them to the proxy: native apps run in their own session
(`setsid`), with no parent-death signal, stdin on `/dev/null` and stdout/stderr written straight
to `run/logs/<app>/<slot>.log` — never to a pipe the proxy holds, so they cannot die of SIGPIPE
when it exits. Containers belong to the Docker daemon. Under systemd the unit needs
`KillMode=process`, which `scripts/soli-proxy.service` sets: the default kills the whole cgroup,
apps included.

**To stop the apps too:** `soli-proxy stop --all` (or `POST /api/v1/apps/stop-all`) stops every
app and leaves the proxy running; run it before `systemctl stop soli-proxy` on a host being
retired. `[apps] stop_on_shutdown = true` restores the old behaviour — every stop and restart
stops every app. It defaults to `true` under `--dev`, so ^C in a terminal still cleans up.

**Upgrading:**

```bash
soli-proxy update                                   # installs the new binary, restarts nothing
soli-proxy check -c /etc/soli-proxy/proxy.conf --sites-dir /srv/sites   # with the new binary
sudo systemctl restart soli-proxy                   # drains, exits, the new one adopts the apps
```

With `-d` instead of systemd, run `soli-proxy -d` with the same flags again (refused while
systemd runs the proxy, see [Systemd Service](#systemd-service)): it signals the running daemon, waits for its drain (`shutdown_grace_period` plus 5 s) and takes over the apps.
Between the old process closing its listeners and the new one opening them, new connections
are refused: for as long as the slowest in-flight request takes to finish (bounded by the grace
period), plus the new process's startup — typically well under a second. A hand-over of the listening sockets, which would close
that gap, is not implemented: two proxies cannot run side by side (the admin port is not shared,
and both would supervise the same apps).

## App Configuration (`app.infos`)

When apps are managed by the proxy (via the sites directory, e.g. `./www`), each app directory **must be named after its domain** (must contain at least one dot, e.g. `myapp.example.org/`) and may contain an `app.infos` file describing how to run it.

`app.infos` is a **TOML file** whose settings live at the top level. Three optional sections may follow them: `[auth]`, and the `[development]` / `[production]` overlays described below. The file itself is optional too — if missing or empty, defaults are used.

It must be a **regular file of at most 64 KiB**. A FIFO, a device, or anything larger makes the
app fail to load (logged, and skipped) instead of being read: the file used to be read whole,
so a FIFO hung discovery and `app.infos -> /dev/zero` exhausted memory at every boot. In
[multi-tenant mode](#multi-tenant-mode-untrusted-apps) a symlinked `app.infos` is refused too;
an operator's single-tenant setup may still symlink it to a shared file.

### Example

```toml
# www/proxy.solisoft.net/app.infos
name = "proxy.solisoft.net"
domain = "proxy.solisoft.net"
start_script = "soli serve . --port $PORT --workers $WORKERS"
workers = 2
stop_script = ""
health_check = "/health"
graceful_timeout = 30
port_range_start = 20000
port_range_end = 30000

# Optional: HTTP Basic Auth on this app's domains...
[auth]
noauth = ["/webhooks/stripe", "/hooks/*"]
# ...and/or forward authentication to an SSO service.
forward = "http://127.0.0.1:4180/"
forward_headers = ["X-Auth-Request-User", "X-Auth-Request-Email"]

[auth.users]
admin = "$2b$12$..."   # generate with: hash-password (cost 4..=13)
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | directory name | Logical app name (used in logs, admin API). |
| `domain` | string | directory name (when auto-detected) | Domain the app serves. Matched against the `Host` header. |
| `start_script` | string | auto-detected (see below) | Command used to launch the app. Supports `$PORT` and `$WORKERS` substitution. Parsed without a shell — no pipes/redirects/globs. |
| `stop_script` | string | _none_ | Optional command to run when stopping the app. |
| `health_check` | string | `"/health"` (`"/up"` for an auto-detected Soli app, `"/"` for LuaOnBeans) | HTTP path the proxy polls every 30s to decide if the app is alive. See [App Health Monitoring](#app-health-monitoring). |
| `graceful_timeout` | int (seconds) | `30` | Time given to the old process to exit cleanly during a blue/green swap. At most `3600`; a larger value is clamped, with a warning. |
| `drain_delay` | int (seconds) | `5` | Time to keep the old process draining existing connections before shutdown. At most `3600`, and clamped to `< graceful_timeout` (set to `graceful_timeout / 2` if too large). |
| `port_range_start` | int | `20000` | Lower bound of the port range used to allocate blue/green slots. Ignored in multi-tenant mode, where `[apps] port_range_start` decides. |
| `port_range_end` | int | `30000` | Upper bound of the port range. A range that starts below 1024, holds fewer than two ports, spans more than 20 000, or contains one of the proxy's own listener ports (HTTP, HTTPS, admin) is refused with an error and the `[apps]` range is used instead. |
| `workers` | int | `1` | Number of worker processes the app should spawn. Exposed as `$WORKERS` in `start_script` and as the `WORKERS` env var. |
| `user` | string | `[apps].default_user` from `config.toml` | OS user to drop privileges to (required when running the proxy as root). |
| `group` | string | `[apps].default_group` from `config.toml` | OS group to drop privileges to. |
| `docker_image` | string | _none_ | If set, the app runs inside Docker using this image instead of a host process. |
| `docker_options` | string | _none_ | Extra flags appended to `docker run`. Whitespace-split, no shell. Single-tenant: a denylist rejects `--privileged`, `--cap-add`, `--device`, `--security-opt`, `--userns`, `--volumes-from`, `--env-file`, `--group-add`, joining the `host` or another container's namespaces, and docker-socket / root mounts in every spelling (`-v/:/x`, `--mount type=bind,source=/`, `/./`, `/etc/..`). Multi-tenant: only the allowlist below is accepted. |
| `docker_network` | string | `"soli-apps"` | Docker network the container joins (created automatically if missing). A plain network name only: `host` and `container:<id>` are refused in every mode, since the value goes straight to `--network`. Ignored in multi-tenant mode, where each app gets a private network. |
| `compress` | bool | _unset_ | `false`: never compress this app's responses. `true`: compress them even with `[compression] enabled = false` — ignored in multi-tenant mode. Unset follows `[compression]`. See [Compression](#compression). |
| `idle_timeout` | int (seconds) | `[apps].idle_timeout` from `config.toml`, itself `900` (`3600` under `--dev`) | Scale to zero: after this many seconds without a request (and with none still open) the proxy stops the app and starts it again on the next one, holding that request until the app is healthy. `0` means the app never sleeps. See [Scale to zero](#scale-to-zero). |
| `[auth.users]` | table | _empty_ | `username = "bcrypt hash"` entries. When non-empty, every request to this app's domains must present matching HTTP Basic Auth credentials. Generate a hash with `hash-password`; only bcrypt hashes at cost 4 to 13 are accepted. |
| `[auth] noauth` | list of strings | _empty_ | Paths served without credentials, for callers that cannot send a password (a payment webhook, a health probe). Exact path, or a prefix ending in `*` — the same syntax as the `@noauth:` route directive, and the same fail-closed rule: a path carrying percent-encoding or a `..` segment is never exempt. Skips forward-auth too. |
| `[auth] forward` | string | _none_ | Auth service asked before every request to this app's domains, WebSocket upgrades included — the app equivalent of `@forward_auth:`. See [Forward authentication](#forward-authentication). With `[auth.users]` too, Basic Auth runs first and both must pass. In multi-tenant mode it must be covered by `[forward_auth] allowed_urls`. |
| `[auth] forward_headers` | list of strings | _empty_ | Auth-service response headers copied onto the request to the app (and always removed from the client's). Requires `forward`. |

Apps are routed by the app manager rather than by `proxy.conf` rules — `sync_routes` prunes
static rules for app-managed domains — so a route's `@auth` cannot protect an app. `[auth]` is
the equivalent for apps, and it covers the app's derived domains (`www.`-stripped, `.test` in
dev) and any admin-managed alias pointing at it. A `[auth]` section the proxy cannot enforce as
written (an empty or malformed hash, a bcrypt cost outside 4–13, a `noauth` pattern that does
not compare literally, a `forward` URL that is not `http(s)://` with a host, a `forward_headers`
name the proxy manages or without `forward`) makes the app fail to load and be skipped, rather
than come up unprotected.

### Per-environment settings

The same manifest can carry a `[development]` and a `[production]` section. The proxy's `--dev`
flag — the flag that already appends `--dev` to an auto-detected Soli start script and registers
each app's `.test` alias — decides which one is folded in:

```toml
# app.infos
workers = 4
idle_timeout = 1800

[development]
workers = 1          # one worker, and no sleeping, while developing
idle_timeout = 0

[production]
workers = 8
```

Run with `--dev` this app has one worker and never sleeps; run without it, eight workers and a
30-minute idle timeout. The alternative — a dev copy of `app.infos` and a prod copy — is two
files nobody diffs until the day they disagree about something that matters.

Rules:

- The selected section is applied **key by key** over the top level. A key the section does not
  mention keeps its top-level value (above, `idle_timeout` in production).
- A nested table **merges** into its counterpart rather than replacing it, so
  `[production.auth.users]` adds accounts without discarding the `noauth` list written under
  `[auth]`.
- The section that is **not** selected is dropped unread. A `[production]` block naming a
  setting only a newer proxy understands will not stop a developer's machine from starting the
  app.
- Both sections are optional, and a manifest carrying neither parses exactly as it did before
  they existed.

Beware the ordinary TOML trap: every key after a `[development]` header belongs to that section
until the next header. A setting meant for both environments goes **above** the first section.

### Unknown settings

A key `app.infos` does not define is ignored — `worker = 4` runs the app with one worker — but
discovery logs it:

```
WARN app.infos for myapp.example.com: unknown setting "worker" — ignored
```

Ignoring rather than refusing is deliberate: a manifest that fails to load takes a running app
off the routing table, which is a steep price for a typo. The warning is there so the typo costs
five minutes instead of five hours. Unknown keys inside `[development]` or `[production]` are
reported the same way, with the section named.

### Scale to zero

Most fleets are mostly idle: on a box hosting thirty small sites, a day's traffic
typically touches a handful, and every one of the others holds its full runtime
in memory for nothing. So the proxy puts an app to sleep — stops its process —
after **15 minutes without a request**, and starts it again on the next one.
`idle_timeout` (seconds) changes the threshold, `0` turns it off:

```toml
# app.infos
idle_timeout = 0      # this app never sleeps
# idle_timeout = 3600 # or: sleep after an hour
```

What happens:

- Every request the proxy routes to an app resets that app's idle clock, and an
  app with a request still open is never idle: a response still streaming
  (server-sent events, a large download) or a WebSocket still up keeps it awake
  however long it lasts, and the clock starts when the last one ends.
- A reaper runs every 30 s. An app past its threshold is stopped the same way
  `soli-proxy stop` stops it, so the exit is not mistaken for a crash — no
  failover, no quarantine, and no health-check failure for the process going
  away. The journal says `<app> put to sleep after <n>s without a request`.
- The next request for one of its domains is **held** while the app is started
  on its current slot and polled for health, then forwarded as usual. A Soli app
  boots in a few hundred milliseconds, so the first visitor waits about a
  second; everyone else finds it running. Concurrent first requests share one
  start.
- A sleeping app keeps its certificate registered and keeps winning over
  static `proxy.conf` rules for its domains, exactly as a running one does.
- `soli-proxy restart <app>` or a deploy wakes it too, and resets the clock.
- `/api/v1/app-metrics` and `/api/v1/apps/{name}/metrics` report it with
  `"asleep": true`, and the TUI shows it as **Sleeping** (`◐ sleep` on the
  dashboard) rather than Stopped: an app that comes back on the next request,
  not one that stays down until someone acts.
- Any request resets the clock, crawlers included. A public site that bots
  fetch more often than its threshold never sleeps; its `requests` and
  `last_request_ms` in `/api/v1/app-metrics` show who keeps it up.

**Set `idle_timeout = 0` on an app that does work without being asked**: cron
jobs, background job workers, a warm cache that takes more than a moment to
rebuild. Asleep, it runs none of them until a request wakes it. (Open
connections are covered: a chat's WebSockets keep its app up.) `_admin` never
sleeps regardless of its manifest. Under `--dev` the default is an hour: a laptop
running a dozen apps gets its memory back without a wake-up after every short
break. The fleet-wide default goes in `config.toml`:

```toml
[apps]
idle_timeout = 1800   # apps that don't say otherwise sleep after 30 minutes
# idle_timeout = 0    # or: no app sleeps unless its app.infos asks
```

Before 1.2 the default was `0`, never sleep: after upgrading, apps without an
`idle_timeout` start sleeping after 15 minutes. Pin the ones that must stay up
first, or set `[apps] idle_timeout = 0` to keep the old behaviour.

### The app's environment

An app is started with a **cleared environment**, so nothing the proxy happens
to inherit leaks into it. The child gets:

| Variable | Value |
|---|---|
| `PORT` | The blue/green slot's port. |
| `WORKERS` | The `workers` setting. |
| `HOME` | **The home directory of the `user` the app runs as**, read from the passwd database — not the proxy's own. |
| `PATH`, `LANG`, `TZ` | Copied from the proxy. |

`HOME` matters more than it looks. The proxy usually runs as root and drops
privileges to the app's `user`, so handing the child the proxy's own `HOME`
(`/root` under systemd) pointed every `~`-resolved path at a directory the app
cannot read. That silently broke soli's package cache (`~/.soli/packages`), its
registry credentials, the Tailwind CLI it downloads to `~/.soli/bin`, and the
cache for [pinned interpreter versions](https://soli.solisoft.net/docs/language/modules).

A short allowlist also survives the clear, when it is set on the proxy:

| Variable | Why |
|---|---|
| `XDG_CACHE_HOME` | Points at a shared soli toolchain cache, so a pinned app does not download its interpreter on the server and several apps running as different users can share one. |
| `SOLI_RELEASE_BASE_URL` | An internal mirror for those downloads. |
| `SOLI_NO_PIN` | Operator override for a version pin, e.g. during an incident. |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase) | Outbound egress proxy. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Custom CA bundle. |

Anything else stays cleared. Put per-app configuration in the app's own `.env`,
not in the proxy's environment.

A Docker app gets the same treatment, minus the entries that name a host path: the proxy-family
variables, `SOLI_RELEASE_BASE_URL` and `SOLI_NO_PIN` are passed as `-e` flags into the
container, while `XDG_CACHE_HOME`, `SSL_CERT_FILE` and `SSL_CERT_DIR` are not (the container
cannot see those directories; bake a CA bundle into the image instead).

In [multi-tenant mode](#multi-tenant-mode-untrusted-apps) the egress variables are the
operator's, not the tenants': `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase) are **not**
forwarded unless `[apps] tenant_proxy_env = true`, and any forwarded value carrying credentials
(`http://user:password@proxy:3128`) is dropped, with a warning, unless
`tenant_proxy_env_credentials = true` as well.

### Pinned Soli versions

A Soli app can pin the exact interpreter it runs on, with
`soli_version = "=2.0.3"` in its `soli.toml`. The proxy needs no configuration
for this: it starts an app with the app directory as the working directory, and
soli resolves the pin from there — the same as on a developer machine.

Two things to get right on a server:

- **Provision the toolchain during deployment, not at start-up.** A new instance
  has 30 seconds to pass its health check. A first start after changing a pin
  spends part of that window downloading, and a slow link can push it over; the
  deploy then fails and succeeds on the retry, once the cache is warm.
- **Make the cache readable by the app's user.** With `HOME` now resolved
  correctly this works by default, but several apps running as different users
  will each download their own copy. Point `XDG_CACHE_HOME` at a shared
  directory readable by all of them to avoid that.

### Variable substitution

`start_script` supports two placeholders, replaced before the process is launched:

- `$PORT` — the slot port allocated by the proxy (from `port_range_start`..`port_range_end`).
- `$WORKERS` — the value of the `workers` field.

The same values are also exported as **environment variables** (`PORT`, `WORKERS`, and `HEALTH_CHECK` for Docker), so scripts that don't use `$VAR` substitution can still read them from the environment.

### Auto-detection

If `start_script` is omitted, the proxy tries to infer one from the app directory:

- **Soli app** — when `app/` and `app/models/` exist:
  - `start_script` → `soli serve . --port $PORT --workers $WORKERS` (with `--dev` appended in dev mode)
  - `health_check` → `/up`, Soli's built-in readiness probe: it answers 503 until the app's
    session store is warm, so a blue/green switch waits for a slot that can actually serve
- **LuaOnBeans app** — when a `luaonbeans.org` binary exists in the directory:
  - `start_script` → `./luaonbeans.org -D . -p $PORT -s`
  - `health_check` → `/`

If no `start_script` is set and neither layout is detected, deployment fails with `No start script configured`.

## Multi-Tenant Mode (untrusted apps)

The native start path is **not a sandbox**. It clears the environment, calls `setsid()` and sets
`PR_SET_NO_NEW_PRIVS`, but the process still reads the host filesystem — other tenants' site
directories, `certs/`, and this proxy's own `config.toml`, which contains the admin API key — and
can connect to anything on localhost. That is fine when you wrote every app, and unacceptable when
you did not.

```toml
[apps]
multi_tenant = true       # default false; existing deployments are unchanged
tenant_memory = "512m"
tenant_cpus   = "1.0"
tenant_user   = "10000:10000"
port_range_start = 20000  # the platform's slot ports; tenants cannot choose their own
port_range_end   = 30000
tenant_proxy_env = false              # forward HTTP(S)_PROXY into containers?
tenant_proxy_env_credentials = false  # ...even when they carry user:password@?
```

With it on:

- An app **without** a `docker_image` fails to deploy rather than falling back to the native path.
  Failing loudly is the point — a silent fallback would undo the isolation.
- Every container gets `--read-only`, a `noexec,nosuid` tmpfs at `/tmp`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--pids-limit 256`, plus the memory/cpu/user limits above.
- These are appended **after** the app's own `docker_options`, and `docker run` honours the last
  occurrence of a repeated flag, so an app cannot raise its own ceiling or run as root. The image
  is passed after a `--` terminator, and `docker_image` must be a well-formed image reference, so
  neither it nor the start script can smuggle in further flags.
- `docker_options` is validated against an **allowlist** — anything not listed fails the deploy,
  naming the offending token. Every flag must carry a value (a trailing flag would swallow the
  platform's hardening). Permitted:
  - `-e`/`--env KEY=VALUE`, `-l`/`--label`, `--stop-timeout`, `--health-*`
  - no `--restart`: the proxy supervises the slot. A docker restart policy is a second
    supervisor that knows nothing of blue/green — `always` brought slots the proxy had stopped
    back to life next to their replacements, each with its own memory ceiling
  - `-m`/`--memory`, `--cpus`, `--cpu-shares`, `--pids-limit`, `--shm-size` (the platform's
    limits still win, see above)
  - no `-p`/`--publish`: the proxy publishes the allocated slot port as `127.0.0.1:$PORT:$PORT`
    itself, so a tenant cannot bind a host port that belongs to another tenant's slot
  - `-v`/`--volume SRC:DST[:ro|rw]` and `--mount type=bind,source=SRC,target=DST[,readonly]`
    only when `SRC` canonicalises (symlinks resolved) to the app's own site directory — the
    directory itself, not a path inside it. Everything under the site directory is writable by
    the tenant's running container, which could swap a sub-directory for a symlink between the
    check and docker's own path resolution at mount time; the site directory's own path has no
    tenant-writable component. The canonical path is what reaches `docker run`, never the
    tenant's spelling. Named volumes, other mount types, propagation and relabel options are
    rejected.
- `name` and `domain` in `app.infos` are bound to the site directory: `name` must equal it,
  `domain` must be it or its `www.` twin (or empty). A tenant cannot claim another site's `Host`
  or take over another app's entry; a directory whose manifest breaks the rule is skipped and
  logged. Names starting with `_` are reserved for bundled apps (`_admin`) in every mode.
- `name`, `domain` and `health_check` are checked at load time in every mode: hostname
  characters (plus `_`, for existing `my_app.example.com` directories) for the first two, an
  absolute URL path for the third.
- A `www.` site's derived apex (`www.example.com/` also answering `example.com`) is the weakest
  claim there is: it never displaces another app's declared domain or an admin alias, and in
  this mode it does not displace an operator's static `proxy.conf` rule or a cluster-pushed
  route either. An app owns its domains whether or not it is running, so stopping a site no
  longer hands its apex to someone else's `www.` directory, and Basic Auth is always taken from
  the app that is actually served. The same goes for the app's `error_pages/` and its
  `maintenance.flag`: they apply to the requests the app serves, never to an apex its claim
  yielded to the operator's rule or a pushed route.
- Slot ports come from the platform range (`[apps] port_range_start`/`port_range_end`); an
  app's own `port_range_*` is ignored. In every mode a range is refused if it reaches below
  1024 or covers one of the proxy's listeners.
- Each app gets a **private Docker network**, `soli-app-<name>`, created with inter-container
  traffic disabled (`com.docker.network.bridge.enable_icc=false`) and a host bridge named
  `sl-<12 hex digits>`. The tenant's `docker_network` is ignored. When a site directory is
  removed, its containers are stopped and its network removed.
- Containers are stopped with `docker stop` + `docker rm -f` **by name**, never by signalling
  the PID docker reports, which left the container (and its restart policy) behind.
- An app's `[auth] forward` must be covered by `[forward_auth] allowed_urls` (empty by default:
  no tenant can use forward-auth), since the proxy fetches it on the tenant's behalf. See
  [Multi-tenant mode: `allowed_urls`](#multi-tenant-mode-allowed_urls).

#### Egress filtering is yours to configure

Docker isolates tenant networks from each other, but a container can still open connections to
the host itself (through its bridge's gateway address — anything listening on `0.0.0.0`, such as
a database) and to private networks the host can reach. The proxy cannot close that portably;
the firewall can. The fixed `sl-` bridge prefix makes it one rule set. With nftables:

```nft
table inet soli_tenants {
    # Tenant containers may not open connections to the host itself.
    chain input {
        type filter hook input priority filter - 1; policy accept;
        iifname "sl-*" ct state established,related accept
        iifname "sl-*" drop
    }
    # ...nor to private, link-local (cloud metadata) or CGNAT ranges.
    chain forward {
        type filter hook forward priority filter - 1; policy accept;
        iifname "sl-*" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
                                   169.254.0.0/16, 100.64.0.0/10 } ct state new drop
        iifname "sl-*" ip6 daddr { fc00::/7, fe80::/10 } ct state new drop
    }
}
```

The iptables equivalent is a `DOCKER-USER` rule per range
(`iptables -I DOCKER-USER -i sl-+ -d 10.0.0.0/8 -m conntrack --ctstate NEW -j DROP`, …) plus
`iptables -I INPUT -i sl-+ -m conntrack --ctstate NEW -j DROP`. Traffic from the proxy to a
container's published slot port is unaffected: it enters the bridge, it does not leave it.

> Docker has a long history of container escapes. This raises the cost of one; it is not a VM
> boundary. For genuinely hostile code, treat it as the first step toward gVisor or Firecracker.

## Admin API

Served on `[admin] bind` (loopback `127.0.0.1:9090` by default); see
[Admin credentials](#admin-credentials) for authentication and the CSRF rule for mutations
(`X-Requested-With`, below under Domain Aliases). Responses are `{"ok": true, "data": ...}`.

| Method | Path | |
|---|---|---|
| GET | `/api/v1/status` | Version, uptime, route and app counts |
| GET / PUT | `/api/v1/config` | Rules and global scripts as JSON / replace them |
| GET / POST | `/api/v1/routes` | List / add a route |
| GET / PUT / DELETE | `/api/v1/routes/{index}` | One route |
| POST | `/api/v1/reload` | Re-read `proxy.conf` and `config.toml` |
| POST | `/api/v1/certs/reload` | Rescan `certs/` |
| GET | `/api/v1/metrics` | Prometheus metrics |
| GET | `/api/v1/app-metrics`, `/api/v1/app-metrics/system`, `/api/v1/apps/{name}/metrics` | Per-app traffic, memory and CPU; `asleep` marks an app stopped by scale to zero |
| GET | `/api/v1/events/apps` | Server-Sent Events, one JSON object per `data:` line with a `type`: `DeployStage` (`stage` = `start`, `health`, `switch`, `drain`, then `done` or `failed`; `slot`, `from`, `detail`), `Asleep` (`idle_secs`), `Waking`, `Deployed`, `StatusChanged`, `Stopped`, `Restarted` |
| GET | `/api/v1/apps`, `/api/v1/apps/{name}`, `/api/v1/apps/by-domain` | Managed apps |
| POST | `/api/v1/apps/{name}/deploy` \| `restart` \| `rollback` \| `stop` | App lifecycle |
| POST | `/api/v1/apps/stop-all` | Stop every app, both slots (the proxy keeps running) |
| POST | `/api/v1/config/validate` | Check a proposed `{"proxy_conf": "...", "config_toml": "..."}` without applying it |
| GET | `/api/v1/apps/{name}/logs` | Deployment logs |
| GET / POST / DELETE | `/api/v1/aliases`, `/api/v1/apps/{name}/aliases[/{domain}]` | Domain aliases |
| GET / POST | `/api/v1/circuit-breaker`, `/api/v1/circuit-breaker/reset` | Circuit-breaker state (plus `health`: `up`/`down` for actively checked targets) / reset (health verdicts stay) |
| GET / PUT | `/api/v1/routing-table` | Cluster-pushed routes (complete set, increasing `index`; a stale push gets 409) |
| GET / PUT | `/api/v1/acme-challenges` | HTTP-01 tokens pushed by an external ACME orderer |
| POST | `/api/v1/hash-password` | `{"password": ...}` → bcrypt hash |
| GET / PUT | `/api/v1/settings` | Admin UI settings (`{"theme": ...}`) |
| GET / PUT | `/api/v1/maintenance` | Maintenance mode for the whole proxy: `{"enabled", "retry_after"?, "message"?}` (see [Maintenance mode](#maintenance-mode)) |
| PUT | `/api/v1/apps/{name}/maintenance` | Maintenance mode for one app, same body |

`POST /api/v1/config/validate` runs `soli-proxy check`'s checks (sites aside) on the text it is
given; a part left out is read from the running proxy's files, so a proposed `proxy.conf` is
checked against the live `config.toml` and vice versa. It answers 200 with `valid`, `errors`,
`warnings` and `problems` — each with `file`, `line` (when known), `severity` and `message` — and
changes nothing; apply with `PUT /api/v1/config` or by writing the file.

Any other path is proxied to the bundled `_admin` UI app, when one is installed.

## Reloading Certificates

Certificate files in `certs/` are scanned at startup. To install one added or renewed since —
a wildcard from an external DNS-01 client, or a `mkcert` certificate for local development —
rescan without restarting:

```bash
curl -X POST http://127.0.0.1:9090/api/v1/certs/reload -H "X-Api-Key: $KEY"
```

The reload is visible to live TLS handshakes immediately; connections are not dropped. Prior to
this, installing a certificate meant a full restart.

ACME-issued certificates do **not** need this — the renewal task injects them into the resolver
directly. Call it from your renewal hook when an external tool writes the files instead.

## Domain Aliases

A site directory gives an app exactly one domain, which ties *the URL* to *the checkout behind
it*. Aliases break that coupling: several domains can point at one running app, and repointing
an alias is an atomic map swap — no restart, no rebuild, effective on the next request. That is
what makes instant rollback and per-branch preview URLs possible.

```bash
# Point a domain at a running app
curl -X POST http://127.0.0.1:9090/api/v1/apps/myapp.example.com/aliases \
     -H 'Content-Type: application/json' -H "X-Api-Key: $KEY" \
     -d '{"domain":"www.example.com"}'

curl http://127.0.0.1:9090/api/v1/aliases            # domain -> app
curl -X DELETE http://127.0.0.1:9090/api/v1/apps/myapp.example.com/aliases/www.example.com \
     -H "X-Api-Key: $KEY"
```

Every non-GET request must carry `X-Api-Key`, or — when no key is configured, or with Basic
auth — an `X-Requested-With` header of any value. That is the CSRF guard: an HTML form cannot
set either header, so a page the operator happens to visit cannot drive the admin API with
the browser's cached credentials or the open loopback default.

Two more guards on the admin listener:

- **The open (credential-less) admin API answers only requests addressed to localhost** —
  a `Host` of `localhost`, a loopback IP such as `127.0.0.1` or `[::1]`, or the bound address,
  with any port — and `403` otherwise. That defeats DNS rebinding, where a page on a hostname
  that re-resolves to `127.0.0.1` would otherwise reach the API as a same-origin request. With
  a credential configured any `Host` is accepted, since such a page has none to send.
- **Ten failed authentications per client IP (IPv6: per /64) per minute**, then `429` with `Retry-After` until
  the minute is up — answered before bcrypt runs. Only requests that carried a credential count,
  and a correct one never does, so the TUI and CLI can poll freely; a Basic credential that
  already succeeded in the last five minutes is still let through while its IP is blocked. This
  is always on, independent of `[rate_limiting]`. Behind a local route every client shares the
  proxy's loopback address, and so this budget.

Rollback is the same POST with a different app: send `{"domain":"www.example.com"}` to the
previous deployment and traffic moves back, with both processes left running.

Notes:

- Aliases are stored in `run/aliases.json` and reloaded at startup. A missing or malformed file
  is ignored with a log line rather than being fatal — aliases are additive routing, so losing
  them degrades to site-domain-only.
- An alias can never shadow an app's own site domain; that is rejected, since otherwise routing
  would depend on map iteration order.
- Aliases are registered for ACME exactly like site domains, so a public alias gets its own
  certificate automatically.
- Traffic arriving on an alias is attributed to its app, so per-app metrics and request-triggered
  failover behave the same as on the site domain.
- `_admin` cannot be aliased: it does no auth of its own and is only safe behind the admin listener.

## Cluster Routing Table

`soli-oned` pushes the domains it runs on other nodes with `PUT /api/v1/routing-table`; the
proxy routes them without supervising them.

```json
{ "index": 42,
  "routes": { "x.soli.app": [ { "url": "http://10.0.0.12:20001", "weight": 100 } ] },
  "auth":   { "x.soli.app": { "users": { "admin": "$2b$12$..." }, "noauth": ["/hooks/*"] } } }
```

- The table replaces the previous one. `index` must be strictly greater than the one in place
  (any index for the first push after a start, 0 included); a stale or replayed push answers
  `409`.
- A target must be an `http://` or `https://` URL with a host, and `weight` an integer 0–255
  (default 100); anything else answers `400`.
- **`auth` is enforced by this proxy, or not at all.** A pushed target is the workload's raw port
  on another node, with nothing in front of it there, so an app's `[auth]` has to travel with its
  route. It takes the `app.infos` shape and validation (bcrypt cost 4–13, literal `noauth`
  paths, and `forward` / `forward_headers` for [forward authentication](#forward-authentication)),
  may only name domains present in `routes`, and is replaced along with them. A pushed
  domain without `auth` is served unprotected. `GET /api/v1/routing-table` returns usernames,
  `noauth` and the forward-auth URL and headers, never hashes. The pusher authenticates as the
  admin, so a pushed `forward` URL is trusted like a `proxy.conf` route and is not checked
  against `[forward_auth] allowed_urls`.

## Deploy Trigger File (`restart.txt`)

Touching `restart.txt` at the root of a site triggers a zero-downtime blue/green deploy of
that app — the same thing `soli-proxy restart <app>` does, with no SSH-side knowledge of the
app name required:

```bash
# at the end of any deploy script
rsync -rzuv ./ server:/home/rocky/sites/myapp.example.org/
ssh server 'touch /home/rocky/sites/myapp.example.org/restart.txt'
```

- The trigger is **polled**, not watched. Sites are usually symlinks into out-of-tree
  repositories and inotify does not traverse symlinks, so the `proxy.conf`/sites watcher never
  sees files inside them.
- Detection latency is the poll interval (2s by default).
- The **first** poll after a daemon start only records a baseline: an already-present
  `restart.txt` does not cause a deploy on startup.
- Creating the file for the first time triggers a deploy; deleting it does not.

The sites watcher does not look at it either: outside dev mode it reacts only to a site
directory appearing, disappearing or being renamed, and to a site's `app.infos`, watching each
non-recursively. A tenant's other writes cost nothing — they used to consume an inotify watch per
directory and trigger a full rediscovery each. Bursts are coalesced (500 ms of quiet, 5 s at
most) and rediscoveries are at least 2 s apart. `--dev` keeps the recursive watch, to restart
an app when its code changes.

Both the file name and the interval are configurable under `[apps]` in `config.toml`. Setting
`restart_trigger_poll_secs = 0` disables the mechanism:

```toml
[apps]
restart_trigger_file = "restart.txt"
restart_trigger_poll_secs = 2
```

## App Health Monitoring

When apps are managed by the proxy, it polls each running app's `health_check` path every 30
seconds and fails the app over to its other slot (a zero-downtime blue/green restart) when it
stops answering:

| Response | Counts as |
|---|---|
| 2xx | healthy — resets the failure count |
| no connection, timeout, 5xx | a **failure** |
| 4xx | not a failure: the app answered, so it is up, and a 404 or 401 on a health path nearly always means `health_check` names the wrong path. Logged as a warning on every poll, so it is noticed. |

A single failure is not acted on: the app is failed over after
**`[apps] health_failure_threshold` consecutive failures** (default `3`, so about 90 seconds of
an unresponsive app at the default interval). A GC pause or one slow answer used to cost a full
restart.

```toml
[apps]
health_failure_threshold = 3
```

A slot being deployed, a quarantined app and a sleeping app are not polled.

See [App Configuration](#app-configuration-appinfos) above for how to set `health_check` per app.

### Quarantine on failed start

When an app **fails to start** — the process cannot be spawned, or the new slot never passes
its health check — the proxy stops trying instead of restarting it in a loop:

- The new slot is killed and marked `Failed`. **The previous slot keeps serving**, so a bad
  deploy never takes the site down.
- The app is put in *quarantine*: the 30s health loop, the process-exit monitor, and the
  request-triggered failover all skip it. An app is also quarantined after 3 consecutive
  unexpected exits.
- `GET /api/v1/apps` and `/api/v1/apps/{name}` report `"quarantined": true`, and a
  `StatusChanged` SSE event with status `quarantined` is emitted.

Quarantine is lifted by any **explicit** deploy: touching `restart.txt`,
`soli-proxy restart <app>`, or `POST /api/v1/apps/{name}/restart|deploy`. The failure reason
and the path to the app's log (`run/logs/<app>/<slot>.log`) are logged at `error` level.

## Systemd Service

Install soli-proxy as a systemd service for automatic restart on failure:

```bash
# A dedicated, unprivileged account owns the config and the sites
sudo useradd --system --home-dir /var/lib/soli-proxy --shell /usr/sbin/nologin soli-proxy
sudo mkdir -p /etc/soli-proxy /srv/sites
sudo chown -R soli-proxy:soli-proxy /etc/soli-proxy /srv/sites

# Copy the service file and adjust the paths in it
sudo cp scripts/soli-proxy.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable soli-proxy
sudo systemctl start soli-proxy

# Check status
sudo systemctl status soli-proxy

# View logs
journalctl -u soli-proxy -f
```

`systemctl reload soli-proxy` re-reads `proxy.conf` and `config.toml` (it sends `SIGUSR1`).
`systemctl restart soli-proxy` drains in-flight requests and leaves the apps running for the new
process to adopt — the unit sets `KillMode=process` for that; see
[Restarts and upgrades](#restarts-and-upgrades). `systemctl stop` leaves them running too: run
`soli-proxy stop --all` first to stop them.

**Once systemd runs it, the proxy cannot be started by hand.** `soli-proxy` (in the
foreground or with `-d`) refuses to start when a systemd unit's main process is already a
soli-proxy and a port it would listen on (`[server] bind`, `https_port`) is already taken. It
prints the unit, its PID and the ports, and exits 1 with the `systemctl` commands to use
instead. Two proxies would not fail to bind: the listeners use `SO_REUSEPORT`, so the second
would silently share :80 and :443 with the first and both would supervise the same apps — and
`-d` would first stop whatever `proxy.pid` names. To run one by hand, `systemctl stop` the unit
first. A proxy on other ports (a second instance with its own config, a test suite) shares
nothing with the managed one and starts normally. The subcommands (`tui`, `check`, `restart <app>`, `stop`, `logs`, `update`…) are not
affected. The check asks systemd for the unit's `MainPID`, so a proxy started from a terminal
that a desktop session launched as a service (uwsm's `app-…@….service`) is not mistaken for a
managed one. Linux only.

### Privileges

The unit runs the proxy as the `soli-proxy` user with a single capability,
`CAP_NET_BIND_SERVICE` (granted by `AmbientCapabilities=`, so no `setcap` on the binary and
nothing for an upgrade to drop), under `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome` and the usual kernel protections — but not `PrivateTmp`: apps outlive a restart
(`KillMode=process`), and systemd empties a unit's private `/tmp` when it stops. Native apps are children of the
proxy and share that sandbox: they can write only where `ReadWritePaths=` allows
(`/etc/soli-proxy` for the admin API's `proxy.conf` rewrites, and `/srv/sites`). Sites under
`/home`? Set `ProtectHome=no` and list the directory in `ReadWritePaths`.

What the unprivileged account can and cannot do:

| Setup | Unprivileged unit |
|---|---|
| Routing, TLS/ACME, admin API, Lua | Yes. |
| Docker apps (`docker_image`, `multi_tenant`) | Yes, with `SupplementaryGroups=docker` — but the docker group is root-equivalent; prefer rootless Docker/Podman. |
| Native apps as the proxy's own user | Yes, but they can read `config.toml` and its admin credentials. |
| Native apps as **other** users (`user`, `[apps] default_user`) | **No.** Use the root variant in the unit's comments. |

Why not simply add `CAP_SETUID`/`CAP_SETGID` for that last row: ambient capabilities survive
`exec`, and a uid change between two non-root uids does not clear them, so every app would start
holding `CAP_SETUID` — root, in effect. A root process that `setuid()`s to the app's user does
shed every capability, which is why per-user native apps need the root variant (still with the
hardening directives and a narrowed `CapabilityBoundingSet`).

`deploy/soli-proxy-setcap.sudoers` is only for a proxy started by hand (a workstation), not by
this unit. It lets one account run `setcap cap_net_bind_service=+ep` on one **root-owned** path,
`/usr/local/bin/soli-proxy`; see the comments in the file for why a user-writable path there
would widen the grant to any binary on the machine.

The service file is located at `scripts/soli-proxy.service`. Its three load-bearing lines:

```ini
WorkingDirectory=/var/lib/soli-proxy
ExecStart=/usr/local/bin/soli-proxy \
    --conf /etc/soli-proxy/proxy.conf \
    --sites-dir /srv/sites
```

### Where things go

| Setting | Notes |
|---|---|
| `--conf` | Points at **`proxy.conf`** (routing), *not* `config.toml`. Short form `-c`. There is no `--config` flag. |
| `config.toml` | Never passed as an argument — it is read from the **same directory** as `--conf`, i.e. `/etc/soli-proxy/config.toml` above. |
| `--sites-dir` | The **only** way to set the sites location. There is no equivalent key in `config.toml`. Defaults to `./sites`. |

`WorkingDirectory` is mandatory: the runtime state paths are relative and cannot be relocated
by flag or environment variable. With the unit above they resolve to:

| Path | Contents |
|---|---|
| `/var/lib/soli-proxy/run/logs/<app>/<blue\|green>.log` | stdout + stderr of each app slot (created automatically) |
| `/var/lib/soli-proxy/run/app_state.json` | which slot currently serves each app |
| `/var/lib/soli-proxy/run/ports.lock` | blue/green port assignments |
| `/var/lib/soli-proxy/run/spawned.json` | the native processes the proxy started, with their start times |
| `/var/lib/soli-proxy/run/aliases.json` | admin-managed domain aliases |
| `/var/lib/soli-proxy/certs/` | TLS cache, when `[tls].cache_dir` is `./certs` |

These files, and `proxy.conf` when the proxy rewrites it, are written atomically (temporary
file, `fsync`, rename), so a crash or a full disk leaves the previous version rather than a
truncated one.

`spawned.json` is what lets a restarted proxy take its apps back, and clean up after itself
without collateral damage. Each record holds the PID, its start time, the app, slot and port,
and a digest of the launch. At startup a recorded process that still matches is adopted (see
[Restarts and upgrades](#restarts-and-upgrades)); a slot's port that is still held is otherwise
reclaimed only if the process holding it — or the process group it belongs to — is one the
proxy recorded spawning, *with the same start time* (a PID alone is reused). Anything else on
the port is logged and left alone, and the slot fails to start rather than kill a stranger.

Without `WorkingDirectory`, systemd starts the process in `/` and the proxy tries to write
`/run` and `/certs`.

Two things to avoid:

- **Do not add `-d`/`--daemon`** to `ExecStart` under `Type=simple`. It forks and detaches, so
  systemd loses the process and restarts it in a loop. In the foreground the proxy's own log
  goes to the journal (`journalctl -u soli-proxy -f`).
- `SOLI_LOG_DIR` / `SOLI_PID_DIR` only affect `proxy.log` and `proxy.pid`, and `proxy.log` is
  only written on the `-d` path. They have **no effect** on the per-app `run/logs/` above.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for semantic release. Use the format `type(scope): description` (e.g. `feat(proxy): add retry`). Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.

Optional setup:

- **Commit template** (reminder in the message box):
  `git config commit.template .gitmessage`
- **Auto-fix non-conventional messages** (prepend `chore: ` if the first line doesn’t match):
  `cp scripts/git-hooks/prepare-commit-msg .git/hooks/prepare-commit-msg && chmod +x .git/hooks/prepare-commit-msg`

## License

MIT
