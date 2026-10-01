# Soli Proxy

A high-performance reverse proxy built in Rust, with HTTP/2 support, automatic HTTPS, hot config
reload, Lua scripting, and blue-green deploys for the apps it hosts.

## Features

- **HTTP/2+ Support**: Native HTTP/2 with automatic fallback to HTTP/1.1
- **Automatic HTTPS**: Self-signed certificates for development, Let's Encrypt for production
- **Hot Config Reload**: Routing rules swap atomically, without dropping connections (see [Hot Reload](#hot-reload) for what needs a restart)
- **Simple Configuration**: Custom config format with comments support
- **Load Balancing**: Round-robin, weighted and failover, with a per-backend circuit breaker
- **WebSocket Support**: Full WebSocket proxy capabilities, with idle/lifetime/size limits
- **Middleware**: HTTP Basic auth (per route, per app, admin API), per-IP rate limiting, request header rules, Lua hooks, JSON or text logging
- **Not included**: JWT/OIDC or API-key auth for proxied routes — use a Lua `on_request` hook or the backend
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
soli-proxy logs    [-c <conf>] <app_name>   # Print deployment logs for both slots
```

Other subcommands:

```
soli-proxy tui [-c <conf>] [--sites-dir <DIR>] [--dev]   # Interactive terminal UI
soli-proxy update [--reinstall] [--allow-unverified]     # Self-update from GitHub releases
soli-proxy hash-password [--cost N]                      # bcrypt hash for @auth / [auth.users] / ADMIN_PASSWORD_HASH
```

`hash-password` prompts twice without echo (or reads the first line of stdin when it is not a
terminal — `echo "$PW" | soli-proxy hash-password`), prints only the hash on stdout, and never
takes the password from the command line. `--cost` defaults to 12 and is bounded to 4–13: the
proxy refuses hashes outside that range (see "How Basic Auth is checked"). The standalone
`hash-password` binary shipped next to `soli-proxy` does the same, and the admin API offers it as
`POST /api/v1/hash-password` (`{"password": "..."}`).

The TUI is a separate process: traffic metrics and circuit-breaker state come from the running
proxy's admin API (`/api/v1/metrics`, `/api/v1/app-metrics`, `/api/v1/circuit-breaker`), and
show as unavailable — never as an empty list — when it cannot be reached. It authenticates with
`[admin].api_key` when set; otherwise, with admin Basic auth (`ADMIN_USER` + hash), the
password typed at its login prompt is reused as the Basic credential, and it polls every 5 s
instead of every second because each request costs the daemon a bcrypt check.

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
max_connections = 10000   # simultaneous client connections; further ones wait to be accepted
max_request_size = "10MB" # request bodies above this get 413
keep_alive_timeout = 30   # seconds to receive a request's headers (closes idle keep-alives)
request_timeout = 60      # seconds for the upstream exchange before a 504 (default 60)
websocket_idle_timeout_secs = 300           # close a forwarded WebSocket silent this long
websocket_max_lifetime_secs = 3600          # absolute cap per WebSocket
websocket_max_bytes_per_direction = 1073741824

[scripting]
enabled = true
scripts_dir = "./scripts/lua"   # cors.lua, logging.lua, rate_limit.lua ship here
hook_timeout_ms = 10
exposed_env = ["BACKEND_TOKEN"] # the only variables Lua's `env` module can read
```

`[tls] force_https` (default `true`) answers plaintext requests for hosts the proxy serves with
a `308` to `https://`. The full key-by-key reference is on the
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

Resolution order on a TLS handshake: exact-match `certs/<sni>.cert.pem` → wildcard `certs/_wildcard.<parent>.cert.pem` (one label deep) → self-signed fallback. Cert files are scanned **once at startup** — `SIGUSR1` and the admin reload endpoint only refresh routing, so adding/replacing a cert file requires a full proxy restart.

For local dev with [mkcert](https://github.com/FiloSottile/mkcert) — install the local CA on your machine (`mkcert -install`) and drop wildcard certs in:

```bash
mkcert "*.example.test"
mv _wildcard.example.test.pem      ./certs/_wildcard.example.test.cert.pem
mv _wildcard.example.test-key.pem  ./certs/_wildcard.example.test.key.pem
```

After restart, every `*.example.test` alias is served with a Mac/Linux-trusted cert (no browser warning).

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
```

#### How Basic Auth is checked

- **bcrypt never runs on the request workers.** Each check goes to a blocking pool bounded to
  half the cores (at least two), so a flood of wrong passwords costs at most that share of the
  CPU and every other site keeps answering. When no slot frees up within a second the request
  gets **`503` with `Retry-After: 1`** rather than queueing without bound (not 401: the client
  did nothing wrong, and a browser would prompt for a password it already has).
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

### What reaches the backend

- **Forwarding headers come from the proxy, never the client.** Any `Forwarded`,
  `X-Forwarded-*` or `X-Real-IP` the client sent is dropped, then `X-Forwarded-For` and
  `X-Real-IP` (the connecting address), `X-Forwarded-Proto` and `X-Forwarded-Host` (the
  Host the client asked for) are set — on rule routes, app domains and WebSocket
  upgrades alike, before any Lua script sees the request.
- **Hop-by-hop headers are removed at the door**, including every header the client
  names in `Connection`, so a client cannot use `Connection: x-user` to delete a header
  a script set.
- **Malformed requests are refused up front**: `CONNECT` (405), authority-form and
  asterisk-form targets (400; `OPTIONS *` is answered directly), more than one `Host`
  header, or on HTTP/2 a `Host` that differs from `:authority` (400).
- **WebSocket upgrades run the route's Lua hooks** (`on_request`, `on_route`) like any
  other request, and an open tunnel keeps counting against the connection limits.

### Connection limits

```toml
[limits]
max_connections = 10000        # whole process
max_connections_per_ip = 256   # per client address (IPv6: per /64); 0 = off
keep_alive_timeout = 30        # header read / idle keep-alive (HTTP/1), idle (HTTP/2)
```

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

Comma-separated URLs (`http://`, `https://`, `ws://`, `redirect://`), each optionally preceded by
`weight:N`. A line ending in `\` continues on the next one. After a stripped prefix, the rest of
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
| `@noauth:/path,/prefix/*` | Paths on a protected rule served without credentials. |

Every target is also tracked by the circuit breaker (`[circuit_breaker]`): a target whose
breaker is open is skipped by every strategy, and a rule whose targets are all open answers 503.

#### `headers { }` blocks

A `headers {` line opens a block that applies to the **rule right above it**, closed by `}` on a
line of its own. Each line is either `Name: value`, which sets the header on the request sent
upstream (replacing whatever the client sent), or `-Name`, which removes it. The block is applied
after the proxy has set `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, so it can
override or remove those too. Values may use:

| Variable | Value |
|---|---|
| `$client_ip` | The TCP peer's address (never a client-supplied header). |
| `$scheme` | `http` or `https`, as the client connected. |
| `$host` | The host the request was routed on, without port. |

`$$` is a literal `$`. Hop-by-hop and framing headers (`Connection`, `Keep-Alive`,
`Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Content-Length`, `Proxy-Connection`) cannot
be set. Blocks apply to proxied HTTP requests; WebSocket upgrades and app-managed domains are
not affected.

#### Errors

A line the parser does not understand is an error naming its line number — an unknown
directive, an invalid `weight:`, a malformed `@auth` entry, an unknown `@lb` strategy, a script
name that is not a plain `*.lua` file, an unterminated `headers` block. At startup that is fatal;
on a hot reload the previous configuration stays in force and the error is logged. (Earlier
versions skipped such lines, which could silently drop a route or the `@auth` protecting it.)

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
│   ├── main.rs               # CLI, startup, signals, self-update, hash-password
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
│   ├── acme.rs               # ACME / Let's Encrypt, certificate resolver, rustls config
│   ├── tls.rs                # Certificate loading and the TLS server config
│   ├── logging.rs            # [logging]: subscriber, non-blocking writer, rotation
│   ├── circuit_breaker.rs
│   ├── metrics.rs            # Prometheus-format metrics
│   ├── pool.rs               # Upstream connection pool
│   ├── proxy_headers.rs      # Hop-by-hop stripping, cookie coalescing, Origin rewrite
│   └── shutdown.rs           # Graceful shutdown
├── tests/                    # Integration tests (admin auth, routing, Lua scripts)
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
`[logging]` `level`/`format`/`output`. Per-request settings — routes, `force_https`, HSTS,
timeouts, body-size limit, `log_endpoints`, admin credentials — take effect on the next request.

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

# Optional: HTTP Basic Auth on this app's domains.
[auth]
noauth = ["/webhooks/stripe", "/hooks/*"]

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
| `idle_timeout` | int (seconds) | `[apps].idle_timeout` from `config.toml`, itself `0` | Scale to zero: after this many seconds without a request the proxy stops the app and starts it again on the next one, holding that request until the app is healthy. `0` means the app never sleeps. See [Scale to zero](#scale-to-zero). |
| `[auth.users]` | table | _empty_ | `username = "bcrypt hash"` entries. When non-empty, every request to this app's domains must present matching HTTP Basic Auth credentials. Generate a hash with `hash-password`; only bcrypt hashes at cost 4 to 13 are accepted. |
| `[auth] noauth` | list of strings | _empty_ | Paths served without credentials, for callers that cannot send a password (a payment webhook, a health probe). Exact path, or a prefix ending in `*` — the same syntax as the `@noauth:` route directive, and the same fail-closed rule: a path carrying percent-encoding or a `..` segment is never exempt. |

Apps are routed by the app manager rather than by `proxy.conf` rules — `sync_routes` prunes
static rules for app-managed domains — so a route's `@auth` cannot protect an app. `[auth]` is
the equivalent for apps, and it covers the app's derived domains (`www.`-stripped, `.test` in
dev) and any admin-managed alias pointing at it. A `[auth]` section the proxy cannot enforce as
written (an empty or malformed hash, a bcrypt cost outside 4–13, a `noauth` pattern that does
not compare literally) makes the app fail to load and be skipped, rather than come up
unprotected.

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
in memory for nothing. `idle_timeout` lets the proxy put such an app to sleep —
stop its process — and start it again on the next request.

```toml
# app.infos
idle_timeout = 900   # sleep after 15 minutes without a request
```

What happens:

- Every request the proxy routes to an app resets that app's idle clock.
- A reaper runs every 30 s. An app past its threshold is stopped the same way
  `soli-proxy stop` stops it, so the exit is not mistaken for a crash — no
  failover, no quarantine.
- The next request for one of its domains is **held** while the app is started
  on its current slot and polled for health, then forwarded as usual. A Soli app
  boots in a few hundred milliseconds, so the first visitor waits about a
  second; everyone else finds it running. Concurrent first requests share one
  start.
- A sleeping app keeps its certificate registered and keeps winning over
  static `proxy.conf` rules for its domains, exactly as a running one does.
- `soli-proxy restart <app>` or a deploy wakes it too, and resets the clock.

The default is `0` — never sleep — and that is the right value for anything
that does work without being asked: cron jobs, background workers, WebSocket
rooms, a warm cache that takes more than a moment to rebuild. Set a threshold
only on apps whose whole life is answering requests. `_admin` never sleeps
regardless of its manifest. A fleet-wide default goes in `config.toml`:

```toml
[apps]
idle_timeout = 1800   # apps that don't say otherwise sleep after 30 minutes
```

An app that must stay up under a fleet-wide default says so with
`idle_timeout = 0` in its own `app.infos`.

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
  the app that is actually served.
- Slot ports come from the platform range (`[apps] port_range_start`/`port_range_end`); an
  app's own `port_range_*` is ignored. In every mode a range is refused if it reaches below
  1024 or covers one of the proxy's listeners.
- Each app gets a **private Docker network**, `soli-app-<name>`, created with inter-container
  traffic disabled (`com.docker.network.bridge.enable_icc=false`) and a host bridge named
  `sl-<12 hex digits>`. The tenant's `docker_network` is ignored. When a site directory is
  removed, its containers are stopped and its network removed.
- Containers are stopped with `docker stop` + `docker rm -f` **by name**, never by signalling
  the PID docker reports, which left the container (and its restart policy) behind.

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
| GET | `/api/v1/app-metrics`, `/api/v1/app-metrics/system`, `/api/v1/apps/{name}/metrics` | Per-app traffic, memory and CPU |
| GET | `/api/v1/events/apps` | Server-Sent Events: app deploys, status changes, quarantine |
| GET | `/api/v1/apps`, `/api/v1/apps/{name}`, `/api/v1/apps/by-domain` | Managed apps |
| POST | `/api/v1/apps/{name}/deploy` \| `restart` \| `rollback` \| `stop` | App lifecycle |
| GET | `/api/v1/apps/{name}/logs` | Deployment logs |
| GET / POST / DELETE | `/api/v1/aliases`, `/api/v1/apps/{name}/aliases[/{domain}]` | Domain aliases |
| GET / POST | `/api/v1/circuit-breaker`, `/api/v1/circuit-breaker/reset` | Circuit-breaker state / reset |
| GET / PUT | `/api/v1/routing-table` | Cluster-pushed routes (complete set, increasing `index`; a stale push gets 409) |
| GET / PUT | `/api/v1/acme-challenges` | HTTP-01 tokens pushed by an external ACME orderer |
| POST | `/api/v1/hash-password` | `{"password": ...}` → bcrypt hash |
| GET / PUT | `/api/v1/settings` | Admin UI settings (`{"theme": ...}`) |

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
- **Ten failed authentications per client IP per minute**, then `429` with `Retry-After` until
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
  paths), may only name domains present in `routes`, and is replaced along with them. A pushed
  domain without `auth` is served unprotected. `GET /api/v1/routing-table` returns usernames and
  `noauth`, never hashes.

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

### Privileges

The unit runs the proxy as the `soli-proxy` user with a single capability,
`CAP_NET_BIND_SERVICE` (granted by `AmbientCapabilities=`, so no `setcap` on the binary and
nothing for an upgrade to drop), under `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp` and the usual kernel protections. Native apps are children of the
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

These files, and `proxy.conf` when the proxy rewrites it, are written atomically (temporary
file, `fsync`, rename), so a crash or a full disk leaves the previous version rather than a
truncated one.

`spawned.json` is what lets a restarted proxy clean up after itself without collateral damage.
At startup, a slot's port that is still held is reclaimed only if the process holding it — or
the process group it belongs to — is one the proxy recorded spawning, *with the same start
time* (a PID alone is reused). Anything else on the port is logged and left alone, and the
slot fails to start rather than kill a stranger.
| `/var/lib/soli-proxy/certs/` | TLS cache, when `[tls].cache_dir` is `./certs` |

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
