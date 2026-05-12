# Soli Proxy

A high-performance, production-ready forward proxy server built in Rust with HTTP/2+ support, automatic HTTPS, and hot config reload.

## Features

- **HTTP/2+ Support**: Native HTTP/2 with automatic fallback to HTTP/1.1
- **Automatic HTTPS**: Self-signed certificates for development, Let's Encrypt for production
- **Hot Config Reload**: Update configuration without dropping connections
- **Simple Configuration**: Custom config format with comments support
- **Load Balancing**: Round-robin, weighted, and health-checked backends
- **WebSocket Support**: Full WebSocket proxy capabilities
- **Middleware**: Authentication (Basic, API Key, JWT), Rate Limiting, JSON Logging
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
  -c, --conf <CONF>            Config file [default: ./proxy.conf]
  -d, --daemon                 Run as daemon
      --dev                    Development mode
      --watch <WATCH>          Watch config & sites for changes [default: true]
      --sites-dir <SITES_DIR>  Sites directory [default: ./sites]
  -h, --help                   Print help
  -V, --version                Print version
```

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
soli-proxy update [--reinstall]                          # Self-update from GitHub releases
```

## Configuration

### Main Config (config.toml)

```toml
[server]
bind = "0.0.0.0:8080"
https_port = 8443
worker_threads = "auto"

[tls]
mode = "auto"  # "auto" for dev, "letsencrypt" for production

[letsencrypt]
email = "admin@example.com"
staging = false

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
endpoint = "/metrics"

[health]
enabled = true
liveness_path = "/health/live"
readiness_path = "/health/ready"

[rate_limiting]
enabled = true
requests_per_second = 1000
burst_size = 2000
```

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

### Proxy Rules (proxy.conf)

```proxy
# Comments are supported
default -> http://localhost:3000

/api/* -> http://localhost:8080
/ws -> ws://localhost:9000

# Load balancing
/api/* -> http://10.0.0.10:8080, http://10.0.0.11:8080, http://10.0.0.12:8080

# Weighted routing
/api/heavy -> weight:70 http://heavy:8080, weight:30 http://light:8080

# Regex routing
~^/users/(\d+)$ -> http://user-service:8080/users/$1

# Headers to add
headers {
    X-Forwarded-For: $client_ip
    X-Forwarded-Proto: $scheme
}

# Authentication
/auth/* {
    auth: basic
    realm: "Restricted"
}
```

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

## Command Line Options

```bash
soli-proxy [dev|prod] [OPTIONS]

Modes:
  dev   Development mode with self-signed certificates
  prod  Production mode with Let's Encrypt support

Environment Variables:
  SOLI_CONFIG_PATH    Path to proxy.conf (default: ./proxy.conf)
```

## Project Structure

```
soli-proxy/
├── Cargo.toml
├── config.toml           # Main configuration
├── proxy.conf            # Proxy rules
├── src/
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library root
│   ├── bin/
│   │   ├── httptest.rs   # End-to-end proxy throughput test
│   │   └── hash-password.rs
│   ├── config/           # Config parsing & hot reload
│   ├── server/           # HTTP/HTTPS server
│   ├── admin/            # Admin API server
│   ├── acme/             # ACME / Let's Encrypt
│   ├── tls.rs            # TLS & certificate management
│   ├── circuit_breaker.rs
│   ├── metrics.rs        # Prometheus-format metrics
│   ├── pool.rs           # Connection pool
│   ├── auth.rs           # Authentication
│   ├── app/              # App management & blue-green deploy
│   └── shutdown.rs       # Graceful shutdown
├── benches/
│   ├── routing.rs        # Rule matching & scaling benchmarks
│   ├── components.rs     # Circuit breaker, load balancer, metrics
│   └── config_parsing.rs # Config file parsing benchmarks
└── scripts/              # Helper scripts
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

Configuration changes are detected automatically:
1. File watcher monitors proxy.conf
2. On change, config is reloaded atomically
3. New connections use new config
4. Existing connections continue with old config
5. Graceful draining of old connections

## App Health Monitoring

When apps are managed by the proxy (via `./sites` directory), the proxy automatically:
- Checks app health every 30 seconds via each app's configured health endpoint (default: `/`)
- Auto-restarts any app that fails the health check (connection refused, timeout, etc.)
- Only restarts on actual failures, not on non-2xx responses

### Health Check Configuration

Each app can configure its own health check path in `app.infos`:

```toml
[apps]
[apps.myapp.example.org]
health_check = "/health"
```

The global default health check path is `/`.

## Systemd Service

Install soli-proxy as a systemd service for automatic restart on failure:

```bash
# Copy the service file
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

The service file is located at `scripts/soli-proxy.service`.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for semantic release. Use the format `type(scope): description` (e.g. `feat(proxy): add retry`). Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.

Optional setup:

- **Commit template** (reminder in the message box):
  `git config commit.template .gitmessage`
- **Auto-fix non-conventional messages** (prepend `chore: ` if the first line doesn’t match):
  `cp scripts/git-hooks/prepare-commit-msg .git/hooks/prepare-commit-msg && chmod +x .git/hooks/prepare-commit-msg`

## License

MIT
