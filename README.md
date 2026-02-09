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
- **High Performance**: Built on Tokio and Hyper for maximum throughput

## Quick Start

### Development Mode

```bash
# Build and run in dev mode
cargo run -- dev

# Or with custom config
SOLI_CONFIG_PATH=./proxy.conf cargo run -- dev
```

### Production Mode

```bash
# Build release
cargo build --release

# Run in production mode (requires Let's Encrypt config)
cargo run -- prod
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
│              Soli Proxy Server                       │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │ Config      │  │ TLS/HTTPS   │  │ HTTP/2+     │  │
│  │ Manager     │  │ Handler     │  │ Listener     │  │
│  │ (hot reload)│  │ (rcgen/LE)  │  │ (tokio/hyper)│  │
│  └─────────────┘  └─────────────┘  └──────────────┘  │
│         │                │               │          │
│         └────────────────┼───────────────┘          │
│                          │                          │
│                   ┌──────▼──────┐                   │
│                   │   Router    │                   │
│                   │ (matching)  │                   │
│                   └─────────────┘                   │
│                          │                          │
│         ┌────────────────┼────────────────┐        │
│         │                │                │        │
│    ┌────▼────┐     ┌─────▼─────┐     ┌────▼────┐   │
│    │ Auth    │     │ Rate      │     │ Logging │   │
│    │ Middle  │     │ Limit     │     │ JSON    │   │
│    └─────────┘     └───────────┘     └─────────┘   │
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
│   ├── config/           # Config parsing & hot reload
│   ├── server/           # HTTP/HTTPS server
│   ├── tls/              # TLS & certificate management
│   ├── router/           # Request routing & matching
│   ├── middleware/       # Auth, rate limiting, logging
│   ├── health/           # Health check endpoints
│   └── shutdown.rs       # Graceful shutdown
├── tests/                # Integration tests
└── scripts/              # Helper scripts
```

## Performance

- **HTTP/2 Multiplexing**: Single connection for multiple requests
- **Connection Pooling**: Reuse backend connections
- **Async I/O**: Tokio for non-blocking operations
- **Efficient Memory**: Minimal allocations, LRU caching
- **Zero-Copy**: Where possible, avoid body copies

## Hot Reload

Configuration changes are detected automatically:
1. File watcher monitors proxy.conf
2. On change, config is reloaded atomically
3. New connections use new config
4. Existing connections continue with old config
5. Graceful draining of old connections

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for semantic release. Use the format `type(scope): description` (e.g. `feat(proxy): add retry`). Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.

Optional setup:

- **Commit template** (reminder in the message box):  
  `git config commit.template .gitmessage`
- **Auto-fix non-conventional messages** (prepend `chore: ` if the first line doesn’t match):  
  `cp scripts/git-hooks/prepare-commit-msg .git/hooks/prepare-commit-msg && chmod +x .git/hooks/prepare-commit-msg`

## License

MIT
