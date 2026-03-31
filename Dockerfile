FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

RUN cargo build --release && strip target/release/soli-proxy

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r -s /bin/false soli-proxy && \
    mkdir -p /etc/soli-proxy/run /etc/soli-proxy/sites /etc/soli-proxy/certs && \
    chown -R soli-proxy:soli-proxy /etc/soli-proxy

COPY --from=builder /app/target/release/soli-proxy /usr/local/bin/soli-proxy
COPY --from=builder /app/target/release/soli-proxy /usr/local/bin/soli-proxy-backup

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

USER soli-proxy

EXPOSE 80 443 9090

ENTRYPOINT ["soli-proxy"]
CMD ["--config", "/etc/soli-proxy/config.toml"]
