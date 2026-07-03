# syntax=docker/dockerfile:1
#
# Consumes the prebuilt release binary produced by the `build-binaries` CI job
# (soli-proxy-linux-<arch>.tar.gz on the GitHub release) instead of compiling
# from source. Built on ubuntu to match the release build environment so the
# dynamically linked binary's glibc/libssl expectations are satisfied.

FROM ubuntu:24.04 AS fetch
ARG REPO=solisoft/soli-proxy
# Release tag to install, e.g. v0.28.5. Empty -> resolve the latest release.
ARG VERSION=
# Populated automatically by BuildKit: "amd64" or "arm64".
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    if [ -z "${VERSION}" ]; then \
      VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 \
        | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"; \
    fi; \
    [ -n "${VERSION}" ] || { echo "could not resolve release version"; exit 1; }; \
    tarball="soli-proxy-linux-${TARGETARCH}.tar.gz"; \
    base="https://github.com/${REPO}/releases/download/${VERSION}"; \
    echo "Downloading ${base}/${tarball}"; \
    curl -fsSL "${base}/${tarball}" -o /tmp/soli-proxy.tar.gz; \
    curl -fsSL "${base}/${tarball}.sha256" -o /tmp/soli-proxy.sha256; \
    echo "$(cat /tmp/soli-proxy.sha256)  /tmp/soli-proxy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/soli-proxy.tar.gz -C /usr/local/bin soli-proxy; \
    chmod +x /usr/local/bin/soli-proxy

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r -s /bin/false soli-proxy && \
    mkdir -p /etc/soli-proxy/run /etc/soli-proxy/sites /etc/soli-proxy/certs && \
    chown -R soli-proxy:soli-proxy /etc/soli-proxy

COPY --from=fetch /usr/local/bin/soli-proxy /usr/local/bin/soli-proxy
COPY --from=fetch /usr/local/bin/soli-proxy /usr/local/bin/soli-proxy-backup

USER soli-proxy

EXPOSE 80 443 9090

ENTRYPOINT ["soli-proxy"]
CMD ["--config", "/etc/soli-proxy/config.toml"]
