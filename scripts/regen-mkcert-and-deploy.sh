#!/usr/bin/env bash
# Run on the Mac. Regenerates the three wildcard mkcert certs against the
# CURRENT mkcert -CAROOT, scps them to the proxy host, and restarts the
# proxy so it picks them up (cert files are only loaded at startup).
#
# Required:
#   PROXY_SSH    ssh destination for the Linux proxy host (e.g. user@192.168.1.30)
# Optional:
#   PROXY_DIR    remote path to the proxy repo (default: workspace/soli/proxy)

set -euo pipefail

PROXY_SSH="${PROXY_SSH:-olivier.bonnaure@delupay.com@192.168.1.30}"
PROXY_DIR="${PROXY_DIR:-/home/olivier.bonnaure@delupay.com/workspace/soli/proxy}"
PROXY_HOST="${PROXY_HOST:-192.168.1.30}"
export PROXY_DIR PROXY_HOST

PARENTS=(solisoft.test delupay.test letelegraphe.test)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "Using mkcert CAROOT: $(mkcert -CAROOT)"
echo

for parent in "${PARENTS[@]}"; do
  cert="_wildcard.${parent}.cert.pem"
  key="_wildcard.${parent}.key.pem"
  echo "=== Generating $cert (covers *.$parent and $parent) ==="
  mkcert -cert-file "$cert" -key-file "$key" "*.${parent}" "${parent}"
  echo
done

echo "=== Copying to ${PROXY_SSH}:${PROXY_DIR}/certs/ ==="
scp _wildcard.*.cert.pem _wildcard.*.key.pem "${PROXY_SSH}:${PROXY_DIR}/certs/"

echo
echo "=== Restarting proxy on ${PROXY_SSH} ==="
ssh "$PROXY_SSH" bash -s -- "$PROXY_DIR" <<'REMOTE'
set -e
cd "$1"
if [ -f proxy.pid ]; then
  pid=$(cat proxy.pid)
  if kill -0 "$pid" 2>/dev/null; then
    echo "Killing existing proxy (pid $pid)"
    kill "$pid"
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
  fi
  rm -f proxy.pid
fi
echo "Starting proxy: soli-proxy --dev -d"
soli-proxy --dev -d
sleep 1
echo "New pid: $(cat proxy.pid 2>/dev/null || echo '?')"
REMOTE

echo
echo "=== Verifying ==="
echo | openssl s_client -servername soli.solisoft.test \
       -connect "${PROXY_HOST:-192.168.1.30}:443" 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 -issuer

echo
echo "Verify against current Mac CA (must say 'OK'):"
LIVE_PEM=$(mktemp)
echo | openssl s_client -servername soli.solisoft.test \
       -connect "${PROXY_HOST:-192.168.1.30}:443" -showcerts 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > "$LIVE_PEM"
openssl verify -CAfile "$(mkcert -CAROOT)/rootCA.pem" "$LIVE_PEM"
rm -f "$LIVE_PEM"
