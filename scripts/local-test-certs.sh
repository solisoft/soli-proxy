#!/usr/bin/env bash
# Make every *.test host on THIS machine serve a certificate this machine
# trusts. The Linux counterpart of regen-mkcert-and-deploy.sh, which mints on
# the Mac and ships to a remote proxy: here the CA, the certificates, the proxy
# and the browser are all the same box, so nothing leaves it.
#
# What it does:
#   1. creates the local mkcert CA if there is none, and installs it in the
#      NSS store (Chrome/Chromium/Brave/Firefox) and, with sudo, in the system
#      store that curl and the Rust/Node clients read;
#   2. mints one wildcard per .test parent domain actually in use, named the
#      way src/acme.rs looks them up (_wildcard.<parent>.{cert,key}.pem);
#   3. asks the running proxy to reload them, without dropping connections.
#
# Usage:
#   scripts/local-test-certs.sh              # mint, install, reload
#   scripts/local-test-certs.sh --no-system  # skip the sudo step
#
# .test resolution itself is not our business: dnsmasq answers
# address=/test/127.0.0.1 on 127.0.0.1:5353 and dns-test-domain.service points
# systemd-resolved's ~test routing domain at it. We only check it still holds.

set -euo pipefail

PROXY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="$PROXY_DIR/certs"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9090}"
WANT_SYSTEM=1
[ "${1:-}" = "--no-system" ] && WANT_SYSTEM=0

command -v mkcert >/dev/null || {
  echo "mkcert not found. Install it with: pacman -S mkcert" >&2
  exit 1
}

# --- 1. local CA ---------------------------------------------------------
CAROOT="$(mkcert -CAROOT)"
if [ ! -f "$CAROOT/rootCA.pem" ]; then
  echo "=== Creating the local CA ==="
  TRUST_STORES=nss mkcert -install
else
  # Idempotent: mkcert skips stores that already hold the CA.
  TRUST_STORES=nss mkcert -install >/dev/null 2>&1 || true
fi
echo "CA: $CAROOT/rootCA.pem"

# The system store is what curl, reqwest and Node read; the NSS store above is
# what the browsers read. Only the former needs root.
ANCHOR=/etc/ca-certificates/trust-source/anchors/mkcert-local-ca.crt
if [ "$WANT_SYSTEM" = 1 ] && ! cmp -s "$CAROOT/rootCA.pem" "$ANCHOR" 2>/dev/null; then
  echo "=== Installing the CA in the system trust store (needs root) ==="
  if sudo -n true 2>/dev/null || [ -t 0 ]; then
    sudo install -m644 "$CAROOT/rootCA.pem" "$ANCHOR"
    sudo update-ca-trust
  else
    echo "  no tty and no cached sudo — run these two lines yourself:" >&2
    echo "    sudo install -m644 $CAROOT/rootCA.pem $ANCHOR" >&2
    echo "    sudo update-ca-trust" >&2
  fi
fi

# --- 2. which names to cover --------------------------------------------
# In --dev the proxy answers for more than the hosts a site declares: it
# registers a `.test` alias for every app by swapping the TLD, so
# soli.solisoft.net is also soli.solisoft.test. That derivation is
# `dev_domain()` in src/app/mod.rs, and this mirrors it — otherwise a parent
# like epiks.test, which no site names but several apps alias into, ends up
# without a certificate.
known_hosts() {
  {
    grep -hoE '^[[:space:]]*(name|domain)[[:space:]]*=[[:space:]]*"[^"]+"' \
      "$PROXY_DIR"/sites/*/app.infos 2>/dev/null |
      sed -E 's/.*"([^"]+)"/\1/'
    (cd "$PROXY_DIR/sites" 2>/dev/null && ls -d *.*/ 2>/dev/null | tr -d /) || true
  } | awk '
    /\.localhost$/ { next }                       # never aliased
    /\.test$/      { print; next }                # already one
    /\./           { sub(/\.[^.]+$/, ".test"); print }
  '
}

# A wildcard matches one label (RFC 6125, and src/acme.rs implements exactly
# that), so *.solisoft.test covers grc.solisoft.test but not a.b.solisoft.test.
# Cover the parent of every known host, and keep the parents we already hold a
# certificate for even when no site declares them today.
mapfile -t PARENTS < <(
  {
    known_hosts
    (cd "$CERTS_DIR" 2>/dev/null && ls _wildcard.*.test.cert.pem 2>/dev/null) |
      sed -E 's/^_wildcard\.(.*)\.cert\.pem$/x.\1/'
  } |
    awk '{ if ($0 == "test") { print; next } n = index($0, "."); if (n) print substr($0, n + 1) }' |
    grep -E '\.test$|^test$' | sort -u
)

# There is deliberately no `*.test`: a wildcard sitting directly under the TLD
# is refused by OpenSSL and by browsers (mkcert warns when minting one), so it
# would look like coverage while serving nothing. A one-label host such as
# `pdfx.test` gets its own exact certificate instead — which the resolver
# prefers over any wildcard anyway. Deeper hosts need nothing here, their
# parent's wildcard has them.
mapfile -t EXACT < <(known_hosts | grep -E '^[^.]+\.test$' | sort -u)

[ "${#PARENTS[@]}" -gt 0 ] || { echo "No .test domain found." >&2; exit 1; }

# --- 3. mint -------------------------------------------------------------
mkdir -p "$CERTS_DIR"
echo
echo "=== Minting into $CERTS_DIR ==="
mint() { # mint <basename> <name>...
  local base="$1"; shift
  mkcert -cert-file "$CERTS_DIR/$base.cert.pem" \
         -key-file "$CERTS_DIR/$base.key.pem" "$@" 2>&1 | sed 's/^/  /'
  chmod 600 "$CERTS_DIR/$base.key.pem"
  chmod 644 "$CERTS_DIR/$base.cert.pem"
}
for parent in "${PARENTS[@]}"; do
  mint "_wildcard.$parent" "*.$parent" "$parent"
done
for host in "${EXACT[@]}"; do
  mint "$host" "$host"
done

# --- 4. reload -----------------------------------------------------------
echo
echo "=== Reloading the proxy ==="
# The admin API rejects mutations without X-Requested-With: a cross-origin
# fetch that sets it is forced into a preflight, and OPTIONS answers 405.
if curl -fsS -X POST -H 'X-Requested-With: local-test-certs' \
     "$ADMIN_URL/api/v1/certs/reload" >/dev/null 2>&1; then
  echo "  reloaded through the admin API, no connection dropped"
else
  echo "  admin API unreachable at $ADMIN_URL — restart the proxy to pick them up" >&2
fi

# --- 5. verify -----------------------------------------------------------
echo
echo "=== Verifying ==="
if ! getent hosts nonexistent-probe.test | grep -q '^127\.0\.0\.1'; then
  echo "  WARNING: *.test does not resolve to 127.0.0.1." >&2
  echo "  Check: systemctl status dnsmasq dns-test-domain.service" >&2
fi
check() { # check <hostname>
  local host="$1" live
  live="$(mktemp)"
  echo | openssl s_client -servername "$host" -connect 127.0.0.1:443 -showcerts 2>/dev/null |
    awk '/BEGIN CERT/,/END CERT/' > "$live"
  if [ -s "$live" ] &&
     openssl verify -CAfile "$CAROOT/rootCA.pem" -verify_hostname "$host" "$live" >/dev/null 2>&1
  then
    echo "  OK   $host"
  else
    echo "  FAIL $host" >&2
  fi
  rm -f "$live"
}
# One probe per wildcard, then every hostname the proxy will actually be asked
# for — the wildcards are the mechanism, the hostnames are the promise.
for parent in "${PARENTS[@]}"; do check "probe.$parent"; done
while read -r host; do check "$host"; done < <(known_hosts | sort -u)

echo
echo "Restart the browser once: it reads the NSS store at startup."
