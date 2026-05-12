#!/usr/bin/env bash
# Run on the Mac. Diagnoses why curl --cacert "$(mkcert -CAROOT)/rootCA.pem"
# fails with "bad signature" against the soli proxy's wildcard cert.
set -u

PROXY_HOST="${PROXY_HOST:-192.168.1.30}"
SNI="${SNI:-soli.solisoft.test}"
EXPECTED_FP="B8:D7:C8:60:6C:B7:21:2A:34:3C:AE:CC:14:99:77:08:58:69:63:11:60:BA:47:C3:E7:A3:30:4E:4B:5E:B0:30"

echo "=== 1. Cert the proxy is currently serving for $SNI ==="
LIVE=$(echo | openssl s_client -servername "$SNI" -connect "$PROXY_HOST:443" 2>/dev/null \
       | openssl x509 -noout -fingerprint -sha256 -issuer 2>&1)
echo "$LIVE"
echo
echo "Expected fingerprint (cert on Linux disk): $EXPECTED_FP"
echo

echo "=== 2. Mac mkcert -CAROOT ==="
CAROOT="$(mkcert -CAROOT)"
echo "CAROOT=$CAROOT"
ls -la "$CAROOT"
echo

echo "=== 3. Mac rootCA fingerprint + subject ==="
openssl x509 -in "$CAROOT/rootCA.pem" -noout -subject -fingerprint -sha256
echo

echo "=== 4. Pull live cert and verify against Mac rootCA ==="
LIVE_PEM=$(mktemp)
echo | openssl s_client -servername "$SNI" -connect "$PROXY_HOST:443" -showcerts 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > "$LIVE_PEM"
openssl verify -CAfile "$CAROOT/rootCA.pem" "$LIVE_PEM"
echo
echo "(live cert at $LIVE_PEM)"
