#!/bin/bash
# Development script to generate self-signed certificates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs/localhost"

mkdir -p "$CERTS_DIR"

echo "Generating RSA private key..."
openssl genrsa -out "$CERTS_DIR/key.pem" 2048

echo "Generating self-signed certificate..."
openssl req -new -x509 \
    -key "$CERTS_DIR/key.pem" \
    -out "$CERTS_DIR/cert.pem" \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Soli Proxy/CN=localhost"

echo "Converting to DER format for Rust..."
openssl x509 -outform DER -in "$CERTS_DIR/cert.pem" -out "$CERTS_DIR/cert.der"
openssl rsa -outform DER -in "$CERTS_DIR/key.pem" -out "$CERTS_DIR/key.der"

echo "Certificates generated in $CERTS_DIR"
echo "  cert.pem (PEM format for servers)"
echo "  key.pem (PEM format for servers)"
echo "  cert.der (DER format for Rust)"
echo "  key.der (DER format for Rust)"
