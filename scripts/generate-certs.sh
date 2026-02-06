#!/bin/bash
# Generate self-signed certificates for the proxy

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificates generated:"
echo "  cert.pem - Certificate"
echo "  key.pem - Private key"
