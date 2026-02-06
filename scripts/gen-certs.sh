#!/bin/bash
# Generate self-signed CA, server and agent certificates for TrueID mTLS.
#
# Usage:
#   ./scripts/gen-certs.sh                      # all certs in ./certs/
#   ./scripts/gen-certs.sh agent DC01.contoso.local  # additional agent cert
set -euo pipefail

CERT_DIR="${CERT_DIR:-./certs}"
mkdir -p "$CERT_DIR"

generate_ca() {
    echo "==> Generating CA certificate"
    openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
        -keyout "$CERT_DIR/ca-key.pem" \
        -out "$CERT_DIR/ca.pem" \
        -subj "/CN=TrueID Internal CA"
    echo "    CA cert:  $CERT_DIR/ca.pem"
    echo "    CA key:   $CERT_DIR/ca-key.pem"
}

generate_server() {
    echo "==> Generating server certificate"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/server-key.pem" \
        -out "$CERT_DIR/server.csr" \
        -subj "/CN=trueid-server"
    openssl x509 -req \
        -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/server.pem" -days 365
    rm -f "$CERT_DIR/server.csr"
    echo "    Server cert: $CERT_DIR/server.pem"
    echo "    Server key:  $CERT_DIR/server-key.pem"
}

generate_agent() {
    local cn="${1:-agent}"
    local prefix
    prefix="$(echo "$cn" | tr '.' '-' | tr '[:upper:]' '[:lower:]')"
    echo "==> Generating agent certificate (CN=$cn)"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/${prefix}-key.pem" \
        -out "$CERT_DIR/${prefix}.csr" \
        -subj "/CN=$cn"
    openssl x509 -req \
        -in "$CERT_DIR/${prefix}.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/${prefix}.pem" -days 365
    rm -f "$CERT_DIR/${prefix}.csr"
    echo "    Agent cert: $CERT_DIR/${prefix}.pem"
    echo "    Agent key:  $CERT_DIR/${prefix}-key.pem"
}

if [ "${1:-}" = "agent" ]; then
    generate_agent "${2:?Usage: $0 agent <CN>}"
else
    generate_ca
    generate_server
    generate_agent "agent"
    echo ""
    echo "Done. Files in $CERT_DIR/"
fi
