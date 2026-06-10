#!/usr/bin/env bash
# Boot a portico server with a throwaway self-signed cert and run the TLS test
# (HTTPS + WSS). tls_test.sh <server-binary>
set -euo pipefail

BIN="${1:?usage: tls_test.sh <server-binary>}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

export TLS_CERT="$TMP/cert.pem" TLS_KEY="$TMP/key.pem"
exec python3 "$DIR/tests/run_with_server.py" "$BIN" "$DIR/tests/tls_test.py"
