#!/usr/bin/env bash
# Local ACME end-to-end against Pebble (Let's Encrypt's test CA), fully offline.
#
# Stands up pebble + pebble-challtestsrv on loopback, then runs the driver which
# drives portico's ACME manager to issue a real (test-CA) certificate: account →
# order → HTTP-01 (Pebble's VA fetches the token from our responder) → finalize →
# download → verify. Self-SKIPS (exit 0) if the tools aren't installed, so it never
# blocks a normal build.
#
# Install once with:
#   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
#   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
set -u

DRIVER="${1:?usage: acme_pebble_test.sh <acme_pebble_e2e binary>}"

PEBBLE="${PEBBLE_BIN:-$(command -v pebble || echo "$HOME/go/bin/pebble")}"
CHALL="${CHALLTESTSRV_BIN:-$(command -v pebble-challtestsrv || echo "$HOME/go/bin/pebble-challtestsrv")}"

# Pebble's test certs (its API TLS cert + the root we must trust) ship in the module
# cache; allow an explicit override via PEBBLE_ASSETS (a .../test/certs dir).
ASSETS="${PEBBLE_ASSETS:-}"
if [ -z "$ASSETS" ]; then
    GOMOD="$(go env GOMODCACHE 2>/dev/null || echo "$HOME/go/pkg/mod")"
    ASSETS="$(ls -d "$GOMOD"/github.com/letsencrypt/pebble/v2@*/test/certs 2>/dev/null | sort -V | tail -1)"
fi

if [ ! -x "$PEBBLE" ] || [ ! -x "$CHALL" ] || [ -z "$ASSETS" ] || [ ! -f "$ASSETS/pebble.minica.pem" ]; then
    echo "acme_pebble: SKIPPED (pebble / pebble-challtestsrv / test certs not found)"
    exit 0
fi

DOMAIN="portico-pebble.test"
TMP="$(mktemp -d)"
cleanup() {
    [ -n "${PEBBLE_PID:-}" ] && kill "$PEBBLE_PID" 2>/dev/null
    [ -n "${CHALL_PID:-}" ]  && kill "$CHALL_PID"  2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# Pebble config with absolute paths to the cached test cert/key. httpPort 5002 is the
# port Pebble's validation authority connects to on the target domain — our responder
# listens there.
cat > "$TMP/config.json" <<EOF
{ "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "$ASSETS/localhost/cert.pem",
    "privateKey": "$ASSETS/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": ""
} }
EOF

# challtestsrv: only the mock DNS (defaults every A query to 127.0.0.1). Disable its
# own challenge servers so :5002 is free for our responder.
"$CHALL" -dnsserver :8053 -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    >"$TMP/chall.log" 2>&1 &
CHALL_PID=$!

# Pebble points its resolver at challtestsrv. NOSLEEP/NONCEREJECT make it fast+
# deterministic (we test badNonce retry separately; here we want a clean run).
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE" -config "$TMP/config.json" -dnsserver 127.0.0.1:8053 \
    >"$TMP/pebble.log" 2>&1 &
PEBBLE_PID=$!

# Wait for Pebble's directory to come up.
up=0
for _ in $(seq 1 50); do
    if curl -sk "https://localhost:14000/dir" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.2
done
if [ "$up" -ne 1 ]; then
    echo "FAIL: pebble did not start"; echo "--- pebble.log ---"; tail -30 "$TMP/pebble.log"
    exit 1
fi

PEBBLE_DIR="https://localhost:14000/dir" \
PEBBLE_CA="$ASSETS/pebble.minica.pem" \
PEBBLE_DOMAIN="$DOMAIN" \
PEBBLE_CHALLENGE_PORT=5002 \
    "$DRIVER"
RC=$?

if [ "$RC" -ne 0 ]; then
    echo "--- pebble.log (tail) ---"; tail -40 "$TMP/pebble.log"
    echo "--- chall.log (tail) ---";  tail -10 "$TMP/chall.log"
fi
exit "$RC"
