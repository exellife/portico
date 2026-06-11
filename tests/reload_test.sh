#!/usr/bin/env bash
# SIGHUP TLS certificate hot-reload: replace the cert files in place, send SIGHUP,
# and new connections get the new cert while the server stays up (zero-downtime
# renewal). Two reloads, so the one-reload grace-period free of the retired context
# group is exercised (run under ASan to validate no leak/UAF there).
#   reload_test.sh <http_server-binary>
set -euo pipefail
BIN="${1:?usage: reload_test.sh <http_server-binary>}"
C="$(mktemp -d)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$C"' EXIT

gen() { openssl req -x509 -newkey rsa:2048 -keyout "$C/srv.key" -out "$C/srv.crt" \
                -days 1 -nodes -subj "/CN=$1" >/dev/null 2>&1; }
gen gen1

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
TLS_CERT="$C/srv.crt" TLS_KEY="$C/srv.key" PORT="$PORT" "$BIN" >/tmp/portico_reload_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

cn() { curl -ksv "https://127.0.0.1:$PORT/" 2>&1 | sed -n 's/.*subject: CN=//p' | head -1; }
reload_to() { gen "$1"; kill -HUP "$SRV"; sleep 0.5; }

ok=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; ok=$((ok+1)); else echo "  FAIL  $1: got '$2' want '$3'"; fail=$((fail+1)); fi; }
echo "== SIGHUP TLS cert hot-reload =="
chk "initial cert"             "$(cn)" "gen1"
reload_to gen2
chk "after 1st reload"         "$(cn)" "gen2"
chk "alive after 1st reload"   "$(kill -0 "$SRV" 2>/dev/null && echo up || echo down)" "up"
reload_to gen3
chk "after 2nd reload"         "$(cn)" "gen3"
chk "alive after 2nd reload"   "$(kill -0 "$SRV" 2>/dev/null && echo up || echo down)" "up"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
