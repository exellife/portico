#!/usr/bin/env bash
# The verifying HTTPS client (used by the ACME flow). Boots a local TLS server
# (portico) with a self-signed cert for "localhost" and checks the client:
#  - trusts that cert + connects to the matching host  -> request succeeds (200)
#  - against the system roots (untrusted self-signed)  -> verification fails
#  - cert trusted but wrong hostname (127.0.0.1)       -> hostname check fails
# Proves both the chain AND hostname verification (no internet needed).
#   https_client_test.sh <http_server-binary> <https_probe-binary>
set -euo pipefail
BIN="${1:?usage: https_client_test.sh <http_server> <https_probe>}"
PROBE="${2:?need https_probe binary}"
C="$(mktemp -d)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$C"' EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$C/s.key" -out "$C/s.crt" -days 1 -nodes \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
TLS_CERT="$C/s.crt" TLS_KEY="$C/s.key" PORT="$PORT" "$BIN" >/tmp/portico_https_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

set +e
out_a=$("$PROBE" GET "https://localhost:$PORT/" "$C/s.crt"); rc_a=$?
out_b=$("$PROBE" GET "https://localhost:$PORT/" "");          rc_b=$?
out_c=$("$PROBE" GET "https://127.0.0.1:$PORT/" "$C/s.crt");  rc_c=$?
set -e

ok=0; fail=0
chk() { if [ "$2" = true ]; then echo "  ok    $1"; ok=$((ok+1)); else echo "  FAIL  $1  [$3]"; fail=$((fail+1)); fi; }
echo "== verifying HTTPS client =="
chk "trusted cert + correct host -> 200" \
    "$([ "$rc_a" = 0 ] && echo "$out_a" | grep -q 'status=200' && echo "$out_a" | grep -q 'portico' && echo true || echo false)" "$out_a"
chk "untrusted (system roots) -> verify fail" "$([ "$rc_b" = 2 ] && echo true || echo false)" "rc=$rc_b $out_b"
chk "hostname mismatch -> fail"               "$([ "$rc_c" = 2 ] && echo true || echo false)" "rc=$rc_c $out_c"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
