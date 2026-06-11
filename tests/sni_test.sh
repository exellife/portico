#!/usr/bin/env bash
# SNI multi-certificate TLS: portico presents a different certificate per domain
# during the handshake, so multiple HTTPS sites share one IP. Mints throwaway
# self-signed certs in a temp dir (NOT the repo) and uses curl --resolve to drive
# a specific SNI server_name, asserting the served cert's CN matches.
#   sni_test.sh <http_server-binary>
set -euo pipefail
BIN="${1:?usage: sni_test.sh <http_server-binary>}"
C="$(mktemp -d)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$C"' EXIT

mint() { openssl req -x509 -newkey rsa:2048 -keyout "$C/$1.key" -out "$C/$1.crt" \
                 -days 1 -nodes -subj "/CN=$2" >/dev/null 2>&1; }
mint default  "default"
mint alpha    "alpha.test"
mint beta     "beta.test"
mint wild     "*.wild.test"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
TLS_CERT="$C/default.crt" TLS_KEY="$C/default.key" \
TLS_SNI="alpha.test:$C/alpha.crt:$C/alpha.key;beta.test:$C/beta.crt:$C/beta.key;*.wild.test:$C/wild.crt:$C/wild.key" \
PORT="$PORT" "$BIN" >/tmp/portico_sni_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

# CN of the cert the server presents for a given SNI hostname (or IP = no SNI).
cn() {
  local host="$1"
  if [ "$host" = "-" ]; then
    curl -ksv "https://127.0.0.1:$PORT/" 2>&1 | sed -n 's/.*subject: CN=//p' | head -1
  else
    curl -ksv --resolve "$host:$PORT:127.0.0.1" "https://$host:$PORT/" 2>&1 | sed -n 's/.*subject: CN=//p' | head -1
  fi
}

ok=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 (CN=$2)"; ok=$((ok+1)); else echo "  FAIL  $1: got CN=$2 want CN=$3"; fail=$((fail+1)); fi; }
echo "== SNI multi-cert selection =="
chk "alpha.test -> alpha cert"     "$(cn alpha.test)"     "alpha.test"
chk "beta.test  -> beta cert"      "$(cn beta.test)"      "beta.test"
chk "x.wild.test -> wildcard cert" "$(cn x.wild.test)"    "*.wild.test"
chk "unknown.test -> default cert" "$(cn unknown.test)"   "default"
chk "no SNI (IP)  -> default cert" "$(cn -)"              "default"

# ALPN: a client offering h2,http/1.1 must be steered to http/1.1.
alpn=$(echo | openssl s_client -connect 127.0.0.1:"$PORT" -alpn h2,http/1.1 2>/dev/null \
        | sed -n 's/^ALPN protocol: //p' | head -1)
chk "ALPN negotiates http/1.1"     "$alpn"                "http/1.1"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
