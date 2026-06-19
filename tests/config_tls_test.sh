#!/usr/bin/env bash
# Config-driven HTTPS (tls.mode: files) + runtime SNI add over the wire. Boots
# portico_server with a default cert and one per-site (SNI) cert, asserts the right
# cert is presented per SNI and bodies are served over TLS; then SIGHUPs in a second
# HTTPS site and asserts its cert is presented + served WITHOUT a restart — the
# end-to-end proof of ws_server_add_sni_cert on a live listener.
#   config_tls_test.sh <portico_server-binary>
set -euo pipefail
BIN="${1:?usage: config_tls_test.sh <portico_server-binary>}"
C="$(mktemp -d)"; A="$(mktemp -d)"; B="$(mktemp -d)"; CFG="$(mktemp)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$C" "$A" "$B" "$CFG"' EXIT
printf 'SITE-A' > "$A/index.html"
printf 'SITE-B' > "$B/index.html"

mint() { openssl req -x509 -newkey rsa:2048 -keyout "$C/$1.key" -out "$C/$1.crt" \
                 -days 1 -nodes -subj "/CN=$2" >/dev/null 2>&1; }
mint default "default"
mint alpha   "alpha.test"
mint beta    "beta.test"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

write_one() { cat > "$CFG" <<JSON
{ "listen": { "port": $PORT, "threads": 2 },
  "tls": { "mode": "files", "cert": "$C/default.crt", "key": "$C/default.key" },
  "sites": [ { "host": "alpha.test", "docroot": "$A",
               "tls": { "cert": "$C/alpha.crt", "key": "$C/alpha.key" } } ] }
JSON
}
write_two() { cat > "$CFG" <<JSON
{ "listen": { "port": $PORT, "threads": 2 },
  "tls": { "mode": "files", "cert": "$C/default.crt", "key": "$C/default.key" },
  "sites": [ { "host": "alpha.test", "docroot": "$A",
               "tls": { "cert": "$C/alpha.crt", "key": "$C/alpha.key" } },
             { "host": "beta.test", "docroot": "$B",
               "tls": { "cert": "$C/beta.crt", "key": "$C/beta.key" } } ] }
JSON
}

write_one
"$BIN" "$CFG" >/tmp/portico_cfgtls_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

# CN the server presents for a given SNI host
cn()   { curl -ksv --resolve "$1:$PORT:127.0.0.1" "https://$1:$PORT/" 2>&1 | sed -n 's/.*subject: CN=//p' | head -1; }
# body served over TLS for a given Host/SNI
body() { curl -sk --resolve "$1:$PORT:127.0.0.1" "https://$1:$PORT/"; }
ok=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; ok=$((ok+1)); else echo "  FAIL  $1: got '$2' want '$3'"; fail=$((fail+1)); fi; }

echo "== config-driven HTTPS + runtime SNI add =="
chk "alpha SNI -> alpha cert" "$(cn alpha.test)"   "alpha.test"
chk "alpha served over TLS"   "$(body alpha.test)" "SITE-A"
chk "unknown SNI -> default"  "$(cn unknown.test)" "default"
chk "beta not yet present"    "$(cn beta.test)"    "default"

# add beta.test (new HTTPS site) via SIGHUP — no restart
write_two
kill -HUP "$SRV"
sleep 0.5
chk "beta SNI -> beta cert (runtime add)" "$(cn beta.test)"   "beta.test"
chk "beta served over TLS"                "$(body beta.test)" "SITE-B"
chk "alpha still presents alpha cert"     "$(cn alpha.test)"  "alpha.test"
chk "alpha still served"                  "$(body alpha.test)" "SITE-A"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
