#!/usr/bin/env bash
# Config-file-driven server + SIGHUP hot-reload (the Half-A standalone story).
# Boots portico_server with a JSON config (one site), then rewrites the config to
# add a second site and SIGHUPs: asserts the new site is served, the original keeps
# serving (no restart, no dropped requests across the reload), and that a BROKEN
# config on SIGHUP is rejected — the running config stays up.
#   config_reload_test.sh <portico_server-binary>
set -euo pipefail
BIN="${1:?usage: config_reload_test.sh <portico_server-binary>}"
A="$(mktemp -d)"; B="$(mktemp -d)"; CFG="$(mktemp)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$A" "$B" "$CFG"' EXIT
printf 'SITE-A' > "$A/index.html"
printf 'SITE-B' > "$B/index.html"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

write_one() { cat > "$CFG" <<JSON
{ "listen": { "port": $PORT, "threads": 2 },
  "sites": [ { "host": "a.com", "docroot": "$A" } ] }
JSON
}
write_two() { cat > "$CFG" <<JSON
{ "listen": { "port": $PORT, "threads": 2 },
  "sites": [ { "host": "a.com", "docroot": "$A" },
             { "host": "b.com", "docroot": "$B" } ] }
JSON
}

write_one
"$BIN" "$CFG" >/tmp/portico_cfgreload_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

body() { curl -s -H "Host: $1" "http://127.0.0.1:$PORT/"; }
code() { curl -s -o /dev/null -w "%{http_code}" -H "Host: $1" "http://127.0.0.1:$PORT/"; }
ok=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; ok=$((ok+1)); else echo "  FAIL  $1: got '$2' want '$3'"; fail=$((fail+1)); fi; }

echo "== config-driven serving + SIGHUP reload =="
chk "a.com served at boot"        "$(body a.com)"   "SITE-A"
chk "b.com not configured -> 404" "$(code b.com)"   "404"

# add site B, reload
write_two
kill -HUP "$SRV"
sleep 0.4
chk "b.com served after reload"   "$(body b.com)"   "SITE-B"
chk "a.com still served"          "$(body a.com)"   "SITE-A"

# broken config on reload -> kept running config
printf '{ this is not json' > "$CFG"
kill -HUP "$SRV"
sleep 0.4
chk "server survives bad reload"  "$(body a.com)"   "SITE-A"
chk "bad reload kept b.com too"   "$(body b.com)"   "SITE-B"

# a request with no matching host and no fallback is a hard 404 (allow-list)
chk "unknown host -> 404"         "$(code zzz.com)" "404"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
