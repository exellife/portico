#!/usr/bin/env bash
# Name-based virtual hosting: one listener serves multiple sites, routed by the
# Host header to per-vhost docroots (the HTTP half of multi-site-on-one-IP; SNI is
# the HTTPS half). Asserts each Host maps to its docroot, :port is stripped,
# wildcards work, an unconfigured Host is 404 (allow-list), and traversal is still
# blocked per-vhost.
#   vhost_test.sh <http_server-binary>
set -euo pipefail
BIN="${1:?usage: vhost_test.sh <http_server-binary>}"
A="$(mktemp -d)"; B="$(mktemp -d)"; W="$(mktemp -d)"
trap '[ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$A" "$B" "$W"' EXIT
printf 'SITE-A' > "$A/page.html"
printf 'SITE-B' > "$B/page.html"
printf 'WILD'   > "$W/page.html"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
VHOSTS="foo.com:$A;bar.com:$B;*.wild.com:$W" PORT="$PORT" "$BIN" >/tmp/portico_vhost_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }; sleep 0.1; done

body() { curl -s -H "Host: $1" "http://127.0.0.1:$PORT$2"; }
code() { curl -s -o /dev/null -w "%{http_code}" -H "Host: $1" "http://127.0.0.1:$PORT$2"; }

ok=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; ok=$((ok+1)); else echo "  FAIL  $1: got '$2' want '$3'"; fail=$((fail+1)); fi; }
echo "== name-based virtual hosting =="
chk "foo.com -> site A"          "$(body foo.com /page.html)"        "SITE-A"
chk "bar.com -> site B"          "$(body bar.com /page.html)"        "SITE-B"
chk "foo.com:1234 (port strip)"  "$(body foo.com:1234 /page.html)"   "SITE-A"
chk "FOO.COM (case-insensitive)" "$(body FOO.COM /page.html)"        "SITE-A"
chk "a.wild.com -> wildcard"     "$(body a.wild.com /page.html)"     "WILD"
chk "deep.a.wild.com no match"   "$(code deep.a.wild.com /page.html)" "404"
chk "unknown.com -> 404"         "$(code unknown.com /page.html)"    "404"
chk "no Host -> 404"             "$(curl -s -o /dev/null -w '%{http_code}' --http1.0 "http://127.0.0.1:$PORT/page.html")" "404"
chk "per-vhost traversal blocked" "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is -H 'Host: foo.com' "http://127.0.0.1:$PORT/../../../etc/passwd")" "403"

echo
[ "$fail" = 0 ] && echo "PASS ($ok ok)" || { echo "FAIL ($fail failed)"; exit 1; }
