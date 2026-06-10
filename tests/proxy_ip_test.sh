#!/usr/bin/env bash
# M-8: behind a trusted proxy (TRUST_PROXY set), the resolved client IP comes from
# the RIGHTMOST X-Forwarded-For element (the address the proxy appended), not the
# client-forgeable leftmost — and it must parse as a valid IP, else fall back to the
# real peer. http_server's GET /ip returns the resolved IP. proxy_ip_test.sh <bin>
set -euo pipefail

BIN="${1:?usage: proxy_ip_test.sh <server-binary>}"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
LOG="/tmp/proxyip_$$.log"; SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -f "$LOG"; }
trap cleanup EXIT

env TRUST_PROXY=1 PORT="$PORT" "$BIN" >"$LOG" 2>&1 &
SRV=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 0.1; done

U="http://127.0.0.1:$PORT/ip"
fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; else echo "  FAIL  $1: got '$2' want '$3'"; fail=1; fi; }

echo "== M-8 proxy client-IP resolution (TRUST_PROXY=1) =="
# spoofed leftmost + real proxy-appended rightmost -> rightmost wins
chk "rightmost XFF used"        "$(curl -s -H 'X-Forwarded-For: 6.6.6.6, 10.0.0.9' "$U")" "10.0.0.9"
# a single element (proxy overwrote XFF) is taken as-is
chk "single XFF element"        "$(curl -s -H 'X-Forwarded-For: 10.1.1.1' "$U")"          "10.1.1.1"
# an invalid rightmost token is ignored -> fall back to the real peer
chk "invalid XFF -> peer"       "$(curl -s -H 'X-Forwarded-For: 6.6.6.6, not-an-ip' "$U")" "127.0.0.1"
# a valid X-Real-IP takes precedence (and is validated)
chk "valid X-Real-IP used"      "$(curl -s -H 'X-Real-IP: 10.2.2.2' -H 'X-Forwarded-For: 6.6.6.6' "$U")" "10.2.2.2"
# an invalid X-Real-IP is ignored -> fall through to the rightmost XFF
chk "invalid X-Real-IP ignored" "$(curl -s -H 'X-Real-IP: bogus' -H 'X-Forwarded-For: 10.3.3.3' "$U")"  "10.3.3.3"

echo
[ $fail = 0 ] && echo PASS || { echo FAIL; cat "$LOG"; exit 1; }
