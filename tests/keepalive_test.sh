#!/usr/bin/env bash
# H-8: wire keepalive PINGs + idle reaping of established connections into the
# event loop. Boot http_server with a 1s ping interval / 1s pong timeout so the
# behaviour is observable quickly. keepalive_test.sh <server-binary>
set -euo pipefail

BIN="${1:?usage: keepalive_test.sh <server-binary>}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

export PING_INTERVAL=1 PONG_TIMEOUT=1
exec python3 "$DIR/tests/run_with_server.py" "$BIN" "$DIR/tests/keepalive_test.py"
