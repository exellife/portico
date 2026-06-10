#!/usr/bin/env bash
# Boot http_server with a short handshake timeout and verify the slowloris reaper
# closes stalled pre-request connections without racing the event loop (H-7).
# reaper_test.sh <server-binary>
set -euo pipefail

BIN="${1:?usage: reaper_test.sh <server-binary>}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

export HANDSHAKE_TIMEOUT=1
exec python3 "$DIR/tests/run_with_server.py" "$BIN" "$DIR/tests/reaper_test.py"
