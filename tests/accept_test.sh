#!/usr/bin/env bash
# Boot http_server with the loopback IP blacklisted, and verify the accept gate
# drops the connection. accept_test.sh <server-binary>
set -euo pipefail

BIN="${1:?usage: accept_test.sh <server-binary>}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

export DENY_IP=127.0.0.1
exec python3 "$DIR/tests/run_with_server.py" "$BIN" "$DIR/tests/accept_test.py"
