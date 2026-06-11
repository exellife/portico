#!/usr/bin/env bash
# Streaming-throughput benchmark for the static-file path. Not a ctest (it's a
# measurement tool, not a pass/fail check) — run it by hand to compare backends or
# evaluate a change. Serves one large file and measures single-stream download
# throughput per aio backend, cold vs warm.
#
# Findings that set the current defaults (200 MB, this box, loopback):
#   - io_uring is link/memory-bound at ~6 GB/s regardless of chunk size; cold≈warm
#     here (fast storage), so a slow-disk regime — where read-ahead/overlap would
#     help — is not reproducible.
#   - threadpool throughput is dominated by per-chunk worker round-trips, so it
#     scales hard with chunk size: 256K→2.4, 1M→5.3, 4M→6.5 GB/s. The 1 MiB default
#     (PORTICO_STREAM_CHUNK) captures most of that for 1 MiB/stream of memory.
#   - Both backends already stream far above any real network link (>10GbE), so
#     read-ahead and io_uring SQPOLL/batched-submit are not warranted here (they'd
#     target a slow-disk or high-IOPS regime that this workload/box doesn't hit).
#
#   stream_bench.sh <http_server-binary> [size_bytes]
set -euo pipefail
BIN="${1:?usage: stream_bench.sh <http_server-binary> [size_bytes]}"
SIZE="${2:-209715200}"   # 200 MB
ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true' EXIT
head -c "$SIZE" /dev/urandom > "$ROOT/f.bin"

gbps() { awk -v b="$1" 'BEGIN{printf "%.2f GB/s", b/1e9}'; }
run() {
  local be="$1" port; port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
  STATIC_ROOT="$ROOT" PORT="$port" PORTICO_AIO_BACKEND="$be" "$BIN" >/dev/null 2>&1 & SRV=$!
  sleep 1
  local cold warm
  cold=$(curl -s -o /dev/null -w "%{speed_download}" "http://127.0.0.1:$port/f.bin")
  warm=$(curl -s -o /dev/null -w "%{speed_download}" "http://127.0.0.1:$port/f.bin")
  kill "$SRV" 2>/dev/null; SRV=; sleep 0.3
  printf "  %-11s cold %-12s warm %s\n" "$be" "$(gbps "$cold")" "$(gbps "$warm")"
}

echo "== streaming throughput ($(( SIZE / 1048576 )) MB, single stream) =="
run iouring
run threadpool
run blocking
