# portico stress / benchmark harness

Two pieces:

- **`examples/stress_server.c`** — a tunable both-protocol server (built as the
  `stress_server` target). Everything comes from the environment:

  | env | meaning | default |
  |-----|---------|---------|
  | `PORT` | listen port | 8090 |
  | `THREADS` | event threads | online CPUs (cap 64) |
  | `MAX_CONNS` | max concurrent connections | 200000 |
  | `MSG_SIZE` | max WS message bytes | 16 MiB |
  | `SMALL`/`MEDIUM`/`LARGE` | buffer-pool counts | 4096/2048/512 |

  Routes: HTTP `GET /health` (tiny JSON), `POST /echo` (echoes body); WS text+binary echo.

- **`tests/stress/loadtest.go`** — a dependency-free (stdlib-only) load client with
  hand-rolled WebSocket framing. Build once: `go build -o /tmp/loadtest loadtest.go`.

  | flag | meaning |
  |------|---------|
  | `-mode` | `http` \| `ws` \| `wsconns` \| `fuzz` |
  | `-addr` | comma-separated server addresses (spread big tests across loopback IPs) |
  | `-conns` | concurrent connections |
  | `-dur` | duration (e.g. `10s`) |
  | `-size` | payload bytes (ws echo / http POST) |
  | `-path` | http GET path (default `/health`) |
  | `-ramp` | delay between connection starts (`wsconns`) |

## Running

```sh
# build
cmake --build build --target stress_server -j
go build -o /tmp/loadtest tests/stress/loadtest.go

# start the server (16 threads)
PORT=8090 THREADS=16 ./build/stress_server &

# HTTP throughput + latency
/tmp/loadtest -mode http -conns 500 -dur 10s

# WS echo throughput + latency (256-byte messages)
/tmp/loadtest -mode ws -conns 500 -dur 10s -size 256

# connection scaling — spread across loopback IPs to beat the ephemeral-port
# ceiling (~28k per dst IP). The whole 127.0.0.0/8 routes to lo, so no aliases
# are needed; just dial different dst IPs.
/tmp/loadtest -mode wsconns \
  -addr 127.0.0.1:8090,127.0.0.2:8090,127.0.0.3:8090,127.0.0.4:8090 \
  -conns 100000 -dur 30s -ramp 40us

# fuzz: malformed frames at speed (run a sanitizer build to catch issues)
/tmp/loadtest -mode fuzz -conns 50 -dur 20s
```

### Finding bugs with sanitizers under load

```sh
# ThreadSanitizer build — best for the threaded epoll server (races in the
# connection hash, refcounts, MPSC queue).
cmake -S . -B build-tsan -DPORTICO_TSAN=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-tsan --target stress_server -j
TSAN_OPTIONS="halt_on_error=0 log_path=/tmp/tsan_report" \
  PORT=8091 THREADS=8 ./build-tsan/stress_server &
# drive http + ws + fuzz concurrently, then inspect /tmp/tsan_report.*

# AddressSanitizer build — buffer/UB issues + leaks.
cmake -S . -B build-asan -DPORTICO_ASAN=ON -DCMAKE_BUILD_TYPE=Debug
```

## OS tuning for large connection counts

Already generous on this box, but for other machines:

```sh
ulimit -n 1048576                                   # fds per process
sysctl -w net.core.somaxconn=4096                   # accept backlog
sysctl -w net.ipv4.ip_local_port_range="10000 65535"# ephemeral ports per 4-tuple
```

The real connection ceiling is usually the OS (ephemeral ports, fd limits), not
portico — spread the client across multiple destination IPs to scale past one
dst IP's ~28k limit.

## Results (this box: 32 cores, 45 GiB RAM; client + server share the host)

Loopback, same-host (client competes with server for cores), release build.

### Throughput

| Test | Peak | Notes |
|------|------|-------|
| HTTP `GET /health` | **~2.0 M req/sec** | 500–1000 conns; p50 ≈ 50–200 µs |
| WS echo, 64 B | **~2.2 M msg/sec** | 500–1000 conns; p50 ≈ 50–200 µs |
| WS echo, 16 KiB | ~162 k msg/sec | ~5 GB/s loopback (bandwidth-bound) |
| WS echo, 256 KiB | ~16 k msg/sec | ~4 GB/s loopback (bandwidth-bound) |

Latency tails (p99 a few ms, p99.9 ~15–25 ms, occasional 100–400 ms max) are
dominated by client-side Go GC pauses and both processes contending for the same
cores — not representative of a dedicated server/client split.

### Connection scaling

| Connections | Server RSS | Resident / conn | Failures |
|-------------|-----------|-----------------|----------|
| idle | ~320–400 MB | — | — |
| 25 000 | 424 MB | ~4.3 KB | 0 |
| 150 000 | 955 MB | ~3.8 KB | 0 |

Each connection reserves a 16 KiB recv buffer *virtually*, but only ~4 KB is
resident while idle (unfaulted pages). Under active traffic the resident set
rises toward ~16–20 KB/conn. Extrapolating from 45 GiB RAM: ~2 M active
connections is the memory ceiling (idle would go far higher), assuming `MAX_CONNS`
and the fd limit are raised to match. **150 k tested with zero failures.**

### Stability — bugs this harness found

The `fuzz` mode (malformed frames + pre-handshake garbage at high concurrency)
plus ASan/TSan builds surfaced real bugs:

- **Connection-leak DoS (fixed, commit 4db52ad).** A lost-message race in the
  lock-free MPSC dequeue left `head` NULL permanently once a producer swapped
  `tail` during the "empty the queue" step. New-connection messages were then
  silently dropped: accepted sockets were never registered in epoll, piled up
  unread in `CLOSE_WAIT`, and the server stopped responding. Observable as
  `ss -tan` CLOSE_WAIT climbing and never recovering, fds growing, throughput
  collapsing. Fixed; CLOSE_WAIT now returns to ~0 after load and fuzz throughput
  rose ~60×.
- **MPSC bounded-batch stranding (fixed).** Only 50 messages drained per
  edge-triggered eventfd wakeup; the rest waited for a wakeup that might never
  come. Now drains the whole queue per wakeup.
- **Node-pool ABA race (fixed).** Treiber-stack free list could hand one node to
  two owners under contention (TSan-confirmed). Now serialized with a small
  per-queue mutex.
- **Send-to-reused-fd cross-talk (fixed, commit 87b9b41).** An echo queued for a
  connection could be delivered to a different one that reused the fd. Sends now
  carry a slot `{conn, generation}` and are dropped if the slot was recycled.
- **Slot init vs global-hash traversal (fixed, commit 87b9b41).** The hash read
  `conn->fd` off a recyclable slot during lookup, racing the unlocked re-init
  memset. The hash now stores `{fd, conn}` and matches on the stored fd.

The harness is now **fully TSan-clean** under concurrent HTTP + WS + fuzz load.

How to reproduce the leak class:
```sh
PORT=8090 THREADS=4 ./build/stress_server &
/tmp/loadtest -mode fuzz -conns 40 -dur 12s &
watch -n1 "ss -tan '( sport = :8090 )' | awk 'NR>1 && \$1==\"CLOSE-WAIT\"' | wc -l"
# pre-fix: climbs into the hundreds and never recovers. post-fix: stays ~0.
```

### Latency (`latency.c`)

A dedicated **C** client (no GC) that measures latency honestly:
- **Open-loop / fixed-rate** — sends on a schedule and measures each request from
  its *intended* send time, so a stall shows up on every request queued behind it
  (avoids coordinated omission, which a closed-loop client hides).
- **No runtime jitter** — plain C, no allocation in the steady-state loop.
- Pin client and server to **disjoint cores**.

```sh
gcc -O2 -o /tmp/latency tests/stress/latency.c -lpthread
taskset -c 0-7  env PORT=8090 THREADS=8 ./build/stress_server &
taskset -c 8-31 /tmp/latency -mode http -conns 6 -rate 200000 -dur 6s -warmup 1.5s
#   -mode http|ws  -conns N  -rate <total req/s>  -size <ws bytes>  -dur 6s  -warmup 1.5s
```

Results on this box (32c/45G, **single host** — client + server share the machine):

| Offered load | HTTP p50 / p99.9 / p99.99 | WS p50 / p99.9 |
|---|---|---|
| floor (1 conn, 10k/s) | 81 / 287 / 404 µs | 76 / 565 µs |
| 50k req/s | ~100 / 300 / 450 µs | ~100 / 350 µs |
| 200k req/s | 85 µs / **1.7 ms** / 3.9 ms | 89 µs / **~20 ms** |
| 500k req/s | 98 µs / 17 ms | saturates |
| 1M req/s | saturates (8 server threads) | — |

Reading it honestly:
- **Median latency is excellent and flat** (~80–290 µs) across the whole range —
  typical-case latency is very good.
- **Sub-millisecond tails up to ~50–100k req/s** (p99.9 ≈ 300 µs). This is the
  clean, reproducible result.
- **The tail grows with load**, and past ~200k req/s a meaningful chunk of that
  is the *measurement* (single box; the client busy-spins to pace and runs two
  threads per connection, so at high rates it contends for its own cores). A
  definitive high-load tail needs **two physical hosts** — this number is a floor
  on quality, not portico's ceiling.
- **WS tails are worse than HTTP** at the same rate: an HTTP response is written
  inline in the handler, but the WS echo round-trips through the per-thread MPSC
  queue + a self-wakeup even for a same-thread send.

  **Tried and rejected — same-thread send fast path.** The "obvious" fix was to
  detect a send issued on the connection's own event thread and write the frame
  inline instead of queueing it. Measured A/B (3 runs each, WS 100k): it made the
  tail *worse* — p99 ~340→520 µs, p99.9 ~900 µs→1.5 ms. The MPSC path's
  **batching** is a feature: draining the queue and sending all echoes together,
  then returning to epoll quickly, beats interleaving a `send()` syscall into the
  read loop per frame. Reverted.

  **Shipped — WS send-path EPOLLOUT buffering.** WS data frames went out via a
  single raw `send()`, which truncates/drops the frame the instant a slow
  consumer's window fills (a silent feed gap). They now route through the same
  per-connection `out_buffer` + EPOLLOUT drain as HTTP responses: buffer what the
  socket won't take, drain on writability, bounded by a 4 MB cap. Verified — a
  2500-frame burst against a non-reading client lost **7 frames before, 0 after**;
  latency is unchanged (the MPSC batching is preserved, so no fast-path-style
  regression); Autobahn 246/246, TSan/ASan clean.

  **Shipped — slow-consumer disconnect at the cap.** A consumer that backs up
  past the 4 MB cap is now disconnected (so it reconnects + resyncs) rather than
  silently dropping frames. The trigger is `shutdown(fd, SHUT_RDWR)` from the
  send path — safe mid-MPSC-drain because it doesn't free the fd (no acceptor
  reuse race); the socket then reports EOF and the connection tears down through
  the normal event-loop close path with its slot still valid. The connection is
  marked `CLOSING` on the first overflow so its remaining queued frames drop
  silently (one log line, not thousands). Verified: over-cap consumer
  disconnected + fd reclaimed; under-cap consumer still gets every frame; server
  stays healthy; TSan/ASan clean.

### Soak

Sustained HTTP + WS + fuzz cycles with periodic RSS/fd/CLOSE_WAIT sampling — RSS
and fd count stay flat, CLOSE_WAIT returns to ~0 between cycles (no slow leak).
