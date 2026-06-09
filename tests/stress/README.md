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

### Stability

- **ThreadSanitizer** under concurrent HTTP + WS + fuzz load: _(see run log)_
- **Long soak** (RSS / fd over time): _(see run log)_
