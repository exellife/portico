# portico — TODO / feature work

A backlog of work surfaced while hardening and stress-testing portico. Nothing
here blocks portico's current job (single-binary HTTP/WS transport for general
real-time apps and [pgforge](https://github.com/exellife/pgforge)); these are the
things that move it from "solid and verified for our tests" toward "trust it with
production traffic for months" — and, eventually, toward a trading-grade gateway
if that ambition firms up.

Already shipped (for context, see `tests/stress/README.md` + git log): connection-leak
DoS fix, four MPSC/lifecycle data races fixed, RFC 6455 conformance (Autobahn 246/246),
HTTP request-smuggling hardening, HTTP + WS EPOLLOUT backpressure, slow-consumer
disconnect, and a repeatable load / open-loop-latency / fuzz / sanitizer harness.

Rough priority: **Confidence → Operability → Performance → Trading-grade**.

---

## 0. TLS termination — deploy without nginx  ← IN PROGRESS

Make portico a genuinely self-contained binary: terminate TLS itself so a small
deployment needs no nginx/proxy at all. Optional — plaintext stays the default,
so proxy deployments (multi-instance LB, WAF, HTTP/2) still run as before. Link
OpenSSL (already common in the process via libpq for pgforge); load cert/key from
disk; secure defaults (TLS 1.2+, server cipher preference). Staged so the risky
core-I/O surgery is isolated:

- [x] **Stage 1 — foundation.** Optional OpenSSL linkage (`PORTICO_TLS`),
      `ws_config_t.tls_cert_file/tls_key_file`, `SSL_CTX` lifecycle + cert/key
      loading (`src/ws/ws_tls.c`, server-level only, no I/O change, fail-closed).
- [x] **Stage 2 — accept + handshake.** Per-conn `SSL*` (`WS_STATE_TLS_HANDSHAKE`);
      wrapped on accept in `process_new_connection`; `SSL_accept` driven through epoll
      from both the EPOLLIN and EPOLLOUT paths (`WANT_READ`/`WANT_WRITE`), then drops to
      `WS_STATE_CONNECTING`. `SSL_free` in `ws_connection_cleanup`. Verified: `openssl
      s_client` completes a TLS 1.3 handshake; plaintext tests unchanged.
- [x] **Stage 3a — HTTPS (HTTP path).** The conn-based HTTP I/O (`read_into_recv`,
      `portico_conn_send`, `conn_out_drain`) now goes through `conn_recv`/`conn_write_raw`
      → `ws_tls_read`/`ws_tls_write`, which keep recv/send semantics (WANT_* → `EAGAIN`)
      so the EPOLLOUT backpressure + ET-drain logic is unchanged. On handshake DONE the
      initial dispatch is driven once to consume any pipelined request. Verified: `curl
      -k https://` → 200 + body, keep-alive over TLS, plaintext ctest 3/3, ASan clean.
      (Known edge, TLS 1.3 no-reneg: a read that genuinely needs *write* is mapped to
      EAGAIN — fine in practice; revisit if client-initiated KeyUpdate ever matters.)
- [x] **Stage 3b — WSS (WebSocket path).** Centralized `ws_conn_socket_read`/
      `ws_conn_socket_write` (SSL-or-raw by `conn->ssl`) in ws_connection.c; converted the
      fd-based frame senders (`ws_send_*_frame`) and `ws_process_handshake`/
      `ws_send_handshake_error` to **conn-based** (all callers had `conn`; the MPSC
      ping/pong/close consumers now resolve conn by fd), plus the WS frame read and the
      write_buffer flush. So every WS socket op routes through SSL on a TLS connection —
      no plaintext can leak into the cipher stream. Verified: `wss://` echo (multi-frame,
      keep-alive) via the `websockets` client; plaintext WS adversarial ctest 3/3; ASan
      clean over repeated WSS connect/echo/close.
      *Remaining gap:* `ws_server.c` `ws_send_ping/pong/close_internal` (public API) still
      do an inline raw `send(fd)` and may be called cross-thread — TLS-unsafe there; not on
      pgforge's hot path. Make them queue via MPSC (like text/binary) in Stage 4.
- [x] **Stage 4 — close + tests.** `SSL_shutdown` (best-effort close_notify in
      `close_connection`, before `close(fd)`); the public `ws_send_ping/pong/close` now
      **queue via MPSC** (resolved on the event thread → TLS-safe + thread-safe, no more
      inline raw `send(fd)`); a permanent **`tls` CTest** (dependency-free HTTPS +
      raw-socket WSS against one listener, self-signed cert minted per run). 4 suites
      green; ASan clean.

**TLS is COMPLETE** — portico serves HTTPS + WSS standalone (no nginx). Enable with
`ws_config_t.tls_cert_file/tls_key_file`; plaintext stays the default. Optional follow-ups:
- [ ] SIGHUP cert reload (hot-rotate without a restart).
- [ ] ALPN (advertise `http/1.1`); later HTTP/2 if ever wanted.
- [ ] Optional ACME, or document Caddy as the zero-code alternative for easy auto-HTTPS.

---

## 1. Confidence & maturity  ← highest value

The single biggest unknown is not speed or features — it's how many bugs remain in
paths we *didn't* stress. We found five serious bugs in one session in code that
passed conformance; the WS core had never been concurrency-tested before. Buy
confidence per hour cheaper than any feature here.

- [ ] **Broaden fuzz/soak under sanitizers.** Exercise the paths the current fuzz
      mode misses: fragmentation reassembly under load, partial/dribbled frames,
      pathological frame sizes, the **buffer-pool expansion path** (never stressed),
      teardown under heavy connection churn, the HTTP deferred-close path under load,
      keep-alive + pipelining edges. Run for hours, not seconds, under TSan/ASan.
- [ ] **Long multi-hour soak** with RSS/fd/latency sampling (extend the existing
      4-minute soak) to catch slow leaks and drift.
- [ ] **Two-host latency characterization.** The current tails above ~200k req/s are
      polluted by single-box client jitter. Run client and server on separate
      machines to get definitive p99.9/p99.99 — this is the real latency answer.

## 2. Operability

What you need to actually run it behind nginx and operate it at scale.

- [ ] **Real client IP behind a proxy.** Behind nginx portico sees 127.0.0.1.
      Add `X-Forwarded-For`/`X-Real-IP` parsing and/or PROXY-protocol support so
      audit, rate-limiting, and geo work. (Introduced by the "deploy behind nginx"
      decision.)
- [ ] **Observability.** Expose per-connection + per-thread metrics: latency
      histograms, send-buffer depth, slow-consumer/disconnect counters, dropped
      frames, active connections, accept rate. Structured logging with levels.
- [ ] **Graceful shutdown / drain.** Verify (and if needed implement) stop-accepting
      + drain-in-flight + close cleanly, so deploys don't drop connections.
- [ ] **Config reload** without a restart (optional).
- [ ] **nginx deployment guide** — the WS proxy essentials (`proxy_http_version 1.1`,
      `Upgrade`/`Connection` forwarding, `proxy_read_timeout`) and the fact that
      client-side backpressure becomes nginx's job once it's the immediate peer.

## 3. API & docs

It's a library; make it pleasant to build against.

- [ ] **Document + version the public API** (`include/portico.h`, `wslib.h`):
      stable surface, semver, changelog.
- [ ] **More examples** beyond echo: pub/sub broadcast, auth handshake, room/topic
      routing.
- [ ] **portico → git submodule** in pgforge (was noted during integration).

## 4. Performance (only if a workload demands it)

Current throughput/latency are already strong; pursue these only against a real
need, and **measure before/after** (the same-thread-send "optimization" regressed
latency — see `tests/stress/README.md`).

- [ ] **Zero-alloc steady state.** Today each send mallocs the message + the frame
      encode. Pre-allocated/pooled buffers would cut allocator jitter from the tail.
- [ ] **Investigate the p99.9 knee** under the two-host setup (item 1) before
      optimizing — don't optimize against single-box measurement noise.

## 5. Trading-grade gateway (future / aspirational)

Only if the trading ambition firms up. The architecture doesn't block any of it;
each is real, finite work. Portico's natural target is the **client-facing
WS gateway / market-data tier**, not the matching engine.

- [ ] **TLS** — postponed: deploy behind nginx for termination. Revisit in-process
      TLS (OpenSSL/BoringSSL/wolfSSL, with the epoll↔TLS read-wants-write interplay)
      only if the extra proxy hop's latency becomes unacceptable.
- [ ] **Message sequence numbers / gap detection** so a client can detect and resync
      a missed message (pairs with the slow-consumer disconnect already shipped).
- [ ] **Admission control / rate limiting / per-client quotas.**
- [ ] **Audit logging** (who connected, when, from where — needs item 2's real IP).
- [ ] **Much higher maturity bar** — multi-week burn-in, chaos testing, formal
      backpressure/ordering guarantees.

---

_Last updated after the stress-testing + hardening + backpressure work. See
`tests/stress/README.md` for the harness, measured numbers, and what's done._
