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

- [x] **Real client IP (proxy-aware).** `portico_req_client_ip(req)` (HTTP) +
      `portico_client_ip(server, fd, …)` (WS peer). `ws_config_t.trust_proxy` (off by
      default → a spoofed `X-Forwarded-For` is ignored); when on, prefers `X-Real-IP`
      then the leftmost `X-Forwarded-For`, else the direct peer. Spoof-safety covered in
      `http_test.py`. *Remaining:* PROXY-protocol support; proxy-aware IP for WS
      (capture XFF at the handshake, not just the peer).
- [x] **Accept-time allow/deny hook.** `ws_callbacks_t.on_accept(client_ip, user_data)`
      runs on the acceptor thread before any handshake/allocation; non-zero drops the peer.
      The cheap enforcement point for IP blacklists / connection caps (policy stays in the
      consumer, e.g. pgforge). `http_server` demos it via `DENY_IP`; CTest `accept_gate`.
      Gates on the *direct* peer — behind a proxy, per-client bans go at the app layer.
- [ ] **Per-IP flood guard (optional, built-in).** A configurable max-connections-per-IP /
      accept-rate cap inside portico, so consumers don't each reimplement it. The on_accept
      hook already lets a consumer do this; a built-in is just convenience.
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

## 4b. Static file serving — the nginx-replacement primitive

The capability that turns portico from "API/WS transport" into a standalone web
server: serve `Host → static_root` directly (HTML, assets), no nginx in front.
The hard part is that regular-file `read()`/`open()` can block on disk, which
would stall the event thread that owns those connections — so async file I/O is
the foundation, built first as a standalone, isolation-tested library.

- [x] **Async file I/O library** (`include/portico_aio.h`, `src/aio/`,
      `tests/aio_test.c`). Loop-agnostic: submit a `pread`, get a completion via an
      injectable `wakeup_fd` (eventfd) + `drain()` — the same eventfd/queue seam the
      WS path already uses. Backend vtable with a **blocking** backend (the portable
      fallback *and* the correctness oracle for the threaded backends). Not yet
      linked into `portico` — depends only on libc + pthreads, tested in isolation
      (24 asserts, ASan/UBSan clean: correctness, EOF/tail/zero-len, `-errno`
      propagation, wakeup signalling, ordering, arg validation, 1000-op queue).
- [x] **Threadpool backend** (`src/aio/aio_threadpool.c`) — N workers pull reads off
      a bounded queue (`-EAGAIN` backpressure when full) and run pread() off the
      event thread, posting via a **coalesced** wakeup (a burst of completions costs
      one eventfd write, not one each — the main lever closing the gap to io_uring).
      Differential-tested against the blocking oracle (identical results), plus 1000
      concurrent ops + backpressure-retry. Clean under TSan and ASan/UBSan. This is
      the portable, non-stalling path and the runtime fallback when io_uring is
      absent (old kernel / seccomp).
- [x] **io_uring backend** (`src/aio/aio_uring.c`) — Linux fast path: reads go to
      the kernel SQ and are reaped from the CQ, no thread parked per in-flight op.
      Built on **raw io_uring syscalls** (no liburing dep — portico stays
      self-contained); registers the frontend's wakeup_fd with the ring so it fits
      the same epoll-add → drain() contract. Ring index publish/consume uses C11
      acquire/release atomics, so ordering is correct on weakly-ordered ARM/Ampere,
      not just x86. Compiled only where `<linux/io_uring.h>` exists (else an
      `-ENOSYS` stub → clean fallback); runtime setup failure (old kernel / seccomp)
      also returns `-ENOSYS`. Differential-tested vs the blocking oracle
      (byte-identical) + 1000 concurrent ops; clean under ASan/UBSan and TSan.
      Caveat: validated functionally on x86 — recommend a smoke run on the actual
      Ampere target. Follow-ups: batched submit / SQPOLL, registered buffers+files.
- [ ] **Offload `open()`/`stat()` too**, not just `read()` (a cold dentry blocks).
- [x] **`portico_res_file`** (src/http/connection.c) — serves a static file from a
      docroot via the aio path. Handler calls it and returns; the core submits one
      async read off the event thread and **parks** the connection (buffering but
      not processing further input), then the read completion builds the response,
      sends it via the existing backpressure path, and resumes (keep-alive →
      pipelined, else close). Security: percent-decode then `realpath()`, requiring
      the result to stay within the docroot — defeats `../` traversal (encoded and
      plain) and symlinks escaping the tree; path validation stays in the HTTP
      layer, never the I/O lib. Slot-reuse guarded by the connection `generation`
      (a connection closed mid-read → result discarded, never written to a recycled
      socket). MIME by extension; synchronous-read fallback when aio is unavailable.
      Each event thread owns its aio instance; `PORTICO_AIO_BACKEND` overrides the
      io_uring-then-threadpool default. Tested e2e (bytes, types, 404/403,
      traversal + symlink safety, 250 KB byte-exact, keep-alive resume) across all
      three backends; ASan-clean; portico suite 11/11.
- [x] **Streaming large files** (src/http/connection.c) — files over 256 KB are sent
      chunk by chunk (read a chunk off-thread → send → on socket drain, read the
      next) instead of buffered whole. Two-sided backpressure: a read in flight is
      the disk wait, a non-empty out-buffer is the socket wait (EPOLLOUT resumes via
      stream_advance). Memory stays bounded to one chunk + the out-buffer regardless
      of file size (tested to 50 MB). Content-Length known up front (from fstat), so
      a normal response, no chunked transfer-encoding. Lifecycle: while a chunk read
      is in flight the completion owns the stream context; otherwise the detaching
      function frees it; a mid-stream connection close is handled by
      portico_http_stream_abort (called from ws_connection_cleanup) + the slot-reuse
      generation guard. A progressing stream bumps last_activity so the idle reaper
      won't kill it; a stalled reader still times out. Tested: 1.5 MB byte-exact,
      keep-alive after a streamed response, mid-stream client disconnect survival,
      16 concurrent streams — across all 3 backends, ASan-clean, suite 11/11.
- [x] **HTTP Range + conditional GET** (src/http/connection.c) — `portico_res_file`
      now computes validators (strong **ETag** from mtime+size, **Last-Modified**)
      and evaluates the conditional/range headers before serving:
      • **Range** (RFC 7233): single `bytes=N-M`, `N-`, `-N` → `206 Partial Content`
        with `Content-Range`; unsatisfiable → `416`; `Accept-Ranges: bytes`
        advertised. Implemented as the streaming/single-read path with a start
        offset + length, so a ranged read of a huge file only touches that window.
      • **Conditional** (RFC 7232): `If-None-Match` / `If-Modified-Since` → `304 Not
        Modified` (no body); `If-Range` serves the range only if the validator still
        matches, else the full body. This is what makes video **seeking** work and
        gives browsers cache revalidation — i.e. portico can now be an HLS/DASH
        origin. Tested: 13 Range/conditional assertions (offsets, suffix, 416, 304,
        If-Range match/mismatch, ranged streamed file) across all 3 backends,
        ASan-clean, suite 11/11.
- [x] **Directory index + URL-prefix stripping** (src/http/connection.c) — new
      `portico_res_static(res, req, opts)` with `{docroot, url_prefix, index}`;
      `portico_res_file` is the no-prefix/index.html wrapper. A directory request
      serves `<dir>/<index>` (default index.html; re-realpath'd so the index can't
      symlink out either), 403 when absent/disabled (nginx convention). `url_prefix`
      mounts the docroot under a whole leading URL segment (e.g. `/static`), with the
      mount root → directory index; a non-segment match (`/staticfoo`) or
      outside-mount path → 404. Traversal/symlink safety preserved. Tested e2e
      (index served with/without trailing slash, no-index 403, prefix mount + its
      404s) across all 3 backends, ASan-clean, suite 11/11.
- [x] **HEAD for static files** (src/http/connection.c, response.c) — a HEAD on a
      file produces the same status + headers as GET (Content-Type, Content-Length,
      ETag, Last-Modified, Accept-Ranges, and Content-Range/206 for a ranged HEAD)
      but no body and **no file read** — `portico_res_static` sets a `head_only`
      response flag and the builder emits Content-Length from file_size with an empty
      body. Tested (HEAD 200 with correct Content-Length + empty body; ranged HEAD →
      206 + Content-Range + empty body) across 3 backends, ASan-clean, suite 11/11.
- [x] **Multipart/byteranges (multi-range)** (src/http/connection.c) — a request with
      several ranges (`Range: bytes=0-9,100-109,...`) is answered as a
      `multipart/byteranges` 206 with a boundary-delimited body (each part carrying
      its own Content-Type + Content-Range). Bounded: assembled in memory with a cap
      on range count (16) and total bytes (1 MiB) — over that, or if the body can't be
      assembled, it falls back to the spec-allowed full 200 (which streams). None
      satisfiable → 416; a single effective range → the normal single-range path; a
      HEAD multi-range → full HEAD. Tested (parts byte-exact, all-unsatisfiable 416)
      across 3 backends, ASan-clean, suite 11/11.
      Follow-ups: read-ahead (double-buffer) for streaming throughput, io_uring
      batched-submit/SQPOLL tuning, fully-streamed (unbounded) multipart.
- [ ] **Plaintext zero-copy** `sendfile`/splice fast path — TLS connections excluded
      (`sendfile` can't encrypt; same limit nginx has without kTLS).

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
