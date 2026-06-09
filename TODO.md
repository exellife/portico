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
