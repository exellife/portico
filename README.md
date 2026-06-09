# portico

A single-binary **HTTP/1.1 + WebSocket** server library for C. One TCP listener,
one epoll event loop, per-connection dispatch to either the WebSocket path or an
HTTP route handler.

- **WebSocket core** — a hardened, RFC 6455 implementation (`src/ws/`).
- **HTTP core** — [picohttpparser](https://github.com/h2o/picohttpparser) (MIT) for
  request parsing + portico's response/router/keep-alive layer (`src/http/`, WIP).

Vendored, zero external dependencies, MIT-compatible throughout — drops into a
single static binary that installs anywhere on Linux.

## Status

- ✅ WebSocket transport: hardened, 34-case adversarial harness (sizes 0 → 1 MB,
  fragmentation, control frames, RFC framing rules, partial/pipelined, concurrency).
- ✅ HTTP/1.1 layer: routing, keep-alive, pipelining, Content-Length bodies,
  16-case adversarial harness (malformed→400, oversized body→413, oversized
  headers→431, byte-at-a-time, HTTP/1.0 close, 500 KB round-trip, concurrency).
- ✅ Unified: one listener serves both — a WebSocket upgrade takes the WS path,
  everything else is HTTP. Register `callbacks.on_http_request` to enable HTTP.
- ✅ Clean under AddressSanitizer + UBSan across both harnesses.

### Using it

```c
#include "portico.h"
ws_callbacks_t cb = {0};
cb.on_binary_message = my_ws_echo;     /* WebSocket */
cb.on_http_request   = my_http_router; /* HTTP — see examples/http_server.c */
ws_server_start(server, &cb);
```

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Options: `-DPORTICO_ASAN=ON` (AddressSanitizer + UBSan), `-DPORTICO_BUILD_TESTS=OFF`,
`-DPORTICO_BUILD_EXAMPLES=OFF`.

## Test

```sh
ctest --test-dir build --output-on-failure
```

Each test boots an example server on a free port (`tests/run_with_server.py`) and
drives it with a raw-socket harness (needs python3). `tests/ws_test.py` is the
WebSocket adversarial suite.

## WebSocket bug-fix history (vs. the original wslib)

The WS core was audited adversarially; these were found and fixed here:

1. **16 KB receive cap** — fixed buffer never grew; frames > 16 KB were dropped.
   Now a drain-to-EAGAIN read-loop grows the buffer up to `max_message_size`.
2. **Split frame header dropped the connection** — incomplete headers returned an
   error instead of "need more data". Fixed.
3. **Unmasked client frames accepted** — RFC 6455 §5.1 violation; now rejected.
4. **Clean close logged as an error** — distinct `WS_FRAME_CLOSE_REQUESTED` sentinel.
5. **Zero-length binary messages couldn't be sent** — three layers rejected
   `len == 0`; now valid empty frames round-trip.

(Plus a latent double-`memmove` corruption in the old frame loop, removed in the rewrite.)
