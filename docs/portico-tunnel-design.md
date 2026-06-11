# portico-tunnel — design sketch

A reverse-tunnel companion to portico that lets a server behind a **dynamic IP,
NAT, or CGNAT** be reachable from the public internet — while keeping the two things
Cloudflare Tunnel gives up: **end-to-end TLS the relay can't decrypt**, and
**portico issuing its own real certificate**.

Status: design only. Not built. This scopes the architecture and, importantly, which
parts we **reuse from proven projects** versus what we actually write.

---

## 1. Problem

A home/edge box often can't accept inbound connections:
- **Dynamic IP** — the address changes. (Solvable alone with DDNS.)
- **NAT / CGNAT** — there is *no* forwardable public IP at all. DDNS can't help; you
  must reach *out*.

The general fix is a **reverse tunnel**: an agent on the private box dials out to a
relay on a public box and holds the connection open; the relay routes inbound public
traffic back down that tunnel. Outbound-only is the whole trick — NAT, CGNAT, and a
changing IP all stop mattering, because the private box is never the one being
reached.

We already own the missing half: a **public box with a stable IP** (the Oracle VM)
that can be the relay, and **portico** itself as the thing being exposed.

## 2. Goals / non-goals

**Goals**
- Agent is **outbound-only** → NAT/CGNAT/dynamic-IP agnostic; transparent reconnect.
- **End-to-end TLS**: relay routes by SNI *without decrypting* (passthrough). The home
  box terminates TLS; the relay cannot read traffic. (Strictly better trust model than
  Cloudflare Tunnel, which terminates at their edge.)
- **portico's own ACME keeps working** through the tunnel (see §6) — the home box owns
  a trusted Let's Encrypt cert; the relay never holds its key.
- **Multi-tenant routing**: one relay serves several agents/hostnames, picked by SNI.
- **One binary, two modes**: `--relay` (on the VM) and `--agent` (at home), reusing
  portico's existing machinery.

**Non-goals (v1)**
- Arbitrary UDP / arbitrary TCP (start with HTTPS + WebSocket; TLS-over-TCP is enough).
- Global anycast, multi-relay load balancing, a web dashboard.
- Replacing Cloudflare's DDoS scale — this is personal/small-fleet hosting.

## 3. Architecture

```
                         (public IP, stable)                 (private, dynamic IP / CGNAT)
  public client ───TLS──►   RELAY                               AGENT  ───►  portico (localhost:443)
                          :443 ingress  ◄──── persistent tunnel ────  dials OUT, holds open
                          :80  ingress (ACME)   (mux, TLS, authed)     proxies streams to local app
```

- **Relay** (`--relay`, on the VM): public ingress on :443 (and :80 for ACME). Reads
  each new connection's SNI, finds the agent that registered that hostname, and opens
  a multiplexed **stream** to it carrying the raw bytes. Never decrypts :443 traffic.
- **Agent** (`--agent`, at home): on startup dials the relay over TLS, authenticates,
  and **registers** the hostnames it serves. For each inbound stream it opens a local
  connection to portico and splices bytes both ways.

## 4. Reuse, don't reinvent

This is a **well-trodden** pattern (ngrok, frp, rathole, chisel, bore, inlets,
Tailscale Funnel). We are not inventing a protocol — we're assembling proven parts and
adapting them to portico's needs (C, epoll, its TLS/ACME stack, E2E passthrough).

| Concern | Reuse | Why / how we adapt |
|---|---|---|
| **Stream multiplexing** | **nghttp2** (C, battle-tested HTTP/2) | Many public conns over one tunnel = HTTP/2 streams. Mature C lib, no hand-rolled framing. Alt: a QUIC lib (msquic / ngtcp2 / lsquic) if we want connection-migration + UDP later. |
| **Tunnel transport / auth** | **OpenSSL** (already linked) | Agent↔relay link is TLS with **mTLS** (client cert) or a pre-shared token. Don't invent crypto or a key exchange. |
| **SNI routing (no decrypt)** | **ClientHello / `ssl_preread` pattern** | HAProxy's `ssl_preread` and nginx's `ssl_preread` are the reference designs for SNI-based routing without termination. Adapt the small ClientHello-parse routine (or OpenSSL `SSL_client_hello_cb`) to pick the agent, then splice raw bytes. |
| **Event loop / buffers / async I/O** | **portico core** | The relay's connection handling is exactly portico's epoll loop + buffer pools + aio. Reuse wholesale; the relay is "portico that forwards instead of serves." |
| **Certificates** | **portico's ACME** (already built) | Relay can mint its *own* cert for the control endpoint; home box mints *its* cert through the tunnel (§6). Nothing new. |
| **Control protocol shape, reconnect, backoff** | patterns from **chisel / frp / rathole / bore** | Study their register/heartbeat/reconnect flows and copy the *shape* (not the code — different languages). These are solved; we adapt, not redesign. |

What we **actually write** is the glue: the relay's SNI→agent routing table, the
agent's local-proxy to portico, the HTTP-01 relay path (§6), the `--relay`/`--agent`
config, and wiring it all onto portico's loop with portico's test rigor.

## 5. Wire protocol (sketch)

Two channels, both inside the agent↔relay TLS connection (multiplexed via nghttp2):

1. **Control stream** (stream 1, persistent):
   - `HELLO {agent_id, auth_token | mTLS, hostnames:[...], modes:{host: passthrough|terminate}}`
   - `REGISTER_OK {lease}` / `REGISTER_ERR {reason}`
   - `PING`/`PONG` heartbeats (detect dead tunnels; agent reconnects with backoff).
2. **Data streams** (one per public connection):
   - Relay → agent: `OPEN {stream_id, hostname, client_ip, proto: tls|http01}` then raw bytes.
   - Bytes flow both directions until either side closes; relay maps `stream_id` ↔ the
     public socket, agent maps it ↔ a fresh `localhost` socket to portico.

Routing: relay peeks SNI on a new :443 connection → looks up the agent that registered
that hostname → opens a data stream tagged with it. No agent for that SNI → relay
closes (or serves a static 502).

## 6. The interesting part — TLS & ACME through the tunnel

**TLS modes (per hostname, configurable):**

- **A. Passthrough (default, end-to-end).** Relay reads SNI only and splices the
  *encrypted* ClientHello + everything after, untouched, to the agent. portico at home
  terminates TLS. The relay literally cannot read the plaintext or the private key.
  This is the headline property Cloudflare Tunnel does not offer.
- **B. Relay-terminates (opt-in).** Relay holds the cert (via portico's ACME on the
  relay) and forwards plaintext down the tunnel. Simpler, lets the relay do caching/
  routing on L7, but the relay sees plaintext. For weak home boxes or non-secret sites.

**Keeping portico's HTTP-01 ACME alive (mode A):** because *we* own the relay, it also
forwards **:80** down the tunnel. So Let's Encrypt's HTTP-01 validation request lands
on the relay, gets relayed to the home agent, and is answered by **portico's existing
HTTP-01 responder** — portico issues its *own* trusted cert through the tunnel, key
never leaving home. (Fallback: **DNS-01**, which needs no inbound port at all but
requires a DNS-provider API — a natural future `portico` challenge provider.)

Net result for mode A: **home server, dynamic IP / behind CGNAT, its own trusted
Let's Encrypt cert, relay cannot decrypt.** That's the design's reason to exist.

## 7. Operations

- **Reconnect**: agent re-dials on drop with exponential backoff + jitter; a dynamic-IP
  change is just a reconnect, invisible to clients mid-reconnect (brief blip only).
- **Agent down**: relay returns a static 502 (or holds briefly) for that hostname.
- **Security of the relay**: it is public ingress, so it gets the same hardening as
  portico's listener (accept-time IP gating, slowloris reaping, the audited paths).
  mTLS/token on the control channel; per-agent hostname allow-list to stop hijacking.
- **Bottleneck**: the relay + the home uplink are the ceiling (see the perf notes —
  portico itself won't be the limit). One relay is fine for personal / small-fleet use.

## 8. Phased plan (each phase independently testable, portico-style)

1. **Splice MVP** — one agent, one hostname, **no mux** (one tunnel conn per public
   conn), TCP passthrough. Proves the outbound-only path end to end. (≈ `bore`.)
2. **Mux + auth + reconnect** — nghttp2 streams over one TLS conn; mTLS/token; heartbeat
   + backoff. Now it scales past one connection and survives drops/IP changes.
3. **SNI passthrough + multi-tenant** — ClientHello SNI parse → routing table → multiple
   agents/hostnames on one relay, no decryption.
4. **ACME through the tunnel** — relay forwards :80 so portico's HTTP-01 issues E2E
   (and/or DNS-01 provider). Home box owns a trusted cert.
5. **Harden** — fold into portico's loop/buffers, ASan/TSan, an integration test that
   stands up relay+agent+portico on loopback and issues a cert through it (mirrors the
   Pebble e2e we already have).

## 9. Open questions

- **Mux choice**: nghttp2 (HTTP/2, simplest reuse, TCP) vs a QUIC lib (better on lossy
  links, connection migration, but a heavier C dependency). Start nghttp2; revisit QUIC.
- **Where it lives**: a `portico-tunnel` binary vs a mode of `portico`. Likely a separate
  binary that links the portico core lib (same pattern as the examples).
- **DNS-01 provider**: which DNS APIs to support first (Cloudflare DNS, deSEC, etc.) if
  we want ACME without forwarding :80.

---

### TL;DR

Yes, very buildable, and it pairs naturally with portico. We reuse the proven parts —
**nghttp2** for muxing, **OpenSSL** for the authed tunnel, the **`ssl_preread`/
ClientHello** SNI-routing pattern, **portico's own loop + ACME** — and adapt the shape
of existing tunnels (chisel/frp/rathole/bore). What's genuinely *ours* is the
combination: **end-to-end TLS passthrough + portico minting its own cert through the
tunnel**, giving a CGNAT-friendly home server that still owns its HTTPS — which the
off-the-shelf tunnels don't.
