# portico-config — design sketch

A config file for portico, so a deployment's **sites** (domains → docroots, TLS,
ACME) live in a file you edit and reload — not in C you recompile, nor in env vars
read once at boot. The target: **add a static site by editing a file and sending
SIGHUP — no restart, no rebuild.**

Status: design only. Not built. This scopes the format, the loader, and the reload
model, and is careful to mark what we **reuse** (almost everything) versus what we
actually **write** (a loader + one generalization of the cert hot-swap).

---

## 1. Problem

portico is a library: today a deployment hard-codes its sites. Using the example
binary you pass `VHOSTS="a.com:/srv/a"`, `tls_sni_certs[]`, and `ACME_DOMAINS` — all
read once in `main()`. Writing your own binary, the `portico_vhost_t[]` array is C.

Either way, **adding a second site means editing config-in-code/env and restarting**
— worst case editing C and recompiling. For a box hosting a handful of static sites
that churn (a new marketing page, a new docs subdomain), that is more friction than
the work deserves. The serving primitives already exist; only the *wiring* is rigid.

## 2. Goals / non-goals

**Goals**
- A declarative config file describes the listener, TLS, ACME, and the **`sites[]`**
  (host → docroot + static options).
- **Add / change / remove a static site at runtime** via SIGHUP — zero downtime for
  every other site, no restart, no recompile.
- **Transactional reload**: a bad edit is rejected whole; the running config keeps
  serving. A typo never takes the server down.
- Reuse the proven machinery: `portico_res_vhost`, SNI cert groups, the ACME manager,
  and the `_Atomic`-swap-with-grace pattern already shipped for `ws_server_reload_tls`.
- Core stays file-I/O-free and dependency-free; the loader is a separate opt-in module.

**Non-goals**
- **Dynamic apps / request logic in config.** A file cannot hold a C function pointer.
  Code-registered `on_http_request` handlers are out of scope (see §10).
- **Reverse-proxy / upstream forwarding.** portico does not forward to separate app
  processes; "site" means a docroot it serves itself. (That is a different feature.)
- **Hot-changing structural state** — listen port, bind address, `thread_count` — stays
  restart-only (§8). The data plane reloads; the socket/thread topology does not.

## 3. The one decision behind the scope

We deliberately restrict "an app" to **a static site** (a docroot / SPA). That is what
makes this small: portico already has every primitive — `portico_res_vhost` (Host →
docroot), SNI cert selection, the ACME manager, async traversal-safe static serving
with precompression / cache-control / SPA-fallback. Nothing new is needed to *serve*;
the work is only to *load and reload* the config that drives them.

## 4. File format

JSON, parsed with the already-vendored **cJSON** (zero new dependency, in-tree and
already exercised by the ACME client). JSON's one wart is no comments; acceptable for
v1, revisitable later (a thin INI/TOML layer is a strictly bigger hardening surface).

```jsonc
{
  "listen":  { "port": 443, "threads": 4 },     // structural — restart to change (§8)
  "trust_proxy": false,

  "tls": {
    "mode": "acme",                              // "acme" | "files" | "off"
    "acme": {
      "directory": "https://acme-v02.api.letsencrypt.org/directory",
      "email": "ops@example.com",
      "account_key": "/var/lib/portico/acme/account.key",
      "cert_dir": "/var/lib/portico/acme",       // issued chain+key live here
      "renew_days": 30,
      "challenge_port": 80
    }
  },

  "sites": [
    {
      "host": "a.com",
      "docroot": "/srv/a",
      "static": {
        "precompressed": true,
        "cache_control": "public, max-age=31536000, immutable",
        "spa_fallback": "index.html",
        "dir_redirect": true
      }
    },
    {
      "host": "*.b.com",
      "docroot": "/srv/b",
      "tls": { "cert": "/etc/ssl/b.crt", "key": "/etc/ssl/b.key" }  // per-site override
    },
    { "host": null, "docroot": "/srv/default" }  // fallback vhost (unmatched Host)
  ]
}
```

A `site` is the unit that **fans out to all three layers** that today are three arrays
kept in sync by hand:
- its `host` + `docroot` + `static` → a `portico_vhost_t` (Host routing),
- its `host` → a cert (via ACME SANs, or a per-site `tls` override → an SNI entry),
- its `host` → a domain the ACME manager keeps renewed.

`static` keys map 1:1 onto `portico_static_opts_t` (`precompressed`, `cache_control`,
`spa_fallback`, `dir_redirect`, `index`, `url_prefix`). `host: null` is the fallback
vhost, matching `portico_res_vhost`'s existing `host==NULL` semantics.

## 5. The loader

A new opt-in module, `src/config/portico_config.c` + `portico_config.h`, exposing:

```c
typedef struct portico_config portico_config_t;   /* owns all parsed strings */

portico_config_t *portico_config_load(const char *path, char *err, size_t errcap);
void              portico_config_free(portico_config_t *cfg);

/* Views into the owned config, for handing to the existing APIs. */
const ws_config_t      *portico_config_ws(const portico_config_t *);     /* port, TLS, SNI */
const portico_vhost_t  *portico_config_vhosts(const portico_config_t *, size_t *n);
```

`load` parses, **validates**, and allocates an object that **owns every string**
(hostnames, docroots, cert paths) for the server's lifetime. It produces exactly the
structs portico already consumes — `ws_config_t` (with `tls_sni_certs[]` populated from
per-site overrides) and a `portico_vhost_t[]`. No core API changes; this is pure
marshalling. Validation up front: docroots exist and are directories, cert/key files
readable, no duplicate hosts, exactly ≤1 fallback, port in range.

## 6. Lifecycle — first boot

```
portico_config_load(path)            → owned config
  → ws_server_create(config_ws)      → listener + SNI group (existing)
  → if tls.mode == "acme":
        portico_acme_manager_start({ domains = every site host, … , on_renewed })
        (ensures a cert NOW, blocking on first issue, then renews in background)
  → ws_server_start(server, { .on_http_request = config_router })
```

`config_router` is a tiny built-in handler the binary registers once: it just calls
`portico_res_vhost(res, req, <current vhost table>, n)`. The vhost table it reads is the
hot-swappable pointer from §7 — that indirection is the whole reload trick.

## 7. Hot reload — SIGHUP

SIGHUP already means "reload" in portico (it drives `ws_server_reload_tls`). We extend
it to re-read the file and rebuild the swappable state, **transactionally**:

```
on SIGHUP (flag → handled on the main loop, not in the handler):
  new = portico_config_load(path)
  if (!new)  → log error, KEEP running config, done     // bad edit never applies
  atomically swap the vhost-table pointer  (old retired one generation, §9)
  diff sites vs running:
     - new host          → register with ACME manager; rebuild+swap SNI group when its
                            cert lands (two-phase, §9)
     - removed host      → stop serving it (drop from table); stop renewing (optional)
     - changed docroot / static opts → already covered by the table swap
  reload certs: ws_server_reload_tls(server)             // existing
  free the config generation retired by the PREVIOUS reload
```

The atomic swap is the **same** mechanism as the shipped cert reload: build the new
thing fully, validate, `atomic_exchange` the pointer, free the prior generation one
reload later. `config_router` reads the pointer once per request; a request in flight
during a swap keeps using the table it loaded.

**Why the grace window is cheap here.** Earlier analysis confirmed config pointers do
not outlive a handler call: `portico_res_static` consumes `docroot` / `cache_control` /
`spa_fallback` synchronously (resolves the path, opens the fd, copies headers) *during*
the call; the async file transfer afterward carries only `{fd, buffer, headers}`. So a
retired vhost table is unreferenced the moment every thread has returned from its
current handler — a short, bounded window. Matching `tls_ctx_retired`'s "free on next
reload" (reloads are far apart) is more than sufficient; no RCU/epoch machinery needed.

## 8. Hot-swappable vs restart-required

| Config | Reload behavior |
|--------|-----------------|
| `sites[]` — add / remove / re-point docroot | **hot** (vhost table swap) |
| `static` opts (cache-control, precompress, SPA, index, dir-redirect) | **hot** (rides the table) |
| TLS certs (renewal, dropped-in files) | **hot** (`ws_server_reload_tls`, shipped) |
| Per-site SNI cert add / remove | **hot** (rebuild SNI group + swap) |
| ACME domain set | **hot** (two-phase: routing now, HTTPS when issued — §9) |
| `trust_proxy` | hot or restart — TBD, low value either way |
| **`listen.port` / bind address** | **restart** (socket bound at create) |
| **`listen.threads`** | **restart** (epoll-thread pool + conn distribution built at start) |

This mirrors nginx: most of a reload is live; new listen sockets / worker topology are
the part that genuinely can't be swapped under load. On reload, a changed `port`/
`threads` is **logged and ignored** (with a "restart required" warning) rather than
silently dropped — never silently misapplied.

## 9. Certs for new domains — the real wrinkle

A brand-new domain cannot serve HTTPS until its cert exists, and ACME issuance is
**async (minutes)**, served over HTTP-01 on :80. So adding a site with `mode: acme` is
**two-phase**, and both phases happen without a restart:

1. **On SIGHUP, immediately:** swap in the new routing and register the domain with the
   manager. The site answers over **plain HTTP at once** (including the `/.well-known/
   acme-challenge/` path the responder needs). HTTPS for it is not yet available.
2. **Minutes later, when the cert lands:** the manager's existing `on_renewed` hook
   fires `ws_server_reload_tls`; the SNI group / default cert rebuilds and the new
   domain's **HTTPS goes live** — still no restart.

Adding a site whose cert already exists (a per-site `tls` override, or a cert already on
disk) is single-phase: routing + SNI swap together, instant.

**One-cert-with-SANs vs per-site certs.** The shipped ACME manager issues **one cert
carrying every domain as a SAN** (one `cert_path`, `domains[]` → SANs). For a handful of
static sites that is the simplest model and needs *zero* new ACME code: the default cert
covers all hosts, SNI isn't even required, and a reload just re-issues with the new SAN
set. Trade-offs to weigh: every add re-issues the whole cert, and all domains are
co-listed in CT logs. Per-site certs (one manager or order per host, wired through SNI)
give isolation at the cost of more moving parts. **Recommendation: v1 = single multi-SAN
cert** (matches what exists); per-site certs an opt-in via the `tls` override.

## 10. What stays in code

The file covers the declarative 90%. Two things remain code, by design:
- **Dynamic handlers.** If a deployment also wants real request logic, it keeps its own
  `on_http_request` and falls through to the config-driven vhost table for anything it
  doesn't handle — exactly what `examples/http_server.c` does today. The config router is
  just the default when no custom handler is supplied.
- **A future "named backend" indirection** (config maps `host → "appName"`, code
  registers `appName → fn`) would let ops point a *new domain* at an *already-compiled*
  app without a rebuild. Out of scope here; noted so the schema can grow into it (a site
  could later carry `"handler": "appName"` instead of `"docroot"`).

## 11. Ownership & memory model

- One `portico_config_t` owns all strings for the lifetime it is the *current* config.
- At most **two generations** are live at once: current + the one retired by the last
  reload (freed on the next reload), mirroring `tls_ctx` / `tls_ctx_retired`.
- The vhost table handed to `config_router` is an `_Atomic(const portico_vhost_t *)`
  plus its count; readers load both under the convention that the count belongs to the
  pointer's generation (pack them in a small struct swapped by one pointer to avoid a
  torn pointer/count pair).

## 12. What we reuse vs write

**Reuse (unchanged):** `ws_server_create/start`, `ws_config_t`, `portico_vhost_t` +
`portico_res_vhost`, `portico_static_opts_t` + `portico_res_static`, the SNI cert group,
`ws_server_reload_tls`, the entire ACME manager, SIGHUP plumbing, cJSON.

**Write (new):**
1. `portico_config.c/.h` — the JSON loader + validation + owned config object (the bulk).
2. The `_Atomic` vhost-table swap + a `config_router` default handler (~the cert-reload
   pattern, generalized).
3. SIGHUP → transactional re-read + diff (new/removed domains → ACME manager).
4. A small `portico` binary (or extend the example) that ties load → create → ACME →
   start → reload together and is driven *only* by the file.

## 13. Testing

- **Loader unit tests** (dependency-free, like `acme_parse_test.c`): valid files →
  expected structs; malformed/duplicate-host/missing-docroot → rejected with a message.
- **Reload integration test:** boot with one site, `curl` it; SIGHUP after appending a
  second site to the file; assert the second serves *and the first never dropped a
  request* (drive a keep-alive loop across the reload). Reuse `tests/run_with_server.py`.
- **Bad-reload test:** SIGHUP with a syntactically broken file → server keeps serving the
  old config, logs the error, exits non-zero never.
- **Two-phase ACME** against Pebble (reuse `acme_pebble_e2e`): add a domain at runtime →
  HTTP-01 challenge served immediately → HTTPS live after issuance, no restart.
- ASan/TSan across a reload storm (repeated SIGHUP under concurrent traffic) to prove the
  table-swap grace window is race-free.

---

## Summary

Static-sites-only is what makes this small: every serving primitive already exists, so
the work is a **JSON loader** plus **one generalization of the cert hot-swap** to the
vhost table, wired to SIGHUP transactionally. The payoff is the workflow we wanted —
**append a `sites[]` block, `kill -HUP`, and the new site is live immediately on HTTP and
within minutes on HTTPS, with zero restart, zero recompile, and not a single dropped
request on the sites already running.**
