/* ============================================================================
 * portico — hot-swappable Host router.
 *
 * Holds the live vhost table behind an atomic pointer so it can be replaced at
 * runtime (config reload) with zero downtime: register portico_router_handle as
 * callbacks.on_http_request (http_user_data = the router), and call
 * portico_router_set() from the reload path to swap the table in atomically.
 *
 * Independent of the JSON loader — it just serves a portico_vhost_t[] (which the
 * loader happens to produce). See docs/portico-config-design.md.
 * ============================================================================ */
#ifndef PORTICO_ROUTER_H
#define PORTICO_ROUTER_H

#include "portico_http.h"   /* portico_vhost_t, request/response types */
#include <stddef.h>

typedef struct portico_router portico_router_t;

/* Create an empty router (no table yet → every request gets 503 until set). */
portico_router_t *portico_router_create(void);
void              portico_router_destroy(portico_router_t *r);

/* Atomically install `vhosts` (n entries) as the live routing table. The array is
 * BORROWED: the caller owns the vhost memory and must keep it alive until a later
 * set replaces it AND one further set has happened (one-generation grace), or until
 * destroy — same discipline as ws_server_reload_tls's retired context. New requests
 * pick up the new table immediately; a request already in its handler keeps the
 * table it loaded. Call from a single reload thread (not thread-safe against itself). */
void portico_router_set(portico_router_t *r, const portico_vhost_t *vhosts, size_t n);

/* portico_http_handler_fn: register as callbacks.on_http_request with
 * http_user_data = the router. Routes by Host (via portico_res_vhost) against the
 * currently-installed table; 503 if none is installed yet. */
int portico_router_handle(const portico_request_t *req, portico_response_t *res,
                          void *user_data);

#endif /* PORTICO_ROUTER_H */
