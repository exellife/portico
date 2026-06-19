/* Hot-swappable Host router — see include/portico_router.h.
 *
 * The live table is a tiny immutable snapshot {vhosts, n} behind an atomic pointer.
 * set() publishes a new snapshot and retires the previous one, freeing the snapshot
 * retired by the PRIOR set — by then any handler that loaded it has long returned
 * (sets are reloads, far apart). Only the 16-byte snapshot is owned here; the vhost
 * array itself is borrowed (owned by the config object), and config pointers never
 * outlive a handler call, so this grace is sufficient. */
#include "portico_router.h"

#include <stdlib.h>
#include <stdatomic.h>

typedef struct {
    const portico_vhost_t *vhosts;
    size_t                 n;
} router_table_t;

struct portico_router {
    _Atomic(router_table_t *) current;   /* NULL until first set */
    router_table_t           *retired;   /* previous snapshot, freed on the next set */
};

portico_router_t *portico_router_create(void) {
    return calloc(1, sizeof(portico_router_t));   /* current=NULL, retired=NULL */
}

void portico_router_set(portico_router_t *r, const portico_vhost_t *vhosts, size_t n) {
    if (!r) return;
    router_table_t *t = malloc(sizeof *t);
    if (!t) return;                       /* keep the current table on OOM */
    t->vhosts = vhosts;
    t->n      = n;

    router_table_t *old = atomic_exchange(&r->current, t);
    /* Free the snapshot retired one set ago — safe now (a handler that read it has
     * returned), then retire the one we just replaced. */
    free(r->retired);
    r->retired = old;
}

int portico_router_handle(const portico_request_t *req, portico_response_t *res,
                          void *user_data) {
    portico_router_t *r = (portico_router_t *)user_data;
    router_table_t *t = r ? atomic_load(&r->current) : NULL;
    if (!t || t->n == 0) {
        portico_res_text(res, 503, "no sites configured\n");
        return 0;
    }
    portico_res_vhost(res, req, t->vhosts, t->n);
    return 0;
}

void portico_router_destroy(portico_router_t *r) {
    if (!r) return;
    free(atomic_load(&r->current));
    free(r->retired);
    free(r);
}
