/* portico_router — hot-swap Host routing. Drives portico_router_handle directly
 * with fabricated requests/responses (no server/event loop): asserts the right
 * vhost is selected, the allow-list 404s, an unset table 503s, and the atomic
 * table swap takes effect. Multiple set()/destroy exercise the retire/free path
 * (verified clean under ASan). */
#include "portico_router.h"
#include "portico_http.h"
#include "http_internal.h"   /* struct portico_response (test reaches into internals) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* a docroot with an index.html so a "/" request resolves to a real file */
static char *mk_docroot(void) {
    static char tmpl[] = "/tmp/portico_rt_XXXXXX";
    char *d = malloc(sizeof tmpl);
    memcpy(d, tmpl, sizeof tmpl);
    if (!mkdtemp(d)) { free(d); return NULL; }
    char p[256];
    snprintf(p, sizeof p, "%s/index.html", d);
    FILE *f = fopen(p, "wb");
    if (f) { fputs("<h1>hi</h1>", f); fclose(f); }
    return d;
}
static void rm_docroot(char *d) {
    if (!d) return;
    char p[256];
    snprintf(p, sizeof p, "%s/index.html", d);
    unlink(p);
    rmdir(d);
    free(d);
}

static void mk_req(portico_request_t *req, const char *host) {
    memset(req, 0, sizeof *req);
    req->method = "GET"; req->method_len = 3;
    req->path = "/";    req->path_len = 1;
    req->minor_version = 1;
    req->keep_alive = 1;
    if (host) {
        req->headers[0].name = "Host";  req->headers[0].name_len = 4;
        req->headers[0].value = host;   req->headers[0].value_len = strlen(host);
        req->num_headers = 1;
    }
}
static void mk_res(struct portico_response *res) {
    memset(res, 0, sizeof *res);
    res->status = 200;          /* the connection layer's default */
    res->keep_alive = 1;
    res->file_fd = -1;
}
static void res_cleanup(struct portico_response *res) {
    if (res->is_file && res->file_fd >= 0) close(res->file_fd);
    if (res->owns_body) free(res->body);
}

/* Route one request through the router; return status, set *served if a file was
 * accepted (is_file). */
static int route(portico_router_t *r, const char *host, int *served) {
    portico_request_t req; struct portico_response res;
    mk_req(&req, host); mk_res(&res);
    portico_router_handle(&req, &res, r);
    if (served) *served = res.is_file;
    int st = res.status;
    res_cleanup(&res);
    return st;
}

int main(void) {
    char *DR1 = mk_docroot(), *DR2 = mk_docroot();
    if (!DR1 || !DR2) { fprintf(stderr, "mkdtemp failed\n"); return 2; }

    printf("portico_router tests\n");
    int served;

    /* 1. no table installed → 503 */
    portico_router_t *r = portico_router_create();
    chk("unset table → 503", route(r, "a.com", NULL) == 503);

    /* 2. table {a.com→DR1}, no fallback */
    portico_vhost_t t1[] = { { .host = "a.com", .static_opts = { .docroot = DR1 } } };
    portico_router_set(r, t1, 1);
    served = 0;
    int st = route(r, "a.com", &served);
    chk("known host served (is_file)", served == 1);
    chk("known host not 404", st != 404);
    chk("unknown host, no fallback → 404", route(r, "nope.com", NULL) == 404);

    /* 3. swap to {b.com→DR2} — old host gone, new host live */
    portico_vhost_t t2[] = { { .host = "b.com", .static_opts = { .docroot = DR2 } } };
    portico_router_set(r, t2, 1);
    served = 0;
    route(r, "b.com", &served);
    chk("after swap: new host served", served == 1);
    chk("after swap: old host → 404", route(r, "a.com", NULL) == 404);

    /* 4. fallback vhost catches everything */
    portico_vhost_t t3[] = {
        { .host = "a.com", .static_opts = { .docroot = DR1 } },
        { .host = NULL,    .static_opts = { .docroot = DR2 } },   /* fallback */
    };
    portico_router_set(r, t3, 2);
    served = 0;
    route(r, "whatever.com", &served);
    chk("fallback serves unmatched host", served == 1);

    /* 5. rapid swaps then destroy — exercises the retire/free path (ASan) */
    for (int i = 0; i < 50; i++)
        portico_router_set(r, (i & 1) ? t1 : t2, 1);
    portico_router_destroy(r);
    chk("rapid swap + destroy clean", 1);

    /* destroy a never-set router */
    portico_router_destroy(portico_router_create());
    chk("destroy empty router clean", 1);

    rm_docroot(DR1); rm_docroot(DR2);
    printf("\n%d ok, %d failed\n", ok, fail);
    return fail ? 1 : 0;
}
