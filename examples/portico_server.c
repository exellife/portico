/* portico — config-file-driven standalone server.
 *
 *   portico_server <config.json>     (or PORTICO_CONFIG=<path> portico_server)
 *
 * Loads a JSON config (listener, TLS, sites[]) and serves it: Host-routed static
 * sites over the built-in hot-swap router. SIGHUP re-reads the file transactionally
 * — a valid edit swaps routing (and installs any new per-site HTTPS certs) with zero
 * downtime; a broken edit is logged and the running config is kept. SIGINT/SIGTERM
 * drain and exit. See docs/portico-config-design.md.
 *
 * Lifetime note: ws_server_create() shallow-copies the config, so the server borrows
 * the FIRST config's default-cert / SNI / bind strings — that config is pinned for
 * the server's life. Reloaded configs back only the router's borrowed vhost table,
 * so they ride a one-generation grace; runtime certs are deep-copied by the server. */
#include "portico.h"
#include "portico_config.h"
#include "portico_router.h"
#include "acme_internal.h"   /* built-in ACME manager (tls.mode: acme) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t g_reload = 0, g_stop = 0;
static void on_hup(int s)  { (void)s; g_reload = 1; }
static void on_term(int s) { (void)s; g_stop = 1; }

static const char            *g_path;
static ws_server_t           *g_server;
static portico_router_t      *g_router;
static portico_config_t      *g_initial;       /* pinned: server borrows its strings */
static portico_config_t      *g_cur, *g_prev;  /* reloaded configs (one-gen grace) */
static portico_acme_manager_t *g_acme;         /* non-NULL only in tls.mode: acme */

/* ACME renewed the cert on disk (called from the manager's renewal thread, a normal
 * context — not a signal handler): hot-swap it in with zero downtime. */
static void on_cert_renewed(void *ud) {
    (void)ud;
    if (g_server) ws_server_reload_tls(g_server);
}

/* Start the ACME manager for all site hostnames: issues one multi-SAN cert (now,
 * synchronously) into the configured cert_dir, serves HTTP-01 challenges itself, and
 * renews in the background → on_cert_renewed. Points `ws` at the issued files so the
 * listener terminates TLS with them. Returns 0, or -1 on failure. The cert/key path
 * buffers are static (live for the process). NOTE: the SAN set is fixed at startup —
 * adding a new ACME domain needs a restart in v1 (files mode supports runtime add). */
static int start_acme(const portico_config_t *cfg, ws_config_t *ws) {
    const portico_acme_settings_t *a = portico_config_acme(cfg);
    size_t nd;
    const char *const *domains = portico_config_acme_domains(cfg, &nd);
    if (nd == 0) { fprintf(stderr, "acme: config has no site hostnames to certify\n"); return -1; }

    static char cert[512], key[512];
    snprintf(cert, sizeof cert, "%s/cert.pem", a->cert_dir);
    snprintf(key,  sizeof key,  "%s/cert.key", a->cert_dir);

    portico_acme_manager_config_t mc = {
        .directory_url       = a->directory_url,
        .account_key_path    = a->account_key_path,
        .cert_path           = cert,
        .cert_key_path       = key,
        .email               = a->email,
        .ca_file             = a->ca_file,
        .domains             = domains,
        .ndomains            = nd,
        .renew_within_days   = a->renew_days,
        .challenge_port      = a->challenge_port,
        .on_renewed          = on_cert_renewed,
    };
    fprintf(stderr, "acme: obtaining a certificate for %zu domain(s) via %s ...\n",
            nd, a->directory_url);
    g_acme = portico_acme_manager_start(&mc);
    if (!g_acme) { fprintf(stderr, "acme: initial issuance failed\n"); return -1; }
    fprintf(stderr, "acme: certificate ready (%s); HTTP-01 on :%d\n",
            cert, portico_acme_manager_challenge_port(g_acme));
    ws->tls_cert_file = cert;
    ws->tls_key_file  = key;
    return 0;
}

/* Apply a freshly-loaded config to the running server: swap the routing table, and
 * (re)install each site's per-host cert so a new HTTPS site is served without a
 * restart. Best-effort on certs — the load already validated them readable; a
 * plaintext listener just no-ops (add_sni_cert returns -1). */
static void apply_config(portico_config_t *cfg) {
    size_t n;
    const portico_vhost_t *vh = portico_config_vhosts(cfg, &n);
    portico_router_set(g_router, vh, n);

    const ws_config_t *ws = portico_config_ws(cfg);
    for (size_t i = 0; i < ws->tls_sni_cert_count; i++) {
        const ws_tls_sni_cert_t *c = &ws->tls_sni_certs[i];
        if (ws_server_add_sni_cert(g_server, c->hostname, c->cert_file, c->key_file) != 0)
            fprintf(stderr, "reload: could not install cert for '%s'\n", c->hostname);
    }
}

/* Transactional reload: parse + validate the whole file first; only on success swap
 * it in. On any error, log and keep the running config. */
static void do_reload(void) {
    char err[256] = {0};
    portico_config_t *nc = portico_config_load(g_path, err, sizeof err);
    if (!nc) {
        fprintf(stderr, "reload: %s — keeping current config\n", err);
        return;
    }
    apply_config(nc);
    if (g_prev) portico_config_free(g_prev);   /* freed: its table was replaced a reload ago */
    g_prev = g_cur;
    g_cur  = nc;
    fprintf(stderr, "reload: applied new config\n");
}

int main(int argc, char **argv) {
    g_path = argc > 1 ? argv[1] : getenv("PORTICO_CONFIG");
    if (!g_path) { fprintf(stderr, "usage: portico_server <config.json>\n"); return 2; }

    char err[256] = {0};
    g_initial = portico_config_load(g_path, err, sizeof err);
    if (!g_initial) { fprintf(stderr, "config: %s\n", err); return 1; }

    /* A local copy so ACME can overlay the issued cert paths; ws_server_create
     * shallow-copies it, borrowing string pointers that outlive this scope (the
     * pinned g_initial, plus the static cert/key buffers from start_acme). */
    ws_config_t ws = *portico_config_ws(g_initial);
    if (portico_config_tls_mode(g_initial) == PORTICO_TLS_ACME)
        if (start_acme(g_initial, &ws) != 0) return 1;

    g_server = ws_server_create(&ws);
    if (!g_server) { fprintf(stderr, "server create failed\n"); return 1; }

    g_router = portico_router_create();
    size_t n;
    const portico_vhost_t *vh = portico_config_vhosts(g_initial, &n);
    portico_router_set(g_router, vh, n);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  on_hup);
    signal(SIGINT,  on_term);
    signal(SIGTERM, on_term);

    ws_callbacks_t cb = {0};
    cb.on_http_request = portico_router_handle;
    cb.http_user_data  = g_router;
    if (ws_server_start(g_server, &cb) != 0) { fprintf(stderr, "server start failed\n"); return 1; }

    fprintf(stderr, "portico: serving %zu site(s) on :%u (%s)\n", n, ws.port,
            ws.tls_cert_file ? "https" : "http");

    while (!g_stop) {
        if (g_reload) { g_reload = 0; do_reload(); }
        pause();   /* wake on any signal; flags drive the loop */
    }

    fprintf(stderr, "portico: shutting down\n");
    if (g_acme) portico_acme_manager_stop(g_acme);
    ws_server_stop(g_server);
    ws_server_destroy(g_server);
    portico_router_destroy(g_router);
    if (g_prev) portico_config_free(g_prev);
    if (g_cur)  portico_config_free(g_cur);
    portico_config_free(g_initial);
    return 0;
}
