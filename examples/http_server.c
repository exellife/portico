/* portico example: one server, both protocols.
 *   - HTTP routes on /, /health, /echo
 *   - WebSocket binary echo (so the same binary exercises both harnesses)
 */
#include "portico.h"
#include "acme_internal.h"   /* built-in ACME (Let's Encrypt) — opt-in via ACME_DOMAINS */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static ws_server_t *g_server = NULL;
static portico_acme_manager_t *g_acme = NULL;   /* NULL unless ACME_DOMAINS is set */
static volatile sig_atomic_t g_running = 1;
static portico_static_opts_t g_static;   /* STATIC_ROOT/STATIC_PREFIX, from main */
static portico_vhost_t g_vhosts[16];      /* VHOSTS="host:docroot;..." */
static size_t g_vhost_n = 0;

/* --- WebSocket: raw binary echo --- */
static int on_binary(int fd, const void *data, size_t len, void *u) {
    (void)u;
    ws_send_binary(g_server, fd, data, len);
    return 0;
}

/* --- accept gate: reject one IP (demo of an IP blacklist) via DENY_IP env --- */
static int on_accept(const char *client_ip, void *deny_ip) {
    if (deny_ip && strcmp(client_ip, (const char *)deny_ip) == 0) return -1;  /* deny */
    return 0;  /* allow */
}

/* --- HTTP routing --- */
static int on_http(const portico_request_t *req, portico_response_t *res, void *u) {
    const char *static_root = (const char *)u;   /* docroot, or NULL if unset */
    /* Name-based virtual hosting: route GET by Host to per-vhost docroots. */
    if (g_vhost_n && portico_req_method_is(req, "GET")) {
        portico_res_vhost(res, req, g_vhosts, g_vhost_n);
        return 0;
    }
    if (portico_req_method_is(req, "GET") && portico_req_path_is(req, "/ip")) {
        portico_res_text(res, 200, portico_req_client_ip(req));   /* resolved client IP */
        return 0;
    }
    if (!static_root && portico_req_method_is(req, "GET") && portico_req_path_is(req, "/")) {
        portico_res_text(res, 200, "portico http+ws server\n");
        return 0;   /* when STATIC_ROOT is set, "/" is served from the docroot below */
    }
    if (portico_req_method_is(req, "GET") && portico_req_path_is(req, "/health")) {
        portico_res_json(res, "{\"status\":\"ok\"}");
        return 0;
    }
    if (portico_req_path_is(req, "/echo")) {
        if (portico_req_method_is(req, "POST")) {
            portico_res_body(res, req->body, req->body_len, "application/octet-stream");
            return 0;
        }
        if (portico_req_method_is(req, "GET")) {
            char buf[1024];
            int n = snprintf(buf, sizeof buf, "query=%.*s\n",
                             (int)req->query_len, req->query ? req->query : "");
            portico_res_body(res, buf, (n > 0 ? (size_t)n : 0), "text/plain");
            return 0;
        }
        portico_res_status(res, 405);
        portico_res_header(res, "Allow", "GET, POST");
        return 0;
    }
    /* Static files: serve any other GET from STATIC_ROOT (async, traversal-safe),
     * with directory index + optional STATIC_PREFIX mounting. */
    if (static_root && (portico_req_method_is(req, "GET") || portico_req_method_is(req, "HEAD"))) {
        portico_res_static(res, req, &g_static);
        return 0;
    }
    portico_res_text(res, 404, "not found\n");
    return 0;
}

static volatile sig_atomic_t g_reload = 0;
static void on_signal(int s) { (void)s; g_running = 0; }
static void on_hup(int s)    { (void)s; g_reload = 1; }   /* SIGHUP → reload TLS certs */

/* ACME renewed the cert on disk (called from the manager's renewal thread — a normal
 * context, not a signal handler): hot-swap it in with zero downtime. Guards g_server
 * because the very first issuance happens before the server is created. */
static void on_cert_renewed(void *ud) {
    (void)ud;
    if (g_server) ws_server_reload_tls(g_server);
}

/* Opt-in ACME: ACME_DOMAINS="a.com,b.com" turns the server into its own CA client —
 * it obtains/renews a real certificate and serves HTTP-01 challenges on :80 itself.
 * Returns 0 (continue) or -1 (fatal). On success, points cfg's TLS paths at the
 * issued files. Other knobs: ACME_EMAIL, ACME_DIRECTORY (default LE staging),
 * ACME_CA_FILE (trust override, e.g. Pebble), ACME_CHALLENGE_PORT (default 80),
 * ACME_CERT/ACME_CERT_KEY/ACME_ACCOUNT_KEY paths, ACME_RENEW_DAYS, ACME_CHECK_INTERVAL. */
static int acme_maybe_start(ws_config_t *cfg) {
    char *ad = getenv("ACME_DOMAINS");
    if (!ad || !*ad) return 0;                       /* not enabled */

    static const char *domains[16];
    static char dbuf[1024];
    snprintf(dbuf, sizeof dbuf, "%s", ad);
    size_t nd = 0;
    for (char *t = strtok(dbuf, ","); t && nd < 16; t = strtok(NULL, ",")) domains[nd++] = t;

    static char cert[512], ckey[512];
    const char *c = getenv("ACME_CERT");     snprintf(cert, sizeof cert, "%s", c ? c : "acme-cert.pem");
    const char *k = getenv("ACME_CERT_KEY"); snprintf(ckey, sizeof ckey, "%s", k ? k : "acme-cert.key");
    const char *dir = getenv("ACME_DIRECTORY");
    const char *cp  = getenv("ACME_CHALLENGE_PORT");
    const char *ci  = getenv("ACME_CHECK_INTERVAL");
    const char *rd  = getenv("ACME_RENEW_DAYS");

    portico_acme_manager_config_t ac = {
        .directory_url    = dir ? dir : "https://acme-staging-v02.api.letsencrypt.org/directory",
        .account_key_path = getenv("ACME_ACCOUNT_KEY") ? getenv("ACME_ACCOUNT_KEY") : "acme-account.key",
        .cert_path        = cert,
        .cert_key_path    = ckey,
        .email            = getenv("ACME_EMAIL"),
        .ca_file          = getenv("ACME_CA_FILE"),
        .domains          = domains,
        .ndomains         = nd,
        .renew_within_days   = rd ? atoi(rd) : 30,
        .challenge_port      = cp ? atoi(cp) : 80,
        .check_interval_secs = ci ? atoi(ci) : 0,
        .on_renewed       = on_cert_renewed,
    };
    fprintf(stderr, "acme: obtaining a certificate for '%s' via %s ...\n", ad, ac.directory_url);
    g_acme = portico_acme_manager_start(&ac);
    if (!g_acme) { fprintf(stderr, "acme: initial issuance failed\n"); return -1; }
    fprintf(stderr, "acme: certificate ready (%s); HTTP-01 challenges on :%d\n",
            cert, portico_acme_manager_challenge_port(g_acme));

    cfg->tls_cert_file = cert;                       /* serve TLS from the issued files */
    cfg->tls_key_file  = ckey;
    return 0;
}

int main(void) {
    const char *p = getenv("PORT");
    int port = (p && *p) ? atoi(p) : 8080;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_hup);

    ws_config_t cfg = {0};
    cfg.port = (uint16_t)port;
    cfg.thread_count = 4;
    cfg.max_connections = 10000;
    cfg.max_message_size = 1024 * 1024;
    cfg.small_buffer_count = 1024;
    cfg.medium_buffer_count = 512;
    cfg.large_buffer_count = 128;
    cfg.enable_keepalive = true;
    cfg.enable_nodelay = true;
    cfg.backlog = 512;

    /* Slowloris reaper deadline for pre-request (handshake) connections, seconds.
     * Lowered by the reaper test to exercise stale-connection reaping quickly. */
    const char *ht = getenv("HANDSHAKE_TIMEOUT");
    if (ht && *ht) cfg.handshake_timeout = (uint32_t)atoi(ht);
    /* Keepalive tunables (H-8), lowered by the keepalive test. PING_INTERVAL=0
     * disables idle keepalive/reaping of established connections. */
    const char *pi = getenv("PING_INTERVAL");
    if (pi && *pi) cfg.ping_interval = (uint32_t)atoi(pi);
    const char *pt = getenv("PONG_TIMEOUT");
    if (pt && *pt) cfg.pong_timeout = (uint32_t)atoi(pt);

    /* Optional TLS: set TLS_CERT + TLS_KEY (PEM paths) to serve HTTPS/WSS. */
    cfg.tls_cert_file = getenv("TLS_CERT");
    cfg.tls_key_file  = getenv("TLS_KEY");
    cfg.trust_proxy   = getenv("TRUST_PROXY") != NULL;   /* honor X-Forwarded-For/X-Real-IP */

    /* Multi-domain HTTPS via SNI: TLS_SNI="host:cert:key;host2:cert2:key2". */
    static ws_tls_sni_cert_t sni[16]; size_t sni_n = 0;
    char *sni_env = getenv("TLS_SNI");
    if (sni_env) {
        char *buf = strdup(sni_env);   /* persists for the program's life */
        for (char *e = strtok(buf, ";"); e && sni_n < 16; e = strtok(NULL, ";")) {
            char *cert = strchr(e, ':'); if (!cert) continue; *cert++ = '\0';
            char *key  = strchr(cert, ':'); if (!key) continue; *key++ = '\0';
            sni[sni_n].hostname = e; sni[sni_n].cert_file = cert; sni[sni_n].key_file = key;
            sni_n++;
        }
        cfg.tls_sni_certs = sni;
        cfg.tls_sni_cert_count = sni_n;
    }

    /* Built-in ACME (opt-in): issues/renews a real cert and overrides the TLS paths
     * above. Must run before create() so the listener starts with a valid cert. */
    if (acme_maybe_start(&cfg) != 0) return 1;

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    g_static.docroot      = getenv("STATIC_ROOT");      /* serve this folder, if set */
    g_static.url_prefix   = getenv("STATIC_PREFIX");     /* e.g. "/static"; NULL = mount at / */
    g_static.index        = getenv("STATIC_INDEX");      /* NULL = index.html */
    g_static.precompressed = getenv("STATIC_PRECOMPRESSED") != NULL;  /* serve .br/.gz */
    g_static.cache_control = getenv("STATIC_CACHE_CONTROL");          /* e.g. "max-age=3600" */
    g_static.spa_fallback  = getenv("STATIC_SPA");                    /* e.g. "index.html" */
    g_static.dir_redirect  = getenv("STATIC_DIR_REDIRECT") != NULL;   /* /dir -> 301 /dir/ */

    /* Name-based virtual hosting: VHOSTS="host:docroot;host2:docroot2" (host may be
     * a "*.example.com" wildcard). Unconfigured Hosts get 404 (allow-list). */
    char *vh_env = getenv("VHOSTS");
    if (vh_env) {
        char *buf = strdup(vh_env);
        for (char *e = strtok(buf, ";"); e && g_vhost_n < 16; e = strtok(NULL, ";")) {
            char *dr = strchr(e, ':'); if (!dr) continue; *dr++ = '\0';
            g_vhosts[g_vhost_n].host = e;
            g_vhosts[g_vhost_n].static_opts.docroot = dr;
            g_vhost_n++;
        }
    }

    cb.on_binary_message = on_binary;
    cb.on_http_request   = on_http;
    cb.http_user_data    = (void *)g_static.docroot;  /* non-NULL enables static serving */
    cb.on_accept         = on_accept;          /* IP gate (demo) */
    cb.accept_user_data  = getenv("DENY_IP");  /* reject this IP, if set */

    if (ws_server_start(g_server, &cb) != 0) {
        fprintf(stderr, "start failed\n");
        ws_server_destroy(g_server);
        return 1;
    }
    fprintf(stderr, "portico http+ws server on :%d\n", port);

    while (g_running) {
        pause();                                  /* wakes on any signal */
        if (g_reload) { g_reload = 0; ws_server_reload_tls(g_server); }
    }
    if (g_acme) portico_acme_manager_stop(g_acme);   /* stop renewals + the :80 responder */
    ws_server_destroy(g_server);
    return 0;
}
