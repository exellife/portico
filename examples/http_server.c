/* portico example: one server, both protocols.
 *   - HTTP routes on /, /health, /echo
 *   - WebSocket binary echo (so the same binary exercises both harnesses)
 */
#include "portico.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static ws_server_t *g_server = NULL;
static volatile sig_atomic_t g_running = 1;
static portico_static_opts_t g_static;   /* STATIC_ROOT/STATIC_PREFIX, from main */

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
    if (portico_req_method_is(req, "GET") && portico_req_path_is(req, "/ip")) {
        portico_res_text(res, 200, portico_req_client_ip(req));   /* resolved client IP */
        return 0;
    }
    if (portico_req_method_is(req, "GET") && portico_req_path_is(req, "/")) {
        portico_res_text(res, 200, "portico http+ws server\n");
        return 0;
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

static void on_signal(int s) { (void)s; g_running = 0; }

int main(void) {
    const char *p = getenv("PORT");
    int port = (p && *p) ? atoi(p) : 8080;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

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

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    g_static.docroot      = getenv("STATIC_ROOT");      /* serve this folder, if set */
    g_static.url_prefix   = getenv("STATIC_PREFIX");     /* e.g. "/static"; NULL = mount at / */
    g_static.index        = getenv("STATIC_INDEX");      /* NULL = index.html */
    g_static.precompressed = getenv("STATIC_PRECOMPRESSED") != NULL;  /* serve .br/.gz */
    g_static.cache_control = getenv("STATIC_CACHE_CONTROL");          /* e.g. "max-age=3600" */

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

    while (g_running) pause();
    ws_server_destroy(g_server);
    return 0;
}
