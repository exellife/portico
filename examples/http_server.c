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

/* --- WebSocket: raw binary echo --- */
static int on_binary(int fd, const void *data, size_t len, void *u) {
    (void)u;
    ws_send_binary(g_server, fd, data, len);
    return 0;
}

/* --- HTTP routing --- */
static int on_http(const portico_request_t *req, portico_response_t *res, void *u) {
    (void)u;
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

    /* Optional TLS: set TLS_CERT + TLS_KEY (PEM paths) to serve HTTPS/WSS. */
    cfg.tls_cert_file = getenv("TLS_CERT");
    cfg.tls_key_file  = getenv("TLS_KEY");

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    cb.on_binary_message = on_binary;
    cb.on_http_request   = on_http;

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
