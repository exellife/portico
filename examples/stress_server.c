/* portico — tunable stress/benchmark server (both protocols on one port).
 *
 * Everything is configured from the environment so one binary covers every
 * stress scenario without recompiling:
 *
 *   PORT       listen port              (default 8090)
 *   THREADS    event threads            (default = online CPUs, capped 64)
 *   MAX_CONNS  max concurrent conns     (default 200000)
 *   MSG_SIZE   max WS message bytes     (default 16 MiB)
 *   SMALL/MEDIUM/LARGE  buffer-pool counts (defaults 4096/2048/512)
 *
 * Routes:
 *   HTTP  GET /health -> {"status":"ok"}   (tiny, for req/sec + latency)
 *         POST /echo  -> body              (sized responses / backpressure)
 *   WS    text+binary echo                 (round-trip msg/sec + latency)
 */
#include "portico.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static ws_server_t *g_server = NULL;
static volatile sig_atomic_t g_running = 1;

static int on_binary(int fd, const void *data, size_t len, void *u) {
    (void)u;
    ws_send_binary(g_server, fd, data, len);
    return 0;
}
static int on_text(int fd, const char *data, size_t len, void *u) {
    (void)u;
    ws_send_text(g_server, fd, data, len);
    return 0;
}

static int on_http(const portico_request_t *req, portico_response_t *res, void *u) {
    (void)u;
    if (portico_req_method_is(req, "GET") && portico_req_path_is(req, "/health")) {
        portico_res_json(res, "{\"status\":\"ok\"}");
        return 0;
    }
    if (portico_req_method_is(req, "POST") && portico_req_path_is(req, "/echo")) {
        portico_res_body(res, req->body, req->body_len, "application/octet-stream");
        return 0;
    }
    portico_res_text(res, 404, "not found\n");
    return 0;
}

static void on_signal(int s) { (void)s; g_running = 0; }

static int env_int(const char *name, int dflt) {
    const char *v = getenv(name);
    return (v && *v) ? atoi(v) : dflt;
}

int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus < 1) cpus = 4;
    if (cpus > 64) cpus = 64;

    ws_config_t cfg = {0};
    cfg.port            = (uint16_t)env_int("PORT", 8090);
    cfg.thread_count    = (uint32_t)env_int("THREADS", (int)cpus);
    cfg.max_connections = (uint32_t)env_int("MAX_CONNS", 200000);
    cfg.max_message_size= (size_t)env_int("MSG_SIZE", 16 * 1024 * 1024);
    cfg.small_buffer_count  = (uint32_t)env_int("SMALL",  4096);
    cfg.medium_buffer_count = (uint32_t)env_int("MEDIUM", 2048);
    cfg.large_buffer_count  = (uint32_t)env_int("LARGE",  512);
    cfg.enable_keepalive = true;
    cfg.enable_nodelay   = true;
    cfg.backlog          = 1024;

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    cb.on_binary_message = on_binary;
    cb.on_text_message   = on_text;
    cb.on_http_request   = on_http;

    if (ws_server_start(g_server, &cb) != 0) {
        fprintf(stderr, "start failed\n");
        ws_server_destroy(g_server);
        return 1;
    }
    fprintf(stderr, "portico stress server :%u  threads=%u  max_conns=%u\n",
            cfg.port, cfg.thread_count, cfg.max_connections);

    while (g_running) pause();
    ws_server_destroy(g_server);
    return 0;
}
