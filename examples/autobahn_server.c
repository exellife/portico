/* portico — echo server for the Autobahn|Testsuite (RFC 6455 conformance).
 * Echoes text as text and binary as binary, which is what the fuzzingclient
 * expects for every case. PORT defaults to 9011. */
#include "wslib.h"

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
static void on_signal(int s) { (void)s; g_running = 0; }

int main(void) {
    const char *p = getenv("PORT");
    int port = (p && *p) ? atoi(p) : 9011;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    ws_config_t cfg = {0};
    cfg.port = (uint16_t)port;
    cfg.thread_count = 4;
    cfg.max_connections = 10000;
    cfg.max_message_size = 16 * 1024 * 1024;   /* Autobahn sends up to ~16MB in 9.x */
    cfg.small_buffer_count = 1024;
    cfg.medium_buffer_count = 512;
    cfg.large_buffer_count = 128;
    cfg.enable_keepalive = true;
    cfg.enable_nodelay = true;
    cfg.backlog = 512;

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    cb.on_binary_message = on_binary;
    cb.on_text_message   = on_text;
    if (ws_server_start(g_server, &cb) != 0) {
        fprintf(stderr, "start failed\n");
        ws_server_destroy(g_server);
        return 1;
    }
    fprintf(stderr, "portico autobahn echo server on ws://0.0.0.0:%d/\n", port);

    while (g_running) pause();
    ws_server_destroy(g_server);
    return 0;
}
