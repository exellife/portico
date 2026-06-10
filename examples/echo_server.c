/* portico example: a raw WebSocket echo server.
 * Echoes every binary message straight back — used to exercise the WS transport
 * (framing, sizes, fragmentation, control frames) independent of any app protocol. */
#include "wslib.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static ws_server_t *g_server = NULL;
static volatile sig_atomic_t g_running = 1;

static int on_binary(int fd, const void *data, size_t len, void *user_data) {
    (void)user_data;
    ws_send_binary(g_server, fd, data, len);   /* echo */
    return 0;
}

static void on_signal(int sig) { (void)sig; g_running = 0; }

int main(void) {
    const char *p = getenv("PORT");
    int port = (p && *p) ? atoi(p) : 8080;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    ws_config_t cfg = {0};
    cfg.port                = (uint16_t)port;
    cfg.thread_count        = 4;
    cfg.max_connections     = 10000;
    cfg.max_message_size    = 1024 * 1024;   /* 1 MB */
    cfg.small_buffer_count  = 1024;
    cfg.medium_buffer_count = 512;
    cfg.large_buffer_count  = 128;
    cfg.enable_keepalive    = true;
    cfg.enable_nodelay      = true;
    cfg.backlog             = 512;

    /* Optional TLS for WSS testing: set TLS_CERT + TLS_KEY (PEM paths). */
    cfg.tls_cert_file = getenv("TLS_CERT");
    cfg.tls_key_file  = getenv("TLS_KEY");

    g_server = ws_server_create(&cfg);
    if (!g_server) { fprintf(stderr, "ws_server_create failed\n"); return 1; }

    ws_callbacks_t cb = {0};
    cb.on_binary_message = on_binary;
    if (ws_server_start(g_server, &cb) != 0) {
        fprintf(stderr, "ws_server_start failed\n");
        ws_server_destroy(g_server);
        return 1;
    }
    fprintf(stderr, "portico echo server listening on ws://0.0.0.0:%d/\n", port);

    while (g_running) pause();

    ws_server_destroy(g_server);
    return 0;
}
