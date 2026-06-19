/* ============================================================================
 * WSLib - High-Performance Scalable WebSocket Library
 * 
 * Main implementation using scalable architecture for millions of connections
 * ============================================================================ */

#define _GNU_SOURCE
#include "wslib.h"
#include "internal/ws_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Default Configuration
 * ============================================================================ */

void ws_get_default_config(ws_config_t *config) {
    if (!config) return;
    
    config->port = 8080;
    config->bind_address = NULL;
    config->thread_count = 0; /* Auto-detect */
    config->max_connections = 500000; /* Increased from 10K to 500K for high-scale testing */
    config->max_connections_per_thread = 100000; /* Increased from 1000 to 100K for high-scale testing */
    config->max_message_size = 1024 * 1024; /* 1MB */
    config->max_frame_size = 65536; /* 64KB */
    config->handshake_timeout = 10;
    config->ping_interval = 30;
    config->pong_timeout = 10;
    config->small_buffer_count = 16384;  /* 16K small buffers - increased 16x */
    config->medium_buffer_count = 8192;  /* 8K medium buffers - increased 16x */
    config->large_buffer_count = 2048;   /* 2K large buffers - increased 20x */
    config->enable_keepalive = true;
    config->enable_nodelay = true;
    config->backlog = 128;
}

/* ============================================================================
 * Server Management Functions
 * ============================================================================ */

ws_server_t* ws_server_create(const ws_config_t *config) {
    if (!config || config->port == 0) {
        WS_ERROR_LOG("Invalid server configuration");
        return NULL;
    }

    return ws_server_create_internal(config);
}

void ws_server_destroy(ws_server_t *server) {
    if (!server) return;
    ws_server_destroy_internal(server);
}

int ws_server_reload_tls(ws_server_t *server) {
    if (!server) return -1;
    return ws_server_reload_tls_internal(server);
}

int ws_server_add_sni_cert(ws_server_t *server, const char *hostname,
                           const char *cert_file, const char *key_file) {
    if (!server || !hostname || !cert_file || !key_file) return -1;
    return ws_server_add_sni_cert_internal(server, hostname, cert_file, key_file);
}

int ws_server_start(ws_server_t *server, const ws_callbacks_t *callbacks) {
    if (!server || !callbacks) {
        return -1;
    }
    return ws_server_start_internal(server, callbacks);
}

int ws_server_stop(ws_server_t *server) {
    if (!server) return -1;
    return ws_server_stop_internal(server);
}

int ws_server_wait(ws_server_t *server) {
    if (!server) return -1;
    return ws_server_wait_internal(server);
}

/* ============================================================================
 * Connection Management Functions
 * ============================================================================ */

int ws_send_text(ws_server_t *server, int fd, const char *data, size_t len) {
    if (!server || fd < 0 || (!data && len > 0)) return -1;  /* portico: allow zero-length */
    return ws_send_text_internal(server, fd, data, len);
}

int ws_send_binary(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0 || (!data && len > 0)) return -1;  /* portico: allow zero-length */
    return ws_send_binary_internal(server, fd, data, len);
}

int ws_send_ping(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0) return -1;
    if (len > 125) return -1; /* Control frames limited to 125 bytes */
    return ws_send_ping_internal(server, fd, data, len);
}

int ws_send_pong(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0) return -1;
    if (len > 125) return -1; /* Control frames limited to 125 bytes */
    return ws_send_pong_internal(server, fd, data, len);
}

int ws_close_connection(ws_server_t *server, int fd, ws_close_code_t code, const char *reason) {
    if (!server || fd < 0) return -1;
    return ws_close_connection_internal(server, fd, code, reason);
}

ws_state_t ws_get_connection_state(ws_server_t *server, int fd) {
    if (!server || fd < 0) return WS_STATE_CLOSED;
    return ws_get_connection_state_internal(server, fd);
}

int ws_set_connection_user_data(ws_server_t *server, int fd, void *user_data) {
    if (!server || fd < 0) return -1;
    return ws_set_connection_user_data_internal(server, fd, user_data);
}

void* ws_get_connection_user_data(ws_server_t *server, int fd) {
    if (!server || fd < 0) return NULL;
    return ws_get_connection_user_data_internal(server, fd);
}

/* ============================================================================
 * Statistics and Monitoring
 * ============================================================================ */

int ws_get_server_stats(ws_server_t *server, ws_server_stats_t *stats) {
    if (!server || !stats) return -1;
    return ws_get_server_stats_internal(server, stats);
}

void ws_print_server_stats(ws_server_t *server) {
    if (!server) return;
    ws_print_server_stats_internal(server);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char* ws_get_version(void) {
    return "WSLib 1.0.0-dev";
}
