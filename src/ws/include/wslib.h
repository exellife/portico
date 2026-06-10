#ifndef WSLIB_H
#define WSLIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "portico_http.h"   /* portico: HTTP request-handler type for unified server */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * WSLib - High-Performance Scalable WebSocket Library
 * 
 * Public API for scalable WebSocket server implementation
 * ============================================================================ */

/* Forward declarations */
typedef struct ws_server ws_server_t;
typedef struct ws_connection ws_connection_t;

/* ============================================================================
 * WebSocket Connection States
 * ============================================================================ */

typedef enum {
    WS_STATE_CONNECTING = 0,    /* Initial state, handshake in progress */
    WS_STATE_OPEN = 1,          /* Connection established and ready */
    WS_STATE_CLOSING = 2,       /* Close frame sent, waiting for response */
    WS_STATE_CLOSED = 3,        /* Connection closed */
    WS_STATE_HTTP = 4           /* portico: plain-HTTP connection (not a WS upgrade) */
} ws_state_t;

/* ============================================================================
 * WebSocket Return Codes
 * ============================================================================ */

#define WS_OK                     0
#define WS_ERROR_INVALID_ARGS    -1
#define WS_ERROR_MEMORY          -2
#define WS_ERROR_SOCKET          -3
#define WS_ERROR_PROTOCOL        -4
#define WS_ERROR_NOT_FOUND       -5
#define WS_ERROR_QUEUE_FULL      -6

/* ============================================================================
 * WebSocket Close Codes (RFC 6455)
 * ============================================================================ */

typedef enum {
    WS_CLOSE_NORMAL = 1000,           /* Normal closure */
    WS_CLOSE_GOING_AWAY = 1001,       /* Endpoint going away */
    WS_CLOSE_PROTOCOL_ERROR = 1002,   /* Protocol error */
    WS_CLOSE_UNSUPPORTED_DATA = 1003, /* Unsupported data type */
    WS_CLOSE_NO_STATUS = 1005,        /* No status code (reserved) */
    WS_CLOSE_ABNORMAL = 1006,         /* Abnormal closure (reserved) */
    WS_CLOSE_INVALID_UTF8 = 1007,     /* Invalid UTF-8 data */
    WS_CLOSE_POLICY_VIOLATION = 1008, /* Policy violation */
    WS_CLOSE_MESSAGE_TOO_BIG = 1009,  /* Message too big */
    WS_CLOSE_MISSING_EXTENSION = 1010,/* Missing extension */
    WS_CLOSE_INTERNAL_ERROR = 1011,   /* Internal server error */
    WS_CLOSE_SERVICE_RESTART = 1012,  /* Service restart */
    WS_CLOSE_TRY_AGAIN_LATER = 1013,  /* Try again later */
    WS_CLOSE_TLS_HANDSHAKE = 1015     /* TLS handshake failure (reserved) */
} ws_close_code_t;

/* ============================================================================
 * Configuration Structure
 * ============================================================================ */

typedef struct {
    /* Network settings */
    uint16_t port;                    /* Server port */
    const char *bind_address;         /* Bind address (NULL for all interfaces) */
    
    /* Threading configuration */
    uint32_t thread_count;            /* Number of event threads (0 = auto) */
    
    /* Connection limits */
    uint32_t max_connections;         /* Maximum total connections */
    uint32_t max_connections_per_thread; /* Max connections per thread */
    
    /* Message limits */
    size_t max_message_size;          /* Maximum message size in bytes */
    uint32_t max_frame_size;          /* Maximum frame size */
    
    /* Timeouts (in seconds) */
    uint32_t handshake_timeout;       /* WebSocket handshake timeout */
    uint32_t ping_interval;           /* Ping interval (0 = disabled) */
    uint32_t pong_timeout;            /* Pong response timeout */
    
    /* Buffer pool configuration */
    uint32_t small_buffer_count;      /* Number of small buffers (1KB) */
    uint32_t medium_buffer_count;     /* Number of medium buffers (4KB) */
    uint32_t large_buffer_count;      /* Number of large buffers (16KB) */
    
    /* Performance tuning */
    bool enable_keepalive;            /* Enable TCP keepalive */
    bool enable_nodelay;              /* Enable TCP_NODELAY */
    uint32_t backlog;                 /* Listen backlog size */

    /* TLS (optional). When BOTH tls_cert_file and tls_key_file are set, the
     * listener terminates TLS (HTTPS/WSS); otherwise it serves plaintext.
     * Requires portico built with OpenSSL (PORTICO_TLS) — if not, server start
     * fails rather than silently downgrading to plaintext. PEM files on disk. */
    const char *tls_cert_file;        /* PEM certificate chain (leaf first) */
    const char *tls_key_file;         /* PEM private key */
} ws_config_t;

/* ============================================================================
 * Callback Function Types
 * ============================================================================ */

/* Forward declaration for handshake info */
typedef struct {
    char path[256];                   /* Request path */
    char sec_websocket_key[32];       /* Client WebSocket key */
    char sec_websocket_protocol[256]; /* Requested protocols */
    char origin[256];                 /* Origin header */
    int error_code;                   /* HTTP error code if invalid */
} ws_handshake_info_t;

/* Callback function types */
typedef int (*ws_on_handshake_fn)(int fd, const ws_handshake_info_t *info, const char **selected_protocol);
typedef int (*ws_on_connect_fn)(int fd, void *user_data);
typedef int (*ws_on_text_message_fn)(int fd, const char *data, size_t len, void *user_data);
typedef int (*ws_on_binary_message_fn)(int fd, const void *data, size_t len, void *user_data);
typedef int (*ws_on_ping_fn)(int fd, const void *data, size_t len, void *user_data);
typedef int (*ws_on_pong_fn)(int fd, const void *data, size_t len, void *user_data);
typedef int (*ws_on_close_fn)(int fd, ws_close_code_t code, const char *reason, void *user_data);
typedef void (*ws_on_disconnect_fn)(int fd, void *user_data);

typedef struct {
    ws_on_handshake_fn on_handshake;           /* Handshake validation callback */
    ws_on_connect_fn on_connect;               /* New connection established */
    ws_on_text_message_fn on_text_message;     /* Text message received */
    ws_on_binary_message_fn on_binary_message; /* Binary message received */
    ws_on_ping_fn on_ping;                     /* Ping frame received */
    ws_on_pong_fn on_pong;                     /* Pong frame received */
    ws_on_close_fn on_close;                   /* Close frame received */
    ws_on_disconnect_fn on_disconnect;         /* Connection disconnected */
    /* portico: invoked for a fully-parsed plain-HTTP request (non-WS). When set,
     * non-Upgrade connections are served as HTTP; when NULL they are rejected. */
    portico_http_handler_fn on_http_request;
    void                   *http_user_data;
} ws_callbacks_t;

/* ============================================================================
 * Statistics Structure
 * ============================================================================ */

typedef struct {
    /* Connection statistics */
    uint64_t total_connections_accepted;
    uint64_t current_connections;
    uint64_t peak_connections;
    
    /* Message statistics */
    uint64_t total_messages_sent;
    uint64_t total_messages_received;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    
    /* Error statistics */
    uint64_t connection_errors;
    uint64_t protocol_errors;
    uint64_t timeout_errors;
    
    /* Performance statistics */
    double cpu_usage;
    uint64_t memory_usage;
    uint32_t active_threads;
    
    /* Buffer pool statistics */
    uint32_t small_buffers_allocated;
    uint32_t medium_buffers_allocated;
    uint32_t large_buffers_allocated;
    uint32_t small_buffers_peak;
    uint32_t medium_buffers_peak;
    uint32_t large_buffers_peak;
} ws_server_stats_t;

/* ============================================================================
 * Server Management Functions
 * ============================================================================ */

/**
 * Create a new WebSocket server with the specified configuration.
 * 
 * @param config Server configuration
 * @return Pointer to server instance, or NULL on failure
 */
ws_server_t* ws_server_create(const ws_config_t *config);

/**
 * Destroy a WebSocket server and free all resources.
 * 
 * @param server Server instance to destroy
 */
void ws_server_destroy(ws_server_t *server);

/**
 * Start the WebSocket server (non-blocking).
 * 
 * @param server Server instance
 * @param callbacks Callback functions for handling events
 * @return 0 on success, -1 on failure
 */
int ws_server_start(ws_server_t *server, const ws_callbacks_t *callbacks);

/**
 * Stop the WebSocket server (graceful shutdown).
 * 
 * @param server Server instance
 * @return 0 on success, -1 on failure
 */
int ws_server_stop(ws_server_t *server);

/**
 * Wait for the server to finish (blocking).
 * 
 * @param server Server instance
 * @return 0 on success, -1 on failure
 */
int ws_server_wait(ws_server_t *server);

/* ============================================================================
 * Connection Management Functions
 * ============================================================================ */

/**
 * Send a text message to a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param data Text data to send
 * @param len Length of the text data
 * @return 0 on success, -1 on failure
 */
int ws_send_text(ws_server_t *server, int fd, const char *data, size_t len);

/**
 * Send a binary message to a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param data Binary data to send
 * @param len Length of the binary data
 * @return 0 on success, -1 on failure
 */
int ws_send_binary(ws_server_t *server, int fd, const void *data, size_t len);

/**
 * Send a ping frame to a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param data Optional ping payload
 * @param len Length of the ping payload
 * @return 0 on success, -1 on failure
 */
int ws_send_ping(ws_server_t *server, int fd, const void *data, size_t len);

/**
 * Send a pong frame to a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param data Optional pong payload
 * @param len Length of the pong payload
 * @return 0 on success, -1 on failure
 */
int ws_send_pong(ws_server_t *server, int fd, const void *data, size_t len);

/**
 * Close a WebSocket connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param code Close code
 * @param reason Optional close reason string
 * @return 0 on success, -1 on failure
 */
int ws_close_connection(ws_server_t *server, int fd, ws_close_code_t code, const char *reason);

/**
 * Get the state of a WebSocket connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @return Connection state
 */
ws_state_t ws_get_connection_state(ws_server_t *server, int fd);

/**
 * Set user data for a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @param user_data User data pointer
 * @return 0 on success, -1 on failure
 */
int ws_set_connection_user_data(ws_server_t *server, int fd, void *user_data);

/**
 * Get user data for a connection.
 * 
 * @param server Server instance
 * @param fd File descriptor of the connection
 * @return User data pointer, or NULL if not found
 */
void* ws_get_connection_user_data(ws_server_t *server, int fd);

/* ============================================================================
 * Statistics and Monitoring
 * ============================================================================ */

/**
 * Get server statistics.
 * 
 * @param server Server instance
 * @param stats Pointer to statistics structure to fill
 * @return 0 on success, -1 on failure
 */
int ws_get_server_stats(ws_server_t *server, ws_server_stats_t *stats);

/**
 * Print server statistics to stderr.
 * 
 * @param server Server instance
 */
void ws_print_server_stats(ws_server_t *server);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get the default configuration.
 * 
 * @param config Pointer to configuration structure to fill
 */
void ws_get_default_config(ws_config_t *config);

/**
 * Get library version string.
 * 
 * @return Version string
 */
const char* ws_get_version(void);

#ifdef __cplusplus
}
#endif

#endif /* WSLIB_H */
