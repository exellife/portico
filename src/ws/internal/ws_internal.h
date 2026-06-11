#ifndef WS_INTERNAL_H
#define WS_INTERNAL_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../include/wslib.h"
#include "ws_utils.h"
#include <stdatomic.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <time.h>

/* ============================================================================
 * Forward Declarations for Cross-Dependencies
 * ============================================================================ */

/* Async file I/O instance (defined in portico_aio.h); per-event-thread, used by
 * the static-file path. Opaque here — only a pointer is stored. */
struct portico_aio;

/* Return codes */
#define WS_OK                     0
#define WS_ERROR_INVALID_ARGS    -1
#define WS_ERROR_MEMORY          -2
#define WS_ERROR_SOCKET          -3
#define WS_ERROR_PROTOCOL        -4
#define WS_ERROR_NOT_FOUND       -5
#define WS_ERROR_QUEUE_FULL      -6

/* WebSocket frame opcodes (RFC 6455) */
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
} ws_opcode_t;

/* Buffer pool statistics structure (forward declaration) */
typedef struct {
    uint32_t total_buffers;        /* Total buffers in pool */
    uint32_t allocated_buffers;    /* Currently allocated buffers */
    uint32_t peak_allocated;       /* Peak allocation count */
    uint64_t total_allocations;    /* Total allocations since creation */
    uint64_t total_deallocations;  /* Total deallocations since creation */
    uint64_t allocation_failures;  /* Failed allocations (pool exhausted) */
    
    /* Adaptive pool statistics */
    uint32_t initial_buffer_count; /* Original buffer count */
    uint32_t max_buffer_count;     /* Maximum allowed buffers */
    uint32_t exhaustion_events;    /* Pool exhaustion events */
    bool is_adaptive;              /* Whether this pool supports adaptive sizing */
} ws_buffer_pool_stats_t;

#include "ws_connection.h"

/* ============================================================================
 * WSLib Internal Architecture
 * 
 * Server architecture and thread management for scalable WebSocket implementation
 * ============================================================================ */

/* Scalability configuration */
#define WS_MAX_CONNECTIONS_PER_THREAD   10000   /* Max connections per event thread */
#define WS_DEFAULT_THREAD_COUNT         8       /* Default number of threads */
#define WS_BUFFER_POOL_SIZE_SMALL      1024     /* Small buffer pool size */
#define WS_BUFFER_POOL_SIZE_MEDIUM     4096     /* Medium buffer pool size */
#define WS_BUFFER_POOL_SIZE_LARGE      16384    /* Large buffer pool size */

/* Default configuration values */
#define WS_DEFAULT_MAX_CONNECTIONS      1000000  /* 1 million connections */
#define WS_DEFAULT_MAX_FRAME_SIZE       (1024 * 1024) /* 1MB frame size */
#define WS_DEFAULT_TIMEOUT              300      /* 5 minutes */
#define WS_FRAME_MAX_CONTROL_PAYLOAD    125      /* Max control frame payload */

/* Buffer pool constants */
#define WS_BUFFER_INVALID_INDEX         UINT32_MAX

/* Shared buffer pool (multiple pools for different sizes) */
typedef struct {
    char *memory_block;            /* Large pre-allocated memory block */
    uint32_t buffer_size;          /* Size of each buffer */
    uint32_t buffer_count;         /* Total buffers in this pool */
    
    /* Lock-free free list using atomic stack */
    atomic_uint_fast32_t free_head; /* Head of free list (atomic) */
    uint32_t *free_next;           /* Next pointers for free list */
    
    /* Statistics */
    atomic_uint_fast32_t allocated_count; /* Currently allocated buffers */
    atomic_uint_fast32_t peak_usage;      /* Peak usage for monitoring */
    
    /* Adaptive expansion capabilities */
    uint32_t initial_buffer_count; /* Original buffer count */
    uint32_t max_buffer_count;     /* Maximum allowed buffers */
    atomic_uint_fast32_t exhaustion_count; /* Pool exhaustion events */
    atomic_bool expanding;         /* Flag to prevent concurrent expansions */
    time_t last_expansion_time;    /* Time of last expansion */
    uint32_t expansion_cooldown_sec; /* Minimum seconds between expansions */
    
    /* Memory alignment and cache optimization */
    char padding[64];              /* Ensure different pools on different cache lines */
} ws_buffer_pool_t;

/* Multi-producer, single-consumer queue for cross-thread messages */
typedef struct ws_mpsc_node {
    atomic_uintptr_t next;         /* Next node (atomic pointer) */
    void *data;                    /* Message data */
    size_t data_size;              /* Size of message data */
    uint32_t message_type;         /* Type of message */
    
    /* Debug information for race condition detection */
    uint64_t debug_info[8];        /* Debug data (magic, thread IDs, timestamps, etc.) */
} ws_mpsc_node_t;

typedef struct {
    atomic_uintptr_t head;         /* Head of queue (atomic) */
    atomic_uintptr_t tail;         /* Tail of queue (atomic for MPSC) */
    
    /* Memory pool for nodes */
    ws_mpsc_node_t *node_pool;     /* Pre-allocated nodes */
    uint32_t node_pool_size;       /* Current size of node pool */
    atomic_uintptr_t free_head;    /* Head of free node list */
    atomic_uint_fast32_t free_nodes; /* Free node count */
    pthread_mutex_t free_lock;     /* Serializes free-list get/return/expand.
                                    * The prior lock-free Treiber stack had an
                                    * ABA race: a node could be popped while
                                    * being returned, handing it to two owners. */
    
    /* Adaptive pool sizing */
    uint32_t initial_pool_size;    /* Starting pool size */
    uint32_t max_pool_size;        /* Maximum allowed pool size */
    uint32_t growth_factor;        /* Growth multiplier (e.g., 2 for doubling) */
    atomic_uint_fast32_t exhaustion_count; /* Number of pool exhaustion events */
    time_t last_growth_time;       /* Time of last pool expansion */
    uint32_t growth_cooldown_sec;  /* Minimum seconds between expansions */
    atomic_bool expanding;         /* Flag to prevent concurrent expansions */
    
    /* Statistics */
    atomic_uint_fast64_t messages_sent;
    atomic_uint_fast64_t messages_received;
    atomic_uint_fast64_t total_expansions; /* Number of pool expansions */
} ws_mpsc_queue_t;

/* Per-thread event loop (inspired by Node.js/libuv architecture) */
typedef struct {
    /* Thread identification */
    pthread_t thread;              /* Thread handle */
    uint32_t thread_id;            /* Numeric thread ID */
    int cpu_affinity;              /* CPU core affinity (-1 = no affinity) */
    
    /* Event handling */
    int epoll_fd;                  /* This thread's epoll instance */
    struct epoll_event *events;    /* Event array for epoll_wait */
    uint32_t max_events;           /* Size of events array */
    
    /* Connection management */
    ws_connection_t *connections;  /* Thread-local connection array */
    uint32_t max_connections;      /* Max connections for this thread */
    atomic_uint_fast32_t active_connections; /* Currently active connections (atomic) */
    
    /* O(1) connection lookup (Bottleneck #5 optimization) */
    ws_connection_t **fd_to_conn_map; /* Direct FD → connection mapping */
    uint32_t fd_map_size;          /* Size of FD map array */
    
    /* Connection allocation (lock-free within thread) */
    uint32_t *free_connection_stack; /* Stack of free connection indices */
    uint32_t free_connection_count;  /* Number of free connections */
    
    /* Inter-thread communication */
    int wakeup_eventfd;            /* eventfd for waking thread */
    ws_mpsc_queue_t *message_queue; /* Multi-producer, single-consumer queue */

    /* Async file I/O for static serving. Its wakeup_fd is registered in this
     * thread's epoll; readiness → portico_aio_drain() fires read completions on
     * this (the owning) thread. NULL if creation failed (serving then 500s). */
    struct portico_aio *aio;
    
    /* Thread-local buffer pools */
    ws_buffer_pool_t small_buffers;  /* Small buffers (1KB) */
    ws_buffer_pool_t medium_buffers; /* Medium buffers (4KB) */
    ws_buffer_pool_t large_buffers;  /* Large buffers (16KB) */
    
    /* Performance monitoring */
    atomic_uint_fast64_t events_processed;
    atomic_uint_fast64_t messages_processed;
    uint64_t last_activity_time;   /* For detecting stuck threads */
    time_t   last_reap;            /* Last slowloris-reaper sweep (rate-limit to ~1Hz) */

    /* Thread state */
    volatile bool running;         /* Thread should continue running */
    volatile bool paused;          /* Thread is paused (for graceful shutdown) */
    
    /* Server reference */
    void *server_instance;         /* Pointer to parent server (ws_server_internal_t) */
} ws_event_thread_t;

/* Main server structure (this IS the ws_server_t from public API) */
typedef struct ws_server {
    /* Configuration */
    ws_config_t config;            /* Base configuration */
    uint32_t thread_count;         /* Number of event threads */
    uint32_t max_connections_total; /* Total max connections across all threads */
    
    /* Thread pool */
    ws_event_thread_t *threads;    /* Array of event threads */
    uint32_t next_thread;          /* Round-robin thread assignment */
    
    /* Global connection lookup */
    ws_connection_hash_t *global_hash; /* Global connection hash table */
    
    /* Shared resources */
    ws_buffer_pool_t *global_buffer_pools; /* Shared buffer pools */
    uint32_t buffer_pool_count;    /* Number of different buffer pool sizes */
    
    /* Server state */
    int listen_fd;                 /* Listening socket */
    volatile bool running;         /* Server running flag */
    pthread_t acceptor_thread;     /* Connection acceptance thread */
    
    /* Load balancing */
    atomic_uint_fast32_t connection_count; /* Total active connections */
    uint32_t *thread_loads;        /* Load per thread for balancing */
    
    /* Monitoring and statistics */
    time_t start_time;             /* Server start time (for offset calculations) */
    atomic_uint_fast64_t total_connections_accepted;
    atomic_uint_fast64_t total_messages_processed;
    
    /* Callbacks */
    ws_callbacks_t callbacks;      /* Application callbacks */

    /* TLS server context (SSL_CTX*, kept as void* so this header needs no
     * OpenSSL include). NULL = plaintext listener; shared read-only by conns. */
    void *tls_ctx;
} ws_server_internal_t;

/* ============================================================================
 * Server Management Functions
 * ============================================================================ */

/* Create server with threading */
ws_server_t* ws_server_create_internal(const ws_config_t *config);

/* Destroy server */
void ws_server_destroy_internal(ws_server_t *server);

/* Start server (non-blocking) */
int ws_server_start_internal(ws_server_t *server, const ws_callbacks_t *callbacks);

/* Stop server (graceful shutdown) */
int ws_server_stop_internal(ws_server_t *server);

/* Wait for server to finish */
int ws_server_wait_internal(ws_server_t *server);

/* ============================================================================
 * Connection Management Functions
 * ============================================================================ */

/* Find connection by file descriptor (thread-safe) */
ws_connection_t* ws_find_connection_internal(ws_server_t *server, int fd);

/* Send message to connection (thread-safe, may queue for other thread) */
int ws_send_text_internal(ws_server_t *server, int fd, const char *data, size_t len);
int ws_send_binary_internal(ws_server_t *server, int fd, const void *data, size_t len);
int ws_send_ping_internal(ws_server_t *server, int fd, const void *data, size_t len);
int ws_send_pong_internal(ws_server_t *server, int fd, const void *data, size_t len);

/* Close connection (thread-safe) */
int ws_close_connection_internal(ws_server_t *server, int fd, ws_close_code_t code, const char *reason);

/* Connection state management */
ws_state_t ws_get_connection_state_internal(ws_server_t *server, int fd);
int ws_set_connection_user_data_internal(ws_server_t *server, int fd, void *user_data);
void* ws_get_connection_user_data_internal(ws_server_t *server, int fd);

/* ============================================================================
 * Buffer Pool Management
 * ============================================================================ */

/* Buffer allocation result structure */
typedef struct {
    uint32_t buffer_idx;           /* Buffer index in pool */
    ws_buffer_pool_t *pool;        /* Pointer to source pool */
    void *data;                    /* Pointer to usable data area */
    size_t data_size;              /* Size of usable data area */
} ws_buffer_allocation_t;

/* Allocate buffer from appropriate pool */
uint32_t ws_buffer_pool_allocate(ws_buffer_pool_t *pool);

/* Return buffer to pool */
void ws_buffer_pool_deallocate(ws_buffer_pool_t *pool, uint32_t buffer_idx);

/* Get buffer pointer from index */
void* ws_buffer_pool_get_buffer(ws_buffer_pool_t *pool, uint32_t buffer_idx);

/* Get usable data size for pool */
size_t ws_buffer_pool_get_data_size(ws_buffer_pool_t *pool);

/* Get buffer index from data pointer */
uint32_t ws_buffer_pool_get_buffer_index(ws_buffer_pool_t *pool, void *buffer_data);

/* Create and destroy buffer pools */
int ws_buffer_pool_init(ws_buffer_pool_t *pool, uint32_t buffer_size, uint32_t buffer_count);
void ws_buffer_pool_cleanup(ws_buffer_pool_t *pool);

/* Buffer pool statistics */
void ws_buffer_pool_get_stats(ws_buffer_pool_t *pool, ws_buffer_pool_stats_t *stats);
void ws_buffer_pool_print_stats(ws_buffer_pool_t *pool, const char *pool_name);

/* Adaptive buffer pool functions */
int ws_buffer_pool_init_adaptive(ws_buffer_pool_t *pool, uint32_t buffer_size, 
                                uint32_t initial_count, uint32_t max_count);
int ws_buffer_pool_expand_safe(ws_buffer_pool_t *pool, uint32_t additional_buffers);
bool ws_buffer_pool_should_expand(ws_buffer_pool_t *pool);
void ws_buffer_pool_reset_exhaustion_counter(ws_buffer_pool_t *pool);

/* High-level allocation API */
ws_buffer_allocation_t ws_allocate_buffer_for_size(ws_event_thread_t *thread, size_t needed_size);
void ws_deallocate_buffer(ws_buffer_allocation_t *allocation);

/* Buffer pool validation (debug builds only) */
#ifdef WS_DEBUG
int ws_buffer_pool_validate(ws_buffer_pool_t *pool);
#endif

/* ============================================================================
 * MPSC Queue Management
 * ============================================================================ */

/* Message types for inter-thread communication */
typedef enum {
    WS_MSG_NEW_CONNECTION = 1,     /* New connection handoff */
    WS_MSG_SEND_TEXT = 2,          /* Send text message to connection */
    WS_MSG_SEND_BINARY = 3,        /* Send binary message to connection */
    WS_MSG_SEND_PING = 4,          /* Send ping frame */
    WS_MSG_SEND_PONG = 5,          /* Send pong frame */
    WS_MSG_CLOSE_CONNECTION = 6,   /* Close connection */
    WS_MSG_UPDATE_USER_DATA = 7,   /* Update connection user data */
    WS_MSG_THREAD_SHUTDOWN = 8,    /* Thread shutdown signal */
    WS_MSG_STATISTICS_REQUEST = 9, /* Request thread statistics */
} ws_message_type_t;

/* Message structures for different operations */
typedef struct {
    int fd;                        /* Connection file descriptor */
    size_t data_len;               /* Length of the data */
    char data[];                   /* Flexible array member for text data */
} ws_msg_send_text_t;

typedef struct {
    int fd;                        /* Connection file descriptor */
    size_t data_len;               /* Length of the data */
    uint8_t data[];                /* Flexible array member for binary data */
} ws_msg_send_binary_t;

typedef struct {
    int fd;                        /* Connection file descriptor */
    size_t data_len;               /* Length of ping data (optional) */
    uint8_t data[];                /* Flexible array member for ping data */
} ws_msg_send_ping_t;

typedef struct {
    int fd;                        /* Connection file descriptor */
    size_t data_len;               /* Length of pong data */
    uint8_t data[];                /* Flexible array member for pong data */
} ws_msg_send_pong_t;

typedef struct {
    int fd;                        /* Connection file descriptor */
    ws_close_code_t code;          /* Close code */
    size_t reason_len;             /* Length of close reason */
    char reason[];                 /* Flexible array member for close reason */
} ws_msg_close_connection_t;

typedef struct {
    int fd;                        /* Connection file descriptor */
    void *user_data;               /* New user data pointer */
} ws_msg_update_user_data_t;

/* Message processor structure for handling different message types */
typedef struct {
    int (*process_new_connection)(int fd, const struct sockaddr_storage *client_addr, socklen_t client_addr_len, void *context);
    int (*process_text_message)(int fd, const char *data, size_t len, void *context);
    int (*process_binary_message)(int fd, const void *data, size_t len, void *context);
    int (*process_ping_message)(int fd, const void *data, size_t len, void *context);
    int (*process_pong_message)(int fd, const void *data, size_t len, void *context);
    int (*process_close_message)(int fd, ws_close_code_t code, const char *reason, void *context);
    int (*process_user_data_update)(int fd, void *user_data, void *context);
    int (*process_shutdown_signal)(void *context);
    void *context;
} ws_mpsc_message_processor_t;

/* Queue statistics structure */
typedef struct {
    uint64_t messages_sent;        /* Total messages sent */
    uint64_t messages_received;    /* Total messages received */
    uint32_t free_nodes;           /* Available nodes in pool */
    uint32_t queue_depth;          /* Approximate queue depth */
    double utilization_percent;    /* Node pool utilization */
    
    /* Adaptive pool statistics */
    uint32_t current_pool_size;    /* Current pool size */
    uint32_t max_pool_size;        /* Maximum pool size */
    uint64_t total_expansions;     /* Number of pool expansions */
    uint32_t exhaustion_count;     /* Current exhaustion events */
} ws_mpsc_stats_t;

/* MPSC Queue lifecycle */
ws_mpsc_queue_t* ws_mpsc_queue_create(uint32_t node_pool_size);
ws_mpsc_queue_t* ws_mpsc_queue_create_adaptive(uint32_t initial_size, uint32_t max_size, uint32_t growth_factor);
int ws_mpsc_queue_expand_pool_safe(ws_mpsc_queue_t *queue, uint32_t new_size);
void ws_mpsc_queue_destroy(ws_mpsc_queue_t *queue);

/* Node management */
ws_mpsc_node_t* ws_mpsc_queue_get_node(ws_mpsc_queue_t *queue);
void ws_mpsc_queue_return_node(ws_mpsc_queue_t *queue, ws_mpsc_node_t *node);

/* Low-level queue operations */
int ws_mpsc_queue_enqueue(ws_mpsc_queue_t *queue, ws_mpsc_node_t *node);
ws_mpsc_node_t* ws_mpsc_queue_dequeue(ws_mpsc_queue_t *queue);

/* High-level message operations (producer side) */
int ws_mpsc_send_new_connection(ws_mpsc_queue_t *queue, int fd, 
                                const struct sockaddr_storage *client_addr, socklen_t client_addr_len);
int ws_mpsc_send_text_message(ws_mpsc_queue_t *queue, int fd, ws_connection_t *conn,
                              uint32_t generation, const char *data, size_t len);
int ws_mpsc_send_binary_message(ws_mpsc_queue_t *queue, int fd, ws_connection_t *conn,
                                uint32_t generation, const void *data, size_t len);
int ws_mpsc_send_ping_message(ws_mpsc_queue_t *queue, int fd, const void *data, size_t len);
int ws_mpsc_send_pong_message(ws_mpsc_queue_t *queue, int fd, const void *data, size_t len);
int ws_mpsc_send_close_message(ws_mpsc_queue_t *queue, int fd, ws_close_code_t code, const char *reason);
int ws_mpsc_update_user_data(ws_mpsc_queue_t *queue, int fd, void *user_data);
int ws_mpsc_send_shutdown_signal(ws_mpsc_queue_t *queue);

/* Message processing (consumer side) */
int ws_mpsc_process_messages(ws_mpsc_queue_t *queue, ws_mpsc_message_processor_t *processor, int max_messages);

/* Statistics and monitoring */
void ws_mpsc_get_stats(ws_mpsc_queue_t *queue, ws_mpsc_stats_t *stats);
void ws_mpsc_print_stats(ws_mpsc_queue_t *queue, const char *queue_name);

/* ============================================================================
 * Performance Monitoring
 * ============================================================================ */

/* Get server statistics */
int ws_get_server_stats_internal(ws_server_t *server, ws_server_stats_t *stats);

/* Print performance report */
void ws_print_server_stats_internal(ws_server_t *server);

/* ============================================================================
 * WebSocket Frame Structures
 * ============================================================================ */

typedef struct {
    uint8_t fin;           /* Final fragment flag */
    uint8_t opcode;        /* Frame opcode */
    uint8_t masked;        /* Mask flag */
    uint64_t payload_len;  /* Payload length */
    uint8_t mask_key[4];   /* Masking key (if masked) */
    uint8_t *payload;      /* Payload data */
    size_t header_len;     /* Header length in bytes */
    uint8_t owns_payload;  /* 1 if payload should be freed, 0 for zero-copy */
} ws_frame_t;

/* ============================================================================
 * WebSocket Function Declarations
 * ============================================================================ */

/* Event thread management functions (ws_event_thread.c) */
int ws_init_event_thread(ws_event_thread_t *thread, uint32_t thread_id, 
                        uint32_t max_connections, const ws_config_t *config,
                        void *server_instance);
void ws_cleanup_event_thread(ws_event_thread_t *thread);
void* ws_event_thread_worker(void *arg);

/* Connection handler functions (ws_connection_handler.c) */
int handle_connection_read(ws_event_thread_t *thread, int fd);
int handle_websocket_handshake(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server);
int handle_websocket_frames(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server);
int process_websocket_frame(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server, const ws_frame_t *frame);
void close_connection(ws_event_thread_t *thread, int fd);

/* portico HTTP integration (src/http/connection.c). The first read of every
 * connection is dispatched here: a WS upgrade continues the WebSocket path,
 * anything else becomes an HTTP connection served via callbacks.on_http_request. */
int portico_initial_dispatch(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server);
int portico_http_event(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server);

/* EPOLLOUT handler for the HTTP path: drains conn->out_buffer (queued response
 * bytes a slow peer hasn't read yet) without blocking the event thread. Returns
 * 0 to keep the connection, -1 if it was closed (fatal write error). */
int portico_conn_on_writable(ws_event_thread_t *thread, ws_connection_t *conn);

/* Queue bytes for sending on a connection with EPOLLOUT backpressure (buffers
 * what the socket can't take, never blocks). Shared by HTTP responses and WS
 * frame sends. Returns 0 ok, -1 on fatal error / backpressure-cap overflow. */
int portico_conn_send(ws_event_thread_t *thread, ws_connection_t *conn,
                      const void *buf, size_t len);

/* UTF-8 validation for text frames / close reasons (ws_utf8.c). */
int ws_utf8_valid(const unsigned char *s, size_t len);

/* Handshake functions */
int ws_parse_handshake_request(const char *request, ws_handshake_info_t *info);
int ws_create_handshake_response(const ws_handshake_info_t *info, const char *selected_protocol,
                                char *response, size_t response_size);
int ws_send_handshake_error(ws_connection_t *conn, int error_code, const char *error_message);
int ws_process_handshake(ws_connection_t *conn, const char *request, const ws_callbacks_t *callbacks);

/* Frame functions */
/* max_payload_len bounds the attacker-controlled declared frame length before any
 * size arithmetic (overflow guard); pass the server's max_message_size. */
int ws_parse_frame(const uint8_t *data, size_t data_len, ws_frame_t *frame,
                   uint64_t max_payload_len);
int ws_encode_frame(uint8_t opcode, const uint8_t *payload, size_t payload_len, 
                   uint8_t **frame_data, size_t *frame_len);
int ws_send_text_frame(ws_connection_t *conn, const char *text, size_t len);
int ws_send_binary_frame(ws_connection_t *conn, const void *data, size_t len);
int ws_send_ping_frame(ws_connection_t *conn, const void *data, size_t len);
int ws_send_pong_frame(ws_connection_t *conn, const void *data, size_t len);
int ws_send_close_frame(ws_connection_t *conn, uint16_t code, const char *reason);

/* Buffered frame sending (Bottleneck #4 optimization) */
int ws_send_text_frame_buffered(ws_connection_t *conn, const char *text, size_t len);
int ws_send_binary_frame_buffered(ws_connection_t *conn, const void *data, size_t len);
int ws_send_ping_buffered(ws_connection_t *conn, const void *payload, size_t len);
int ws_send_pong_buffered(ws_connection_t *conn, const void *payload, size_t len);
int ws_send_close_buffered(ws_connection_t *conn, uint16_t code, const char *reason);

int ws_process_received_frame(ws_connection_t *conn, const ws_frame_t *frame, 
                             const ws_callbacks_t *callbacks);
void ws_free_frame(ws_frame_t *frame);

/* Fragmentation support functions */
int process_fragmented_frame(ws_event_thread_t *thread, ws_connection_t *conn, 
                           ws_server_internal_t *server, const ws_frame_t *frame);
int process_continuation_frame(ws_event_thread_t *thread, ws_connection_t *conn,
                             ws_server_internal_t *server, const ws_frame_t *frame);
void cleanup_fragmentation_state(ws_connection_t *conn);

/* ============================================================================
 * Logging Macros
 * ============================================================================ */

#ifdef WS_DEBUG
#include <stdio.h>
#define WS_DEBUG_LOG(fmt, ...) fprintf(stderr, "[WS_DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define WS_DEBUG_LOG(fmt, ...)
#endif

#define WS_ERROR_LOG(fmt, ...) fprintf(stderr, "[WS_ERROR] " fmt "\n", ##__VA_ARGS__)

#endif /* WS_INTERNAL_H */
