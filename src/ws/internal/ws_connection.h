#ifndef WS_CONNECTION_H
#define WS_CONNECTION_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../include/wslib.h"
#include "ws_utils.h"
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>

/* ============================================================================
 * WSLib Connection Management
 * 
 * Connection structures and management for scalable WebSocket implementation
 * ============================================================================ */

/* Frame parsing state */
typedef struct {
    bool header_parsed;          /* Frame header completely parsed */
    bool fin;                    /* FIN bit from frame header */
    ws_opcode_t opcode;          /* Frame opcode */
    bool masked;                 /* MASK bit from frame header */
    uint64_t payload_length;     /* Payload length */
    uint8_t masking_key[4];      /* Masking key (if masked) */
    uint64_t bytes_received;     /* Payload bytes received so far */
    
    /* Fragmentation support */
    bool in_fragmented_message;  /* Currently receiving fragmented message */
    ws_opcode_t fragment_opcode; /* Original opcode of fragmented message */
    uint8_t *fragment_buffer;    /* Buffer for assembling fragments */
    size_t fragment_buffer_size; /* Size of fragment buffer */
    size_t fragment_total_size;  /* Total size of assembled fragments */
} ws_frame_parser_t;

/* Connection structure (optimized for cache efficiency and memory usage) */
struct ws_connection {
    /* Core connection data (first cache line) */
    uint32_t fd;                    /* Socket file descriptor */
    uint32_t user_id;              /* Application user ID */
    
    /* Packed state (32 bits total) */
    uint32_t state : 4;            /* ws_state_t (4 values need 2 bits, use 4 for future) */
    uint32_t has_read_buffer : 1;  /* Has allocated read buffer */
    uint32_t has_write_buffer : 1; /* Has allocated write buffer */
    uint32_t is_authenticated : 1; /* User authentication status */
    uint32_t protocol_version : 4; /* WebSocket protocol version */
    uint32_t reserved_flags : 21;  /* Reserved for future use */
    
    /* Reference counting for thread safety */
    _Atomic uint32_t ref_count;    /* Reference count for safe cleanup */
    
    /* Timestamps (absolute unix seconds, truncated to 32 bits) */
    uint32_t connect_time;         /* When the connection was accepted */
    uint32_t last_activity;        /* Last time inbound data was seen (keepalive) */
    uint32_t ping_sent_at;         /* When a keepalive PING was sent and is awaiting
                                    * a PONG; 0 = none outstanding (H-8) */
    
    /* Buffer pool indices (UINT32_MAX = no buffer allocated) */
    uint32_t read_buffer_idx;      /* Index in buffer pool */
    uint32_t write_buffer_idx;     /* Index in buffer pool */
    
    /* Hash table linkage */
    uint32_t hash_next;            /* Next in hash chain */
    
    /* Thread assignment */
    uint16_t thread_id;            /* Which thread handles this connection */
    uint16_t pool_index;           /* Index in thread's connection array */

    /* Reuse generation: bumped on every ws_connection_init. A cross-thread
     * message (e.g. a queued send) captures the generation it was created for;
     * the consumer drops it if the slot has since been recycled, so an echo
     * can't be delivered to a different connection that reused the fd/slot. */
    uint32_t generation;

    /* Client information (second cache line) */
    struct sockaddr_storage client_addr; /* Client address (128 bytes) */
    
    /* Frame parsing state */
    ws_frame_parser_t frame_parser; /* Frame parsing context */
    
    /* Receive buffering for incomplete frames (FIX for RSV bits error) */
    uint8_t *recv_buffer;          /* Persistent buffer for incomplete frames */
    size_t recv_buffer_capacity;   /* Total buffer capacity */
    size_t recv_buffer_used;       /* Bytes currently in buffer */
    
    /* Write buffering (Bottleneck #4 optimization) */
    uint8_t *write_buffer;         /* Userspace write buffer */
    size_t write_buffer_size;      /* Total buffer size */
    size_t write_buffer_used;      /* Bytes currently in buffer */
    uint64_t syscall_count;        /* Number of actual send() calls */

    /* HTTP outbound backpressure: bytes awaiting a writable socket, drained by
     * the EPOLLOUT handler instead of blocking the event thread on a slow peer. */
    uint8_t *out_buffer;           /* Pending unsent response bytes */
    size_t out_capacity;           /* Allocated capacity of out_buffer */
    size_t out_used;               /* Total bytes queued */
    size_t out_sent;               /* Bytes already drained from the front */
    uint8_t out_close_when_drained;/* Close the connection once out_buffer empties */
    
    /* User data pointer */
    void *user_data;               /* Application-specific data */

    /* TLS (NULL = plaintext). Per-connection SSL object, created on accept when
     * the listener has a TLS context; freed in ws_connection_cleanup. */
    void *ssl;

    /* Statistics (optional, can be disabled) */
    #ifdef WS_ENABLE_STATISTICS
    atomic_uint_fast64_t bytes_sent;     /* Atomic counters for thread safety */
    atomic_uint_fast64_t bytes_received;
    atomic_uint_fast32_t message_count;
    #endif
};

/* A bucket entry keys on the fd VALUE, stored here rather than read from the
 * connection slot during traversal. The slot is recyclable array memory whose
 * fd field a producer can overwrite under no lock (ws_connection_init); keeping
 * the key in the entry means find/remove never touch the slot to match, so the
 * lookup can't race with a slot being re-initialized. */
typedef struct {
    uint32_t fd;
    ws_connection_t *conn;
} ws_hash_entry_t;

/* Hierarchical hash table for connection lookup (millions of connections) */
typedef struct {
    /* Level 1: 256 buckets based on high bits of hash */
    ws_hash_entry_t *level1[256];
    uint32_t level1_sizes[256];    /* Size of each level1 bucket */
    uint32_t level1_capacities[256]; /* Capacity of each level1 bucket */
    
    /* Level 2: Dynamic buckets for collision resolution */
    uint32_t level2_bucket_size;   /* Target size for level2 buckets */
    
    /* Hash table statistics */
    atomic_uint_fast32_t total_connections;
    atomic_uint_fast32_t hash_collisions;
    
    /* Thread safety */
    pthread_rwlock_t level1_locks[256]; /* One lock per level1 bucket */
} ws_connection_hash_t;

/* ============================================================================
 * Connection Management Functions
 * ============================================================================ */

/* Connection hash table operations */
ws_connection_hash_t* ws_connection_hash_create(void);
void ws_connection_hash_destroy(ws_connection_hash_t *hash);
int ws_connection_hash_insert(ws_connection_hash_t *hash, ws_connection_t *conn);
ws_connection_t* ws_connection_hash_find(ws_connection_hash_t *hash, int fd);
int ws_connection_hash_remove(ws_connection_hash_t *hash, int fd);

/* Connection state management */
void ws_connection_init(ws_connection_t *conn, int fd, uint16_t thread_id, uint16_t pool_index);
void ws_connection_cleanup(ws_connection_t *conn);
void ws_connection_set_state(ws_connection_t *conn, ws_state_t state);
bool ws_connection_is_active(const ws_connection_t *conn);

/* Reference counting for thread-safe access */
void ws_connection_ref(ws_connection_t *conn);
bool ws_connection_unref(ws_connection_t *conn);
ws_connection_t* ws_connection_hash_find_and_ref(ws_connection_hash_t *hash, int fd);

/* Connection statistics */
void ws_connection_update_activity(ws_connection_t *conn, uint32_t server_time_offset);
void ws_connection_add_bytes_sent(ws_connection_t *conn, uint64_t bytes);
void ws_connection_add_bytes_received(ws_connection_t *conn, uint64_t bytes);
void ws_connection_increment_messages(ws_connection_t *conn);

/* Write buffering (Bottleneck #4 optimization) */
int ws_connection_init_write_buffer(ws_connection_t *conn);
int ws_connection_flush_write_buffer(ws_connection_t *conn);
int ws_connection_buffered_send(ws_connection_t *conn, const void *data, size_t len);
void ws_connection_cleanup_write_buffer(ws_connection_t *conn);

/* The single socket I/O chokepoint: TLS (SSL_read/SSL_write) when this connection
 * is encrypted, else a raw non-blocking recv/send. recv()/send()-compatible
 * (>0 bytes, 0 = peer closed, -1 with errno EAGAIN on would-block), so every WS
 * read/write site can call these and behave identically for plaintext and TLS.
 * MUST be used for ALL socket writes on a connection — a raw send() on a TLS
 * connection would inject plaintext into the cipher stream and corrupt it. */
ssize_t ws_conn_socket_read(ws_connection_t *conn, void *buf, size_t len);
ssize_t ws_conn_socket_write(ws_connection_t *conn, const void *buf, size_t len);

/* Write a numeric IP for a socket address (or a connection's peer) into out
 * (>= 46 bytes), NUL-terminated; "" if the address family is unknown. */
void ws_sockaddr_ip(const struct sockaddr_storage *ss, char *out, size_t out_len);
void ws_conn_peer_ip(const ws_connection_t *conn, char *out, size_t out_len);

#endif /* WS_CONNECTION_H */
