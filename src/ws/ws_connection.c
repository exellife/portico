/* ============================================================================
 * WSLib - Connection Management Implementation
 * 
 * Implementation of connection structures and hash table management
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_utils.h"
#include "internal/ws_tls.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>

/* ============================================================================
 * Connection Hash Table Implementation
 * ============================================================================ */

ws_connection_hash_t* ws_connection_hash_create(void) {
    ws_connection_hash_t *hash = calloc(1, sizeof(ws_connection_hash_t));
    if (!hash) {
        return NULL;
    }

    /* Initialize level1 buckets */
    for (int i = 0; i < 256; i++) {
        hash->level1[i] = NULL;
        hash->level1_sizes[i] = 0;
        hash->level1_capacities[i] = 0;
        
        /* Initialize locks */
        if (pthread_rwlock_init(&hash->level1_locks[i], NULL) != 0) {
            /* Cleanup already initialized locks */
            for (int j = 0; j < i; j++) {
                pthread_rwlock_destroy(&hash->level1_locks[j]);
            }
            free(hash);
            return NULL;
        }
    }

    hash->level2_bucket_size = 32; /* Target bucket size */
    atomic_init(&hash->total_connections, 0);
    atomic_init(&hash->hash_collisions, 0);

    return hash;
}

void ws_connection_hash_destroy(ws_connection_hash_t *hash) {
    if (!hash) return;

    /* Free all level1 buckets */
    for (int i = 0; i < 256; i++) {
        pthread_rwlock_destroy(&hash->level1_locks[i]);
        if (hash->level1[i]) {
            free(hash->level1[i]);
        }
    }

    free(hash);
}

int ws_connection_hash_insert(ws_connection_hash_t *hash, ws_connection_t *conn) {
    if (!hash || !conn) return -1;

    /* Calculate hash bucket */
    uint64_t hash_val = ws_fnv1a_hash_uint32(conn->fd);
    uint8_t bucket = (hash_val >> 24) & 0xFF; /* Use high bits */

    /* Lock the bucket */
    pthread_rwlock_wrlock(&hash->level1_locks[bucket]);

    /* Allocate/reallocate bucket if needed */
    if (hash->level1[bucket] == NULL) {
        hash->level1[bucket] = malloc(sizeof(ws_hash_entry_t) * 32);
        if (!hash->level1[bucket]) {
            pthread_rwlock_unlock(&hash->level1_locks[bucket]);
            return -1;
        }
        hash->level1_capacities[bucket] = 32;
    } else if (hash->level1_sizes[bucket] >= hash->level1_capacities[bucket]) {
        /* Bucket is full - expand it dynamically */
        uint32_t new_capacity = hash->level1_capacities[bucket] * 2; /* Double capacity */
        ws_hash_entry_t *new_bucket = realloc(hash->level1[bucket],
                                              sizeof(ws_hash_entry_t) * new_capacity);
        if (!new_bucket) {
            /* Realloc failed - this is a critical error */
            atomic_fetch_add(&hash->hash_collisions, 1);
            pthread_rwlock_unlock(&hash->level1_locks[bucket]);
            return -1;
        }
        hash->level1[bucket] = new_bucket;
        hash->level1_capacities[bucket] = new_capacity;
        WS_DEBUG_LOG("Expanded hash bucket %u from %u to %u slots",
                     bucket, hash->level1_capacities[bucket] / 2, new_capacity);
    }

    /* Insert connection, keying on the fd value captured here. */
    hash->level1[bucket][hash->level1_sizes[bucket]].fd = conn->fd;
    hash->level1[bucket][hash->level1_sizes[bucket]].conn = conn;
    hash->level1_sizes[bucket]++;
    atomic_fetch_add(&hash->total_connections, 1);

    pthread_rwlock_unlock(&hash->level1_locks[bucket]);
    return 0;
}

ws_connection_t* ws_connection_hash_find(ws_connection_hash_t *hash, int fd) {
    if (!hash || fd < 0) return NULL;

    /* Calculate hash bucket */
    uint64_t hash_val = ws_fnv1a_hash_uint32((uint32_t)fd);
    uint8_t bucket = (hash_val >> 24) & 0xFF; /* Use high bits */

    /* Lock the bucket for reading */
    pthread_rwlock_rdlock(&hash->level1_locks[bucket]);

    ws_connection_t *result = NULL;
    if (hash->level1[bucket]) {
        /* Linear search in bucket — compares the entry's stored fd, never the
         * (recyclable) slot's fd field. */
        for (uint32_t i = 0; i < hash->level1_sizes[bucket]; i++) {
            if (hash->level1[bucket][i].fd == (uint32_t)fd) {
                result = hash->level1[bucket][i].conn;
                break;
            }
        }
    }

    pthread_rwlock_unlock(&hash->level1_locks[bucket]);
    return result;
}

ws_connection_t* ws_connection_hash_find_and_ref(ws_connection_hash_t *hash, int fd) {
    if (!hash || fd < 0) return NULL;

    /* Calculate hash bucket */
    uint64_t hash_val = ws_fnv1a_hash_uint32((uint32_t)fd);
    uint8_t bucket = (hash_val >> 24) & 0xFF; /* Use high bits */

    /* Lock the bucket for reading */
    pthread_rwlock_rdlock(&hash->level1_locks[bucket]);

    ws_connection_t *result = NULL;
    if (hash->level1[bucket]) {
        /* Linear search in bucket — compares the entry's stored fd. */
        for (uint32_t i = 0; i < hash->level1_sizes[bucket]; i++) {
            if (hash->level1[bucket][i].fd == (uint32_t)fd) {
                result = hash->level1[bucket][i].conn;
                /* Take a reference while holding the lock */
                ws_connection_ref(result);
                break;
            }
        }
    }

    pthread_rwlock_unlock(&hash->level1_locks[bucket]);
    return result;
}

int ws_connection_hash_remove(ws_connection_hash_t *hash, int fd) {
    if (!hash || fd < 0) return -1;

    /* Calculate hash bucket */
    uint64_t hash_val = ws_fnv1a_hash_uint32((uint32_t)fd);
    uint8_t bucket = (hash_val >> 24) & 0xFF; /* Use high bits */

    /* Lock the bucket */
    pthread_rwlock_wrlock(&hash->level1_locks[bucket]);

    int result = -1;
    if (hash->level1[bucket]) {
        /* Find and remove by stored fd (never reads the slot). */
        for (uint32_t i = 0; i < hash->level1_sizes[bucket]; i++) {
            if (hash->level1[bucket][i].fd == (uint32_t)fd) {
                /* Move last element to this position */
                hash->level1_sizes[bucket]--;
                if (i < hash->level1_sizes[bucket]) {
                    hash->level1[bucket][i] = hash->level1[bucket][hash->level1_sizes[bucket]];
                }
                hash->level1[bucket][hash->level1_sizes[bucket]].fd = 0;
                hash->level1[bucket][hash->level1_sizes[bucket]].conn = NULL;
                atomic_fetch_sub(&hash->total_connections, 1);
                result = 0;
                break;
            }
        }
    }

    pthread_rwlock_unlock(&hash->level1_locks[bucket]);
    return result;
}

/* ============================================================================
 * Connection Management Functions
 * ============================================================================ */

void ws_connection_init(ws_connection_t *conn, int fd, uint16_t thread_id, uint16_t pool_index) {
    if (!conn) return;

    /* Preserve and bump the reuse generation across the wipe. The slots array is
     * calloc'd, so a never-used slot starts at 0 and its first init yields 1. */
    uint32_t next_generation = conn->generation + 1;
    memset(conn, 0, sizeof(ws_connection_t));
    conn->generation = next_generation;

    conn->fd = (uint32_t)fd;
    conn->state = WS_STATE_CONNECTING;
    conn->thread_id = thread_id;
    conn->pool_index = pool_index;
    conn->read_buffer_idx = UINT32_MAX;  /* No buffer allocated */
    conn->write_buffer_idx = UINT32_MAX; /* No buffer allocated */
    conn->hash_next = UINT32_MAX;        /* Not in hash chain */
    
    /* Initialize reference count to 1 (created with one reference) */
    atomic_init(&conn->ref_count, 1);

    /* Initialize frame parser */
    memset(&conn->frame_parser, 0, sizeof(ws_frame_parser_t));
    
    /* Initialize receive buffer for incomplete frames (16KB) */
    conn->recv_buffer_capacity = 16384;
    conn->recv_buffer = malloc(conn->recv_buffer_capacity);
    conn->recv_buffer_used = 0;
    if (!conn->recv_buffer) {
        WS_ERROR_LOG("Failed to allocate receive buffer for connection fd=%d", fd);
        conn->recv_buffer_capacity = 0;
    }

    /* No pending HTTP output yet. */
    conn->out_buffer = NULL;
    conn->out_capacity = 0;
    conn->out_used = 0;
    conn->out_sent = 0;
    conn->out_close_when_drained = 0;

    /* Initialize statistics if enabled */
    #ifdef WS_ENABLE_STATISTICS
    atomic_init(&conn->bytes_sent, 0);
    atomic_init(&conn->bytes_received, 0);
    atomic_init(&conn->message_count, 0);
    #endif
}

void ws_connection_cleanup(ws_connection_t *conn) {
    if (!conn) return;

    /* Free the TLS object (BIO_NOCLOSE, so this never touches the fd). */
    if (conn->ssl) {
        ws_tls_conn_free(conn->ssl);
        conn->ssl = NULL;
    }

    /* Cleanup write buffer */
    ws_connection_cleanup_write_buffer(conn);
    
    /* Cleanup receive buffer */
    if (conn->recv_buffer) {
        free(conn->recv_buffer);
        conn->recv_buffer = NULL;
        conn->recv_buffer_capacity = 0;
        conn->recv_buffer_used = 0;
    }

    /* Cleanup pending HTTP output buffer */
    if (conn->out_buffer) {
        free(conn->out_buffer);
        conn->out_buffer = NULL;
        conn->out_capacity = 0;
        conn->out_used = 0;
        conn->out_sent = 0;
    }

    /* Note: Buffer cleanup and socket closing handled by caller. Preserve the
     * reuse generation across the wipe so it stays monotonic per slot — the
     * next init bumps it again, distinguishing this slot's successive lives. */
    uint32_t gen = conn->generation;
    memset(conn, 0, sizeof(ws_connection_t));
    conn->generation = gen;
}

void ws_connection_set_state(ws_connection_t *conn, ws_state_t state) {
    if (!conn) return;
    conn->state = (uint32_t)state;
}

bool ws_connection_is_active(const ws_connection_t *conn) {
    if (!conn) return false;
    return conn->state == WS_STATE_CONNECTING || conn->state == WS_STATE_OPEN;
}

/* ============================================================================
 * Reference Counting for Thread Safety
 * ============================================================================ */

void ws_connection_ref(ws_connection_t *conn) {
    if (!conn) return;
    atomic_fetch_add(&conn->ref_count, 1);
}

bool ws_connection_unref(ws_connection_t *conn) {
    if (!conn) return false;
    
    uint32_t old_count = atomic_fetch_sub(&conn->ref_count, 1);
    return (old_count == 1); /* Return true if this was the last reference */
}

void ws_connection_update_activity(ws_connection_t *conn, uint32_t server_time_offset) {
    if (!conn) return;
    conn->last_activity = server_time_offset;
}

void ws_connection_add_bytes_sent(ws_connection_t *conn, uint64_t bytes) {
    if (!conn) return;
    #ifdef WS_ENABLE_STATISTICS
    atomic_fetch_add(&conn->bytes_sent, bytes);
    #else
    (void)bytes; /* Suppress unused warning */
    #endif
}

void ws_connection_add_bytes_received(ws_connection_t *conn, uint64_t bytes) {
    if (!conn) return;
    #ifdef WS_ENABLE_STATISTICS
    atomic_fetch_add(&conn->bytes_received, bytes);
    #else
    (void)bytes; /* Suppress unused warning */
    #endif
}

void ws_connection_increment_messages(ws_connection_t *conn) {
    if (!conn) return;
    #ifdef WS_ENABLE_STATISTICS
    atomic_fetch_add(&conn->message_count, 1);
    #endif
}

/* ============================================================================
 * Write Buffering (Bottleneck #4 Optimization)
 * 
 * Batches multiple send() calls into userspace buffer to reduce syscalls
 * Performance: 14-82x reduction in system calls
 * ============================================================================ */

#define WS_DEFAULT_WRITE_BUFFER_SIZE 65536  // 64KB

/* Initialize write buffer for a connection */
int ws_connection_init_write_buffer(ws_connection_t *conn) {
    if (!conn) return -1;
    
    if (conn->write_buffer) {
        return 0; /* Already initialized */
    }
    
    conn->write_buffer = malloc(WS_DEFAULT_WRITE_BUFFER_SIZE);
    if (!conn->write_buffer) {
        WS_ERROR_LOG("Failed to allocate write buffer");
        return -1;
    }
    
    conn->write_buffer_size = WS_DEFAULT_WRITE_BUFFER_SIZE;
    conn->write_buffer_used = 0;
    conn->syscall_count = 0;
    
    WS_DEBUG_LOG("Initialized write buffer for fd=%u (size=%zu)", 
                 conn->fd, conn->write_buffer_size);
    return 0;
}

/* Flush write buffer to socket */
int ws_connection_flush_write_buffer(ws_connection_t *conn) {
    if (!conn || !conn->write_buffer || conn->write_buffer_used == 0) {
        return 0;
    }
    
    ssize_t sent = send(conn->fd, conn->write_buffer, conn->write_buffer_used, 
                       MSG_NOSIGNAL | MSG_DONTWAIT);
    conn->syscall_count++;
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer full - leave data in our buffer */
            return 0;
        }
        WS_ERROR_LOG("send() failed for fd=%u: %s", conn->fd, strerror(errno));
        return -1;
    }
    
    if (sent < (ssize_t)conn->write_buffer_used) {
        /* Partial send - move remaining data to front of buffer */
        size_t remaining = conn->write_buffer_used - sent;
        memmove(conn->write_buffer, conn->write_buffer + sent, remaining);
        conn->write_buffer_used = remaining;
    } else {
        /* All data sent */
        conn->write_buffer_used = 0;
    }
    
    #ifdef WS_ENABLE_STATISTICS
    atomic_fetch_add(&conn->bytes_sent, sent);
    #endif
    
    return sent;
}

/* Buffered send - accumulate in buffer, flush when full */
int ws_connection_buffered_send(ws_connection_t *conn, const void *data, size_t len) {
    if (!conn || !data || len == 0) {
        return -1;
    }
    
    /* Initialize write buffer if needed */
    if (!conn->write_buffer) {
        if (ws_connection_init_write_buffer(conn) != 0) {
            /* Fallback to direct send */
            ssize_t sent = send(conn->fd, data, len, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                #ifdef WS_ENABLE_STATISTICS
                atomic_fetch_add(&conn->bytes_sent, sent);
                #endif
            }
            return sent < 0 ? -1 : sent;
        }
    }
    
    /* If message is too large for buffer, send directly */
    if (len > conn->write_buffer_size) {
        /* Flush any buffered data first */
        if (conn->write_buffer_used > 0) {
            ws_connection_flush_write_buffer(conn);
        }
        
        /* Send large message directly */
        ssize_t sent = send(conn->fd, data, len, MSG_NOSIGNAL | MSG_DONTWAIT);
        conn->syscall_count++;
        
        if (sent > 0) {
            #ifdef WS_ENABLE_STATISTICS
            atomic_fetch_add(&conn->bytes_sent, sent);
            #endif
        }
        return sent < 0 ? -1 : sent;
    }
    
    /* If message fits in buffer, just copy */
    if (conn->write_buffer_used + len <= conn->write_buffer_size) {
        memcpy(conn->write_buffer + conn->write_buffer_used, data, len);
        conn->write_buffer_used += len;
        return len;
    }
    
    /* Buffer would overflow - flush first */
    int flushed = ws_connection_flush_write_buffer(conn);
    if (flushed < 0) {
        return -1;
    }
    
    /* After flush, message should fit */
    if (conn->write_buffer_used + len > conn->write_buffer_size) {
        /* Still doesn't fit - something is wrong */
        WS_ERROR_LOG("Write buffer size mismatch for fd=%u", conn->fd);
        return -1;
    }
    
    memcpy(conn->write_buffer + conn->write_buffer_used, data, len);
    conn->write_buffer_used += len;
    return len;
}

/* Cleanup write buffer */
void ws_connection_cleanup_write_buffer(ws_connection_t *conn) {
    if (!conn) return;
    
    /* Flush any remaining data */
    if (conn->write_buffer_used > 0) {
        ws_connection_flush_write_buffer(conn);
    }
    
    if (conn->write_buffer) {
        free(conn->write_buffer);
        conn->write_buffer = NULL;
        conn->write_buffer_size = 0;
        conn->write_buffer_used = 0;
    }
    
    WS_DEBUG_LOG("Cleaned up write buffer for fd=%u (total syscalls: %lu)", 
                 conn->fd, conn->syscall_count);
}
