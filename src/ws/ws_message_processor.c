/* ============================================================================
 * WSLib - Message Processing Functions
 * 
 * MPSC message processors for inter-thread communication
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_connection.h"
#include "internal/ws_utils.h"
#include "internal/ws_tls.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* ============================================================================
 * Forward Declarations - O(1) Connection Lookup Functions
 * ============================================================================ */

ws_connection_t* ws_find_connection_by_fd(ws_event_thread_t *thread, int fd);
void ws_register_fd(ws_event_thread_t *thread, int fd, ws_connection_t *conn);
void ws_unregister_fd(ws_event_thread_t *thread, int fd);

/* ============================================================================
 * Message Processing Functions
 * ============================================================================ */

int process_new_connection(int fd, const struct sockaddr_storage *client_addr, socklen_t client_addr_len, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0) {
        return -1;
    }

    /* Get server instance for statistics */
    ws_server_internal_t *server = (ws_server_internal_t*)thread->server_instance;
    
    /* Log the new connection */
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port = 0;
    
    if (client_addr->ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)client_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr_in->sin_port);
    } else if (client_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)client_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr_in6->sin6_port);
    } else {
        snprintf(client_ip, sizeof(client_ip), "unknown");
    }

    WS_DEBUG_LOG("Thread %u: Processing new connection fd=%d from %s:%u", 
                 thread->thread_id, fd, client_ip, client_port);

    /* Find a free connection slot using the free stack */
    ws_connection_t *conn = NULL;
    if (thread->free_connection_count > 0) {
        /* Pop from free connection stack */
        uint32_t free_index = thread->free_connection_stack[thread->free_connection_count - 1];
        thread->free_connection_count--;
        conn = &thread->connections[free_index];
    }
    
    if (!conn) {
        WS_ERROR_LOG("Thread %u: No free connection slots for fd=%d", thread->thread_id, fd);
        close(fd);
        return -1;
    }

    /* Initialize connection */
    ws_connection_init(conn, fd, thread->thread_id, conn - thread->connections);
    ws_connection_set_state(conn, WS_STATE_CONNECTING); /* Start in connecting state */

    /* TLS listener: wrap the fd and start in the handshake state so the first
     * reads drive SSL_accept rather than the HTTP/WS dispatch. Fail closed. */
    if (server && server->tls_ctx) {
        conn->ssl = ws_tls_conn_new(server->tls_ctx, fd);
        if (!conn->ssl) {
            WS_ERROR_LOG("Thread %u: TLS init failed for fd=%d", thread->thread_id, fd);
            ws_connection_cleanup(conn);
            close(fd);
            return -1;
        }
        ws_connection_set_state(conn, WS_STATE_TLS_HANDSHAKE);
    }

    /* Register in FD map for O(1) lookup (Bottleneck #5) */
    ws_register_fd(thread, fd, conn);
    
    /* Store client address */
    memcpy(&conn->client_addr, client_addr, client_addr_len);
    
    /* Add connection to global hash table for lookup */
    if (server && server->global_hash) {
        if (ws_connection_hash_insert(server->global_hash, conn) < 0) {
            WS_ERROR_LOG("Thread %u: Failed to add fd=%d to global hash", thread->thread_id, fd);
            /* Continue anyway - connection will work but sending might fail */
        }
    }
    
    /* Add to epoll for handshake processing */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; /* Edge-triggered input */
    ev.data.fd = fd;
    
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to add fd=%d to epoll: %s", 
                     thread->thread_id, fd, strerror(errno));
        ws_connection_cleanup(conn);
        close(fd);
        return -1;
    }

    /* Update connection counts */
    atomic_fetch_add(&thread->active_connections, 1);
    if (server) {
        atomic_fetch_add(&server->total_connections_accepted, 1);
    }
    
    WS_DEBUG_LOG("Thread %u: Added fd=%d to epoll in CONNECTING state, connections: %u/%u", 
                 thread->thread_id, fd, atomic_load(&thread->active_connections), thread->max_connections);
    
    return 0;
}

/* Encode a data frame and queue it through the connection's EPOLLOUT-backed
 * out_buffer instead of a single raw send(). A raw send() on a non-blocking
 * socket truncates/drops the frame the moment the peer's window fills (a slow
 * consumer = silent feed gaps); buffering holds it and drains on writability,
 * and lets bursts batch. Bounded by the out_buffer cap — past that, the frame
 * is dropped (graceful degradation; a slow-consumer disconnect is a follow-up). */
static int ws_buffered_data_send(ws_event_thread_t *thread, int fd, uint8_t opcode,
                                 const void *data, size_t len) {
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);
    if (!conn) return -1;   /* connection gone (closed/reused) — drop */

    /* Already disconnecting (cap was hit on an earlier frame): drop the rest of
     * this connection's backlog quietly instead of re-shutting-down + re-logging
     * for every queued frame. */
    if (conn->state != WS_STATE_OPEN) return 0;

    uint8_t *frame;
    size_t frame_len;
    if (ws_encode_frame(opcode, (const uint8_t *)data, len, &frame, &frame_len) != 0) {
        return -1;
    }
    int rc = portico_conn_send(thread, conn, frame, frame_len);
    free(frame);
    if (rc < 0) {
        /* Backpressure cap exceeded (or the socket errored): this consumer can't
         * keep up. Disconnect it so it reconnects and resyncs rather than
         * silently missing frames. shutdown() — not close() — is safe to call
         * here mid-MPSC-drain: it doesn't free the fd, so there's no reuse race
         * with the acceptor. It makes the socket report EOF/error, and the
         * connection then tears down through the normal event-loop close path
         * with its slot still valid (no double-close). */
        WS_ERROR_LOG("Thread %u: disconnecting slow consumer fd=%d (send buffer cap exceeded)",
                     thread->thread_id, fd);
        /* Mark closing so the rest of this connection's queued frames drop
         * quietly (here and at the MPSC dispatch's state==OPEN check). */
        ws_connection_set_state(conn, WS_STATE_CLOSING);
        shutdown(fd, SHUT_RDWR);
    }
    return rc;
}

int process_text_message(int fd, const char *data, size_t len, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0 || (!data && len > 0)) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing outbound text message for fd=%d (%zu bytes)",
                 thread->thread_id, fd, len);

    if (ws_buffered_data_send(thread, fd, WS_OPCODE_TEXT, data, len) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to send text frame to fd=%d", thread->thread_id, fd);
        return -1;
    }
    return 0;
}

int process_binary_message(int fd, const void *data, size_t len, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0 || (!data && len > 0)) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing outbound binary message for fd=%d (%zu bytes)",
                 thread->thread_id, fd, len);

    if (ws_buffered_data_send(thread, fd, WS_OPCODE_BINARY, data, len) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to send binary frame to fd=%d", thread->thread_id, fd);
        return -1;
    }
    return 0;
}

int process_shutdown_signal(void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Received shutdown signal", thread->thread_id);
    thread->running = false;
    return 0;
}

int process_ping_message(int fd, const void *data, size_t len, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing outbound ping message for fd=%d (%zu bytes)", 
                 thread->thread_id, fd, len);

    /* Send ping frame directly */
    if (ws_send_ping_frame(fd, data, len) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to send ping frame to fd=%d", thread->thread_id, fd);
        return -1;
    }

    return 0;
}

int process_pong_message(int fd, const void *data, size_t len, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing outbound pong message for fd=%d (%zu bytes)", 
                 thread->thread_id, fd, len);

    /* Send pong frame directly */
    if (ws_send_pong_frame(fd, data, len) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to send pong frame to fd=%d", thread->thread_id, fd);
        return -1;
    }

    return 0;
}

int process_close_message(int fd, ws_close_code_t code, const char *reason, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing close message for fd=%d (code=%d, reason='%s')", 
                 thread->thread_id, fd, code, reason ? reason : "");

    /* Send close frame */
    if (ws_send_close_frame(fd, (uint16_t)code, reason) < 0) {
        WS_ERROR_LOG("Thread %u: Failed to send close frame to fd=%d", thread->thread_id, fd);
        return -1;
    }

    /* Find connection using O(1) FD map lookup */
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);

    if (conn) {
        WS_DEBUG_LOG("Thread %u: Closing connection fd=%d after sending close frame", 
                     thread->thread_id, fd);
        
        /* Remove from epoll */
        if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
            WS_ERROR_LOG("Thread %u: Failed to remove fd=%d from epoll: %s", 
                         thread->thread_id, fd, strerror(errno));
        }

        /* Trigger application close callback */
        ws_server_internal_t *server = (ws_server_internal_t*)thread->server_instance;
        if (server && server->callbacks.on_close) {
            server->callbacks.on_close(fd, code, reason, conn->user_data);
        }

        /* Remove from global hash table first */
        if (server && server->global_hash) {
            ws_connection_hash_remove(server->global_hash, fd);
        }

        /* Unregister from FD map for O(1) lookup (Bottleneck #5) */
        ws_unregister_fd(thread, fd);

        /* FIXED: Save pool_index before cleanup zeros it out */
        uint32_t pool_index = conn->pool_index;
        
        /* Release the initial reference and check if connection can be freed */
        if (ws_connection_unref(conn)) {
            /* This was the last reference - safe to cleanup and reuse */
            ws_connection_cleanup(conn);
            
            /* Return connection to free pool using saved pool_index */
            if (thread->free_connection_count < thread->max_connections) {
                thread->free_connection_stack[thread->free_connection_count] = pool_index;
                thread->free_connection_count++;
            }
        } else {
            /* Other threads still have references - mark as closed but don't reuse yet */
            ws_connection_set_state(conn, WS_STATE_CLOSED);
            WS_DEBUG_LOG("Connection fd=%d has pending references, deferred cleanup", fd);
        }
        if (thread->free_connection_count < thread->max_connections) {
            thread->free_connection_stack[thread->free_connection_count] = pool_index;
            thread->free_connection_count++;
        }

        /* Update active connection count */
        atomic_fetch_sub(&thread->active_connections, 1);
    }

    return 0;
}

int process_user_data_update(int fd, void *user_data, void *context) {
    ws_event_thread_t *thread = (ws_event_thread_t*)context;
    if (!thread || fd < 0) {
        return -1;
    }

    WS_DEBUG_LOG("Thread %u: Processing user data update for fd=%d", thread->thread_id, fd);

    /* Find connection using O(1) FD map lookup */
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);

    if (!conn) {
        WS_ERROR_LOG("Thread %u: Connection fd=%d not found for user data update", 
                     thread->thread_id, fd);
        return -1;
    }

    /* Update the user data */
    conn->user_data = user_data;
    
    WS_DEBUG_LOG("Thread %u: Updated user data for fd=%d", thread->thread_id, fd);
    return 0;
}
