/* ============================================================================
 * WSLib - Scalable Server Main Implementation
 * 
 * Main server management, creation, start/stop, and acceptor thread
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_connection.h"
#include "internal/ws_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>

/* ============================================================================
 * Forward Declarations - Functions in other files
 * ============================================================================ */

/* Event thread functions (in ws_event_thread.c) */
extern void* ws_event_thread_worker(void *arg);

/* ============================================================================
 * Forward Declarations - Local functions
 * ============================================================================ */

static int ws_create_listening_socket(const ws_config_t *config);
static void* ws_acceptor_thread_worker(void *arg);

/* ============================================================================
 * Acceptor Thread Worker Function
 * ============================================================================ */

static void* ws_acceptor_thread_worker(void *arg) {
    ws_server_internal_t *server = (ws_server_internal_t*)arg;
    if (!server) {
        WS_ERROR_LOG("Acceptor thread started with NULL argument");
        return NULL;
    }

    WS_DEBUG_LOG("Acceptor thread started on port %d", server->config.port);

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;
    uint32_t connection_count = 0;

    while (server->running) {
        client_addr_len = sizeof(client_addr);
        
        /* Accept new connection */
        client_fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No pending connections, wait a bit */
                usleep(1000); /* 1ms */
                continue;
            } else if (errno == EINTR) {
                /* Interrupted by signal, continue */
                continue;
            } else {
                WS_ERROR_LOG("Failed to accept connection: %s", strerror(errno));
                if (!server->running) break; /* Server shutting down */
                continue;
            }
        }

        connection_count++;
        WS_DEBUG_LOG("Accepted connection %u from fd=%d", connection_count, client_fd);

        /* Set socket to non-blocking mode */
        if (ws_set_socket_nonblocking(client_fd) < 0) {
            WS_ERROR_LOG("Failed to set client socket non-blocking: %s", strerror(errno));
            close(client_fd);
            continue;
        }

        /* Enable TCP_NODELAY if configured */
        if (server->config.enable_nodelay) {
            if (ws_set_socket_nodelay(client_fd, true) < 0) {
                WS_DEBUG_LOG("Failed to set TCP_NODELAY (non-critical): %s", strerror(errno));
            }
        }

        /* Enable SO_KEEPALIVE if configured */
        if (server->config.enable_keepalive) {
            if (ws_set_socket_keepalive(client_fd, true) < 0) {
                WS_DEBUG_LOG("Failed to set SO_KEEPALIVE (non-critical): %s", strerror(errno));
            }
        }

        /* Select target thread using round-robin load balancing */
        uint32_t target_thread = server->next_thread;
        server->next_thread = (server->next_thread + 1) % server->thread_count;

        /* Check if target thread has capacity */
        ws_event_thread_t *thread = &server->threads[target_thread];
        if (atomic_load(&thread->active_connections) >= thread->max_connections) {
            WS_DEBUG_LOG("Thread %u at capacity (%u/%u), trying other threads", 
                         target_thread, atomic_load(&thread->active_connections), thread->max_connections);
            
            /* Find a thread with capacity */
            bool found_thread = false;
            for (uint32_t i = 0; i < server->thread_count; i++) {
                uint32_t try_thread = (target_thread + i) % server->thread_count;
                if (atomic_load(&server->threads[try_thread].active_connections) < server->threads[try_thread].max_connections) {
                    target_thread = try_thread;
                    thread = &server->threads[target_thread];
                    found_thread = true;
                    WS_DEBUG_LOG("Using thread %u instead (%u/%u connections)", 
                                 target_thread, atomic_load(&thread->active_connections), thread->max_connections);
                    break;
                }
            }
            
            if (!found_thread) {
                WS_ERROR_LOG("All threads at capacity, rejecting connection");
                close(client_fd);
                continue;
            }
        }

        /* Send new connection message to selected thread via MPSC queue */
        WS_DEBUG_LOG("Assigned connection fd=%d to thread %u (%u/%u connections)", 
                     client_fd, target_thread, atomic_load(&thread->active_connections), thread->max_connections);
        
        /* Send the connection to the event thread */
        if (ws_mpsc_send_new_connection(thread->message_queue, client_fd, &client_addr, client_addr_len) < 0) {
            WS_ERROR_LOG("Failed to send new connection fd=%d to thread %u: closing connection", 
                         client_fd, target_thread);
            close(client_fd);
            continue;
        }

        /* Wake up the target thread */
        uint64_t wakeup_value = 1;
        if (write(thread->wakeup_eventfd, &wakeup_value, sizeof(wakeup_value)) < 0) {
            WS_DEBUG_LOG("Failed to wake up thread %u (non-critical): %s", 
                         target_thread, strerror(errno));
        }
        
        WS_DEBUG_LOG("Sent connection fd=%d to thread %u via MPSC queue", client_fd, target_thread);
        
        /* Update connection count tracking */
        atomic_fetch_add(&server->connection_count, 1);
        server->thread_loads[target_thread]++;
        
        /* Update thread load tracking */
        WS_DEBUG_LOG("Thread loads: [0]=%u [1]=%u [2]=%u [3]=%u", 
                     server->thread_loads[0], server->thread_loads[1], 
                     server->thread_loads[2], server->thread_loads[3]);
    }

    WS_DEBUG_LOG("Acceptor thread stopping");
    return NULL;
}

/* ============================================================================
 * Server Creation and Destruction
 * ============================================================================ */

ws_server_t* ws_server_create_internal(const ws_config_t *config) {
    if (!config || config->thread_count == 0) {
        WS_ERROR_LOG("Invalid configuration or thread count");
        return NULL;
    }

    ws_server_internal_t *server = calloc(1, sizeof(ws_server_internal_t));
    if (!server) {
        WS_ERROR_LOG("Failed to allocate server memory");
        return NULL;
    }

    /* Copy configuration */
    server->config = *config;
    server->thread_count = config->thread_count;
    server->max_connections_total = config->max_connections;
    server->listen_fd = -1;
    server->running = false;
    server->start_time = time(NULL);

    /* Create global connection hash table */
    server->global_hash = ws_connection_hash_create();
    if (!server->global_hash) {
        WS_ERROR_LOG("Failed to create global connection hash");
        free(server);
        return NULL;
    }

    /* Allocate thread pool */
    server->threads = calloc(server->thread_count, sizeof(ws_event_thread_t));
    if (!server->threads) {
        WS_ERROR_LOG("Failed to allocate thread pool");
        ws_connection_hash_destroy(server->global_hash);
        free(server);
        return NULL;
    }

    /* Allocate thread loads tracking */
    server->thread_loads = calloc(server->thread_count, sizeof(uint32_t));
    if (!server->thread_loads) {
        WS_ERROR_LOG("Failed to allocate thread loads array");
        free(server->threads);
        ws_connection_hash_destroy(server->global_hash);
        free(server);
        return NULL;
    }

    /* Create listening socket */
    server->listen_fd = ws_create_listening_socket(&server->config);
    if (server->listen_fd < 0) {
        WS_ERROR_LOG("Failed to create listening socket");
        free(server->thread_loads);
        free(server->threads);
        ws_connection_hash_destroy(server->global_hash);
        free(server);
        return NULL;
    }

    WS_DEBUG_LOG("WebSocket server created on port %d with %d threads", 
                 config->port, config->thread_count);
    
    return (ws_server_t*)server;
}

void ws_server_destroy_internal(ws_server_t *server) {
    if (!server) return;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;

    /* Stop server if running */
    if (internal->running) {
        ws_server_stop_internal(server);
    }

    /* Close listening socket */
    if (internal->listen_fd >= 0) {
        close(internal->listen_fd);
        internal->listen_fd = -1;
    }

    /* Destroy global hash table */
    if (internal->global_hash) {
        ws_connection_hash_destroy(internal->global_hash);
        internal->global_hash = NULL;
    }

    /* Free thread-related resources (per-thread buffers/queues, then the array). */
    if (internal->threads) {
        for (uint32_t i = 0; i < internal->thread_count; i++)
            ws_cleanup_event_thread(&internal->threads[i]);
        free(internal->threads);
        internal->threads = NULL;
    }

    if (internal->thread_loads) {
        free(internal->thread_loads);
        internal->thread_loads = NULL;
    }

    free(internal);
    WS_DEBUG_LOG("WebSocket server destroyed");
}

/* ============================================================================
 * Server Start/Stop/Wait Functions
 * ============================================================================ */

int ws_server_start_internal(ws_server_t *server, const ws_callbacks_t *callbacks) {
    if (!server || !callbacks) {
        return WS_ERROR_INVALID_ARGS;
    }

    ws_server_internal_t *internal = (ws_server_internal_t*)server;

    if (internal->running) {
        WS_ERROR_LOG("Server is already running");
        return WS_ERROR_PROTOCOL;
    }

    /* Store callbacks */
    internal->callbacks = *callbacks;
    internal->running = true;

    /* Initialize event threads */
    uint32_t connections_per_thread = internal->max_connections_total / internal->thread_count;
    if (connections_per_thread == 0) {
        connections_per_thread = 1;
    }

    WS_DEBUG_LOG("Initializing %u event threads with %u connections each", 
                 internal->thread_count, connections_per_thread);

    for (uint32_t i = 0; i < internal->thread_count; i++) {
        int result = ws_init_event_thread(&internal->threads[i], i, 
                                        connections_per_thread, &internal->config, internal);
        if (result != WS_OK) {
            WS_ERROR_LOG("Failed to initialize event thread %u", i);
            
            /* Cleanup already initialized threads */
            for (uint32_t j = 0; j < i; j++) {
                ws_cleanup_event_thread(&internal->threads[j]);
            }
            internal->running = false;
            return result;
        }
    }

    /* Start event threads */
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        int result = pthread_create(&internal->threads[i].thread, NULL, 
                                   ws_event_thread_worker, &internal->threads[i]);
        if (result != 0) {
            WS_ERROR_LOG("Failed to create event thread %u: %s", i, strerror(result));
            
            /* Signal previously started threads to stop */
            for (uint32_t j = 0; j < i; j++) {
                internal->threads[j].running = false;
                uint64_t wakeup = 1;
                write(internal->threads[j].wakeup_eventfd, &wakeup, sizeof(wakeup));
            }
            
            /* Join already started threads */
            for (uint32_t j = 0; j < i; j++) {
                pthread_join(internal->threads[j].thread, NULL);
            }
            
            /* Cleanup all threads */
            for (uint32_t j = 0; j < internal->thread_count; j++) {
                ws_cleanup_event_thread(&internal->threads[j]);
            }
            
            internal->running = false;
            return WS_ERROR_SOCKET;
        }
        
        WS_DEBUG_LOG("Started event thread %u", i);
    }

    /* Create acceptor thread */
    WS_DEBUG_LOG("Creating acceptor thread...");
    int result = pthread_create(&internal->acceptor_thread, NULL, 
                               ws_acceptor_thread_worker, internal);
    if (result != 0) {
        WS_ERROR_LOG("Failed to create acceptor thread: %s", strerror(result));
        
        /* Signal all event threads to stop */
        for (uint32_t i = 0; i < internal->thread_count; i++) {
            internal->threads[i].running = false;
            uint64_t wakeup = 1;
            write(internal->threads[i].wakeup_eventfd, &wakeup, sizeof(wakeup));
        }
        
        /* Join all event threads */
        for (uint32_t i = 0; i < internal->thread_count; i++) {
            pthread_join(internal->threads[i].thread, NULL);
        }
        
        /* Cleanup all threads */
        for (uint32_t i = 0; i < internal->thread_count; i++) {
            ws_cleanup_event_thread(&internal->threads[i]);
        }
        
        internal->running = false;
        return WS_ERROR_SOCKET;
    }
    
    WS_DEBUG_LOG("Acceptor thread created successfully");

    WS_DEBUG_LOG("WebSocket server started on port %d", internal->config.port);
    return WS_OK;
}

int ws_server_stop_internal(ws_server_t *server) {
    if (!server) return WS_ERROR_INVALID_ARGS;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;

    if (!internal->running) {
        return WS_ERROR_INVALID_ARGS;
    }

    /* Signal shutdown */
    internal->running = false;

    /* Join acceptor thread first */
    if (internal->acceptor_thread != 0) {
        int result = pthread_join(internal->acceptor_thread, NULL);
        if (result != 0) {
            WS_ERROR_LOG("Failed to join acceptor thread: %s", strerror(result));
        } else {
            WS_DEBUG_LOG("Joined acceptor thread");
        }
        internal->acceptor_thread = 0;
    }

    /* Signal all event threads to stop */
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        internal->threads[i].running = false;
        
        /* Wake up the thread if it's sleeping in epoll_wait */
        uint64_t wakeup = 1;
        if (write(internal->threads[i].wakeup_eventfd, &wakeup, sizeof(wakeup)) < 0) {
            WS_ERROR_LOG("Failed to wake up thread %u: %s", i, strerror(errno));
        }
    }

    /* Join all event threads */
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        if (internal->threads[i].thread != 0) {
            int result = pthread_join(internal->threads[i].thread, NULL);
            if (result != 0) {
                WS_ERROR_LOG("Failed to join thread %u: %s", i, strerror(result));
            } else {
                WS_DEBUG_LOG("Joined event thread %u", i);
            }
            internal->threads[i].thread = 0;
        }
    }

    /* Join acceptor thread */
    if (internal->acceptor_thread != 0) {
        WS_DEBUG_LOG("Joining acceptor thread...");
        pthread_join(internal->acceptor_thread, NULL);
        internal->acceptor_thread = 0;
        WS_DEBUG_LOG("Joined acceptor thread");
    }

    WS_DEBUG_LOG("WebSocket server stopped");
    return WS_OK;
}

int ws_server_wait_internal(ws_server_t *server) {
    if (!server) return WS_ERROR_INVALID_ARGS;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;

    /* Wait for all event threads to finish */
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        if (internal->threads[i].thread != 0) {
            pthread_join(internal->threads[i].thread, NULL);
            internal->threads[i].thread = 0;
        }
    }

    /* Wait for acceptor thread to finish */
    if (internal->acceptor_thread != 0) {
        pthread_join(internal->acceptor_thread, NULL);
        internal->acceptor_thread = 0;
    }

    /* Cleanup all threads */
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        ws_cleanup_event_thread(&internal->threads[i]);
    }

    return WS_OK;
}

/* ============================================================================
 * Connection Management Functions (Stubs)
 * ============================================================================ */

ws_connection_t* ws_find_connection_internal(ws_server_t *server, int fd) {
    if (!server || fd < 0) return NULL;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;
    /* Note: This function returns a connection WITHOUT taking a reference.
     * Use ws_connection_hash_find_and_ref for thread-safe access. */
    return ws_connection_hash_find(internal->global_hash, fd);
}

int ws_send_text_internal(ws_server_t *server, int fd, const char *data, size_t len) {
    if (!server || fd < 0 || !data) return WS_ERROR_INVALID_ARGS;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;
    
    /* Find connection and take a reference for thread safety */
    ws_connection_t *conn = ws_connection_hash_find_and_ref(internal->global_hash, fd);
    if (!conn) {
        WS_ERROR_LOG("Connection fd=%d not found for text send", fd);
        return WS_ERROR_NOT_FOUND;
    }
    
    /* Check connection state */
    if (conn->state != WS_STATE_OPEN) {
        WS_ERROR_LOG("Connection fd=%d not in OPEN state for text send", fd);
        ws_connection_unref(conn); /* Release reference */
        return WS_ERROR_PROTOCOL;
    }
    
    /* Send message to the appropriate event thread */
    ws_event_thread_t *target_thread = &internal->threads[conn->thread_id];
    if (ws_mpsc_send_text_message(target_thread->message_queue, fd, data, len) < 0) {
        WS_ERROR_LOG("Failed to queue text message for fd=%d", fd);
        ws_connection_unref(conn); /* Release reference */
        return WS_ERROR_QUEUE_FULL;
    }
    
    /* Wake up the target thread */
    uint64_t wake_value = 1;
    if (write(target_thread->wakeup_eventfd, &wake_value, sizeof(wake_value)) < 0) {
        WS_ERROR_LOG("Failed to wake up thread %u for text send", conn->thread_id);
    }
    
    WS_DEBUG_LOG("Queued text message (%zu bytes) for fd=%d to thread %u", len, fd, conn->thread_id);
    
    /* Release reference */
    ws_connection_unref(conn);
    return WS_OK;
}

int ws_send_binary_internal(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0 || (!data && len > 0)) return WS_ERROR_INVALID_ARGS;  /* portico: allow zero-length */

    ws_server_internal_t *internal = (ws_server_internal_t*)server;
    
    /* Find connection and take a reference for thread safety */
    ws_connection_t *conn = ws_connection_hash_find_and_ref(internal->global_hash, fd);
    if (!conn) {
        WS_ERROR_LOG("Connection fd=%d not found for binary send", fd);
        return WS_ERROR_NOT_FOUND;
    }
    
    /* Check connection state */
    if (conn->state != WS_STATE_OPEN) {
        WS_ERROR_LOG("Connection fd=%d not in OPEN state for binary send", fd);
        ws_connection_unref(conn); /* Release reference */
        return WS_ERROR_PROTOCOL;
    }
    
    /* Send message to the appropriate event thread */
    ws_event_thread_t *target_thread = &internal->threads[conn->thread_id];
    if (ws_mpsc_send_binary_message(target_thread->message_queue, fd, data, len) < 0) {
        WS_ERROR_LOG("Failed to queue binary message for fd=%d", fd);
        ws_connection_unref(conn); /* Release reference */
        return WS_ERROR_QUEUE_FULL;
    }
    
    /* Wake up the target thread */
    uint64_t wake_value = 1;
    if (write(target_thread->wakeup_eventfd, &wake_value, sizeof(wake_value)) < 0) {
        WS_ERROR_LOG("Failed to wake up thread %u for binary send", conn->thread_id);
    }
    
    WS_DEBUG_LOG("Queued binary message (%zu bytes) for fd=%d to thread %u", len, fd, conn->thread_id);
    
    /* Release reference */
    ws_connection_unref(conn);
    return WS_OK;
}

int ws_send_ping_internal(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0) return WS_ERROR_INVALID_ARGS;
    
    /* Limit ping payload to 125 bytes (RFC 6455) */
    if (len > WS_FRAME_MAX_CONTROL_PAYLOAD) {
        WS_ERROR_LOG("Ping payload too large: %zu bytes (max %d)", len, WS_FRAME_MAX_CONTROL_PAYLOAD);
        return WS_ERROR_INVALID_ARGS;
    }

    /* Create ping frame */
    uint8_t *frame_data = NULL;
    size_t frame_len = 0;
    
    int result = ws_encode_frame(WS_OPCODE_PING, (const uint8_t*)data, len, &frame_data, &frame_len);
    if (result != WS_OK) {
        WS_ERROR_LOG("Failed to encode ping frame: %d", result);
        return result;
    }
    
    /* Send ping frame */
    ssize_t sent = send(fd, frame_data, frame_len, MSG_NOSIGNAL);
    free(frame_data);
    
    if (sent < 0) {
        WS_ERROR_LOG("Failed to send ping frame to fd=%d: %s", fd, strerror(errno));
        return WS_ERROR_SOCKET;
    } else if ((size_t)sent != frame_len) {
        WS_ERROR_LOG("Partial ping frame sent to fd=%d: %zd/%zu bytes", fd, sent, frame_len);
        return WS_ERROR_SOCKET;
    }
    
    WS_DEBUG_LOG("Sent ping frame to fd=%d (%zu bytes payload)", fd, len);
    return WS_OK;
}

int ws_send_pong_internal(ws_server_t *server, int fd, const void *data, size_t len) {
    if (!server || fd < 0) return WS_ERROR_INVALID_ARGS;
    
    /* Limit pong payload to 125 bytes (RFC 6455) */
    if (len > WS_FRAME_MAX_CONTROL_PAYLOAD) {
        WS_ERROR_LOG("Pong payload too large: %zu bytes (max %d)", len, WS_FRAME_MAX_CONTROL_PAYLOAD);
        return WS_ERROR_INVALID_ARGS;
    }

    /* Create pong frame */
    uint8_t *frame_data = NULL;
    size_t frame_len = 0;
    
    int result = ws_encode_frame(WS_OPCODE_PONG, (const uint8_t*)data, len, &frame_data, &frame_len);
    if (result != WS_OK) {
        WS_ERROR_LOG("Failed to encode pong frame: %d", result);
        return result;
    }
    
    /* Send pong frame */
    ssize_t sent = send(fd, frame_data, frame_len, MSG_NOSIGNAL);
    free(frame_data);
    
    if (sent < 0) {
        WS_ERROR_LOG("Failed to send pong frame to fd=%d: %s", fd, strerror(errno));
        return WS_ERROR_SOCKET;
    } else if ((size_t)sent != frame_len) {
        WS_ERROR_LOG("Partial pong frame sent to fd=%d: %zd/%zu bytes", fd, sent, frame_len);
        return WS_ERROR_SOCKET;
    }
    
    WS_DEBUG_LOG("Sent pong frame to fd=%d (%zu bytes payload)", fd, len);
    return WS_OK;
}

int ws_close_connection_internal(ws_server_t *server, int fd, ws_close_code_t code, const char *reason) {
    if (!server || fd < 0) return WS_ERROR_INVALID_ARGS;

    /* Prepare close frame payload */
    uint8_t payload[125]; /* Max control frame payload */
    size_t payload_len = 0;
    
    /* Add close code (2 bytes, network byte order) */
    payload[0] = (code >> 8) & 0xFF;
    payload[1] = code & 0xFF;
    payload_len = 2;
    
    /* Add reason string if provided */
    if (reason) {
        size_t reason_len = strlen(reason);
        /* Ensure total payload doesn't exceed 125 bytes */
        if (payload_len + reason_len > WS_FRAME_MAX_CONTROL_PAYLOAD) {
            reason_len = WS_FRAME_MAX_CONTROL_PAYLOAD - payload_len;
        }
        memcpy(payload + payload_len, reason, reason_len);
        payload_len += reason_len;
    }

    /* Create close frame */
    uint8_t *frame_data = NULL;
    size_t frame_len = 0;
    
    int result = ws_encode_frame(WS_OPCODE_CLOSE, payload, payload_len, &frame_data, &frame_len);
    if (result != WS_OK) {
        WS_ERROR_LOG("Failed to encode close frame: %d", result);
        return result;
    }
    
    /* Send close frame */
    ssize_t sent = send(fd, frame_data, frame_len, MSG_NOSIGNAL);
    free(frame_data);
    
    if (sent < 0) {
        WS_DEBUG_LOG("Failed to send close frame to fd=%d: %s", fd, strerror(errno));
        /* Continue with close even if send fails */
    } else if ((size_t)sent != frame_len) {
        WS_DEBUG_LOG("Partial close frame sent to fd=%d: %zd/%zu bytes", fd, sent, frame_len);
    } else {
        WS_DEBUG_LOG("Sent close frame to fd=%d (code=%d, reason='%s')", fd, code, reason ? reason : "");
    }
    
    /* Note: The actual socket close is handled by the connection cleanup logic */
    return WS_OK;
}

ws_state_t ws_get_connection_state_internal(ws_server_t *server, int fd) {
    if (!server || fd < 0) return WS_STATE_CLOSED;

    ws_connection_t *conn = ws_find_connection_internal(server, fd);
    if (!conn) return WS_STATE_CLOSED;

    return (ws_state_t)(conn->state);
}

int ws_set_connection_user_data_internal(ws_server_t *server, int fd, void *user_data) {
    if (!server || fd < 0) return WS_ERROR_INVALID_ARGS;

    ws_connection_t *conn = ws_find_connection_internal(server, fd);
    if (!conn) return WS_ERROR_NOT_FOUND;

    conn->user_data = user_data;
    return WS_OK;
}

void* ws_get_connection_user_data_internal(ws_server_t *server, int fd) {
    if (!server || fd < 0) return NULL;

    ws_connection_t *conn = ws_find_connection_internal(server, fd);
    if (!conn) return NULL;

    return conn->user_data;
}

/* ============================================================================
 * Statistics Functions (Stubs)
 * ============================================================================ */

int ws_get_server_stats_internal(ws_server_t *server, ws_server_stats_t *stats) {
    if (!server || !stats) return WS_ERROR_INVALID_ARGS;

    ws_server_internal_t *internal = (ws_server_internal_t*)server;

    /* Clear stats structure */
    memset(stats, 0, sizeof(ws_server_stats_t));

    /* Fill connection statistics */
    stats->current_connections = atomic_load(&internal->connection_count);
    stats->total_connections_accepted = atomic_load(&internal->total_connections_accepted);
    
    /* Calculate peak connections by summing active connections across threads */
    uint32_t total_active = 0;
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        total_active += atomic_load(&internal->threads[i].active_connections);
    }
    stats->peak_connections = total_active; /* For now, use current as peak */
    
    /* Fill message statistics */
    stats->total_messages_received = atomic_load(&internal->total_messages_processed);
    
    /* Fill performance statistics */
    stats->active_threads = internal->thread_count;
    
    /* Calculate total events processed across all threads */
    uint64_t total_events = 0;
    uint64_t total_messages = 0;
    for (uint32_t i = 0; i < internal->thread_count; i++) {
        total_events += atomic_load(&internal->threads[i].events_processed);
        total_messages += atomic_load(&internal->threads[i].messages_processed);
    }
    /* Add thread-level message processing to the total */
    stats->total_messages_received += total_messages;

    return WS_OK;
}

void ws_print_server_stats_internal(ws_server_t *server) {
    if (!server) return;

    ws_server_stats_t stats;
    if (ws_get_server_stats_internal(server, &stats) == WS_OK) {
        fprintf(stderr, "=== WebSocket Server Statistics ===\n");
        fprintf(stderr, "Current connections: %lu\n", stats.current_connections);
        fprintf(stderr, "Messages received: %lu\n", stats.total_messages_received);
        fprintf(stderr, "Bytes sent: %lu\n", stats.total_bytes_sent);
        fprintf(stderr, "Bytes received: %lu\n", stats.total_bytes_received);
        fprintf(stderr, "===================================\n");
    }
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static int ws_create_listening_socket(const ws_config_t *config) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        WS_ERROR_LOG("Failed to create listening socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket options */
    if (ws_set_socket_reuseaddr(listen_fd, true) < 0) {
        WS_ERROR_LOG("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }

    /* SO_REUSEPORT is optional and not exposed in config for now */

    if (ws_set_socket_nonblocking(listen_fd) < 0) {
        WS_ERROR_LOG("Failed to set non-blocking mode: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    /* Bind to address */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config->port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        WS_ERROR_LOG("Failed to bind to port %d: %s", config->port, strerror(errno));
        close(listen_fd);
        return -1;
    }

    /* Start listening */
    if (listen(listen_fd, config->backlog) < 0) {
        WS_ERROR_LOG("Failed to listen on socket: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    return listen_fd;
}
