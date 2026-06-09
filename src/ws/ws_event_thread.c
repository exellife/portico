/* ============================================================================
 * WSLib - Event Thread Management
 * 
 * Event thread initialization, cleanup, and worker functions
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
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>

/* Forward declarations for functions in other files */
extern int handle_connection_read(ws_event_thread_t *thread, int fd);
extern int handle_connection_write(ws_event_thread_t *thread, int fd);
extern void close_connection(ws_event_thread_t *thread, int fd);
extern int process_new_connection(int fd, const struct sockaddr_storage *client_addr, socklen_t client_addr_len, void *context);
extern int process_text_message(int fd, const char *data, size_t len, void *context);
extern int process_binary_message(int fd, const void *data, size_t len, void *context);
extern int process_ping_message(int fd, const void *data, size_t len, void *context);
extern int process_pong_message(int fd, const void *data, size_t len, void *context);
extern int process_close_message(int fd, ws_close_code_t code, const char *reason, void *context);
extern int process_user_data_update(int fd, void *user_data, void *context);
extern int process_shutdown_signal(void *context);

/* ============================================================================
 * O(1) Connection Lookup (Bottleneck #5 Optimization)
 * 
 * Direct FD → connection mapping for instant lookups
 * Performance: O(1) vs O(n) linear search through 10,000 connections
 * ============================================================================ */

/* Register connection in FD map */
void ws_register_fd(ws_event_thread_t *thread, int fd, ws_connection_t *conn) {
    if (fd < 0) {
        WS_ERROR_LOG("Thread %u: Cannot register invalid FD %d", thread->thread_id, fd);
        return;
    }
    
    if (fd < (int)thread->fd_map_size) {
        /* Fast path: Register in O(1) lookup map */
        thread->fd_to_conn_map[fd] = conn;
    } else {
        /* FD exceeds map size - will use O(n) fallback for lookups */
        WS_DEBUG_LOG("Thread %u: FD %d exceeds map size %u, O(1) lookup unavailable (will use fallback)", 
                     thread->thread_id, fd, thread->fd_map_size);
        /* Connection is still tracked in thread->connections array, so fallback search will work */
    }
}

/* Unregister connection from FD map */
void ws_unregister_fd(ws_event_thread_t *thread, int fd) {
    if (fd >= 0 && fd < (int)thread->fd_map_size) {
        thread->fd_to_conn_map[fd] = NULL;
    }
    /* If fd >= fd_map_size, it was never registered, so nothing to do */
}

/* O(1) connection lookup by FD with fallback to O(n) for out-of-bounds FDs */
ws_connection_t* ws_find_connection_by_fd(ws_event_thread_t *thread, int fd) {
    /* Fast path: O(1) lookup if FD is within map bounds */
    if (fd >= 0 && fd < (int)thread->fd_map_size) {
        return thread->fd_to_conn_map[fd];
    }
    
    /* Slow path fallback: O(n) linear search for FDs beyond map size */
    /* This handles edge cases where FD numbers exceed our map size */
    WS_DEBUG_LOG("Thread %u: FD %d exceeds map size %u, using fallback search", 
                 thread->thread_id, fd, thread->fd_map_size);
    
    for (uint32_t i = 0; i < thread->max_connections; i++) {
        if (thread->connections[i].fd == fd) {
            return &thread->connections[i];
        }
    }
    
    return NULL;
}

/* ============================================================================
 * Event Thread Management
 * ============================================================================ */

int ws_init_event_thread(ws_event_thread_t *thread, uint32_t thread_id, 
                               uint32_t max_connections, const ws_config_t *config,
                               void *server_instance) {
    if (!thread || max_connections == 0) {
        return WS_ERROR_INVALID_ARGS;
    }

    /* Initialize thread identification */
    thread->thread_id = thread_id;
    thread->cpu_affinity = -1; /* No affinity by default */
    thread->server_instance = server_instance;
    thread->max_connections = max_connections;
    atomic_store(&thread->active_connections, 0);
    thread->running = false;
    thread->paused = false;

    /* Create epoll instance */
    thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (thread->epoll_fd < 0) {
        WS_ERROR_LOG("Failed to create epoll instance for thread %u: %s", 
                     thread_id, strerror(errno));
        return WS_ERROR_SOCKET;
    }

    /* Allocate events array */
    thread->max_events = 1024; /* Process up to 1024 events per epoll_wait */
    thread->events = calloc(thread->max_events, sizeof(struct epoll_event));
    if (!thread->events) {
        WS_ERROR_LOG("Failed to allocate events array for thread %u", thread_id);
        close(thread->epoll_fd);
        return WS_ERROR_MEMORY;
    }

    /* Create wakeup eventfd */
    thread->wakeup_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (thread->wakeup_eventfd < 0) {
        WS_ERROR_LOG("Failed to create wakeup eventfd for thread %u: %s", 
                     thread_id, strerror(errno));
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_SOCKET;
    }

    /* Add wakeup eventfd to epoll */
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET; /* Edge-triggered */
    ev.data.fd = thread->wakeup_eventfd;
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->wakeup_eventfd, &ev) < 0) {
        WS_ERROR_LOG("Failed to add wakeup eventfd to epoll for thread %u: %s", 
                     thread_id, strerror(errno));
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_SOCKET;
    }

    /* Create MPSC queue for inter-thread communication */
    /* Increased queue size for high-load scenarios (10K+ connections) */
    thread->message_queue = ws_mpsc_queue_create_adaptive(4096, 131072, 2);
    if (!thread->message_queue) {
        WS_ERROR_LOG("Failed to create MPSC queue for thread %u", thread_id);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_MEMORY;
    }

    /* Initialize thread-local buffer pools */
    int result = ws_buffer_pool_init_adaptive(&thread->small_buffers, 1024, 
                                            config->small_buffer_count / 4, 
                                            config->small_buffer_count);
    if (result != 0) {
        WS_ERROR_LOG("Failed to initialize small buffer pool for thread %u", thread_id);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return result;
    }

    result = ws_buffer_pool_init_adaptive(&thread->medium_buffers, 4096, 
                                        config->medium_buffer_count / 4, 
                                        config->medium_buffer_count);
    if (result != 0) {
        WS_ERROR_LOG("Failed to initialize medium buffer pool for thread %u", thread_id);
        ws_buffer_pool_cleanup(&thread->small_buffers);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return result;
    }

    result = ws_buffer_pool_init_adaptive(&thread->large_buffers, 16384, 
                                        config->large_buffer_count / 4, 
                                        config->large_buffer_count);
    if (result != 0) {
        WS_ERROR_LOG("Failed to initialize large buffer pool for thread %u", thread_id);
        ws_buffer_pool_cleanup(&thread->medium_buffers);
        ws_buffer_pool_cleanup(&thread->small_buffers);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return result;
    }

    /* Allocate connections array */
    thread->connections = calloc(max_connections, sizeof(ws_connection_t));
    if (!thread->connections) {
        WS_ERROR_LOG("Failed to allocate connections array for thread %u", thread_id);
        ws_buffer_pool_cleanup(&thread->large_buffers);
        ws_buffer_pool_cleanup(&thread->medium_buffers);
        ws_buffer_pool_cleanup(&thread->small_buffers);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_MEMORY;
    }

    /* Initialize FD → connection map for O(1) lookup (Bottleneck #5) */
    /* Query system FD limit to size the map appropriately */
    struct rlimit fd_limit;
    if (getrlimit(RLIMIT_NOFILE, &fd_limit) == 0) {
        /* Use the soft limit directly - memory is cheap, performance is critical */
        thread->fd_map_size = fd_limit.rlim_cur;
        WS_DEBUG_LOG("Thread %u: System FD limit: %lu, using FD map size: %u (%.2f MB)", 
                     thread_id, (unsigned long)fd_limit.rlim_cur, thread->fd_map_size,
                     (thread->fd_map_size * sizeof(ws_connection_t*)) / (1024.0 * 1024.0));
    } else {
        /* Fallback if getrlimit fails - use 1M to match typical system limit */
        /* This is 8 MB per thread, which is acceptable for robust FD coverage */
        thread->fd_map_size = 1048576;
        WS_ERROR_LOG("Thread %u: Failed to query FD limit, using fallback map size: %u (%.2f MB)", 
                     thread_id, thread->fd_map_size,
                     (thread->fd_map_size * sizeof(ws_connection_t*)) / (1024.0 * 1024.0));
    }
    
    thread->fd_to_conn_map = calloc(thread->fd_map_size, sizeof(ws_connection_t*));
    if (!thread->fd_to_conn_map) {
        WS_ERROR_LOG("Failed to allocate FD map for thread %u", thread_id);
        free(thread->connections);
        ws_buffer_pool_cleanup(&thread->large_buffers);
        ws_buffer_pool_cleanup(&thread->medium_buffers);
        ws_buffer_pool_cleanup(&thread->small_buffers);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_MEMORY;
    }

    /* Initialize connection free stack */
    thread->free_connection_stack = calloc(max_connections, sizeof(uint32_t));
    if (!thread->free_connection_stack) {
        WS_ERROR_LOG("Failed to allocate connection free stack for thread %u", thread_id);
        free(thread->connections);
        ws_buffer_pool_cleanup(&thread->large_buffers);
        ws_buffer_pool_cleanup(&thread->medium_buffers);
        ws_buffer_pool_cleanup(&thread->small_buffers);
        ws_mpsc_queue_destroy(thread->message_queue);
        close(thread->wakeup_eventfd);
        free(thread->events);
        close(thread->epoll_fd);
        return WS_ERROR_MEMORY;
    }

    /* Initialize free connection stack (all connections available initially) */
    thread->free_connection_count = max_connections;
    for (uint32_t i = 0; i < max_connections; i++) {
        thread->free_connection_stack[i] = max_connections - 1 - i; /* Stack, so reverse order */
        
        /* Initialize connection structure */
        ws_connection_t *conn = &thread->connections[i];
        conn->fd = -1;
        conn->state = WS_STATE_CLOSED;
        conn->thread_id = thread_id;
        conn->pool_index = i;
        conn->user_data = NULL;
        conn->last_activity = 0;
    }

    /* Initialize performance counters */
    atomic_init(&thread->events_processed, 0);
    atomic_init(&thread->messages_processed, 0);
    thread->last_activity_time = time(NULL);

    WS_DEBUG_LOG("Initialized event thread %u: epoll_fd=%d, max_conn=%u, buffers=(%d/%d/%d)", 
                 thread_id, thread->epoll_fd, max_connections,
                 config->small_buffer_count / 4, config->medium_buffer_count / 4, 
                 config->large_buffer_count / 4);

    return WS_OK;
}

void ws_cleanup_event_thread(ws_event_thread_t *thread) {
    if (!thread) return;

    /* Signal thread to stop if running */
    thread->running = false;

    /* Join thread if it was started */
    if (thread->thread != 0) {
        pthread_join(thread->thread, NULL);
        thread->thread = 0;
    }

    /* Destroy the per-thread MPSC message queue (preallocated node pool). */
    if (thread->message_queue) {
        ws_mpsc_queue_destroy(thread->message_queue);
        thread->message_queue = NULL;
    }

    /* Close all connections */
    if (thread->connections) {
        for (uint32_t i = 0; i < thread->max_connections; i++) {
            ws_connection_t *conn = &thread->connections[i];
            if (conn->fd >= 0) {
                close(conn->fd);
                conn->fd = -1;
            }
        }
        free(thread->connections);
        thread->connections = NULL;
    }

    /* Free connection management structures */
    if (thread->free_connection_stack) {
        free(thread->free_connection_stack);
        thread->free_connection_stack = NULL;
    }

    /* Free FD map */
    if (thread->fd_to_conn_map) {
        free(thread->fd_to_conn_map);
        thread->fd_to_conn_map = NULL;
    }

    /* Cleanup buffer pools */
    ws_buffer_pool_cleanup(&thread->large_buffers);
    ws_buffer_pool_cleanup(&thread->medium_buffers);
    ws_buffer_pool_cleanup(&thread->small_buffers);

    /* Cleanup MPSC queue */
    if (thread->message_queue) {
        ws_mpsc_queue_destroy(thread->message_queue);
        thread->message_queue = NULL;
    }

    /* Close event-related file descriptors */
    if (thread->wakeup_eventfd >= 0) {
        close(thread->wakeup_eventfd);
        thread->wakeup_eventfd = -1;
    }

    if (thread->epoll_fd >= 0) {
        close(thread->epoll_fd);
        thread->epoll_fd = -1;
    }

    /* Free events array */
    if (thread->events) {
        free(thread->events);
        thread->events = NULL;
    }

    WS_DEBUG_LOG("Cleaned up event thread %u", thread->thread_id);
}

/* ============================================================================
 * Event Thread Worker Function
 * ============================================================================ */

void* ws_event_thread_worker(void *arg) {
    ws_event_thread_t *thread = (ws_event_thread_t*)arg;
    if (!thread) {
        WS_ERROR_LOG("Event thread started with NULL argument");
        return NULL;
    }

    WS_DEBUG_LOG("Event thread %u started (epoll_fd=%d)", thread->thread_id, thread->epoll_fd);

    /* Set up message processor */
    ws_mpsc_message_processor_t processor = {
        .process_new_connection = process_new_connection,
        .process_text_message = process_text_message,
        .process_binary_message = process_binary_message,
        .process_ping_message = process_ping_message,
        .process_pong_message = process_pong_message,
        .process_close_message = process_close_message,
        .process_user_data_update = process_user_data_update,
        .process_shutdown_signal = process_shutdown_signal,
        .context = thread
    };

    /* Set CPU affinity if specified */
    if (thread->cpu_affinity >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(thread->cpu_affinity, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
            WS_ERROR_LOG("Failed to set CPU affinity for thread %u to CPU %d", 
                         thread->thread_id, thread->cpu_affinity);
        } else {
            WS_DEBUG_LOG("Thread %u bound to CPU %d", thread->thread_id, thread->cpu_affinity);
        }
    }

    thread->running = true;
    thread->last_activity_time = time(NULL);

    /* Main event loop */
    while (thread->running && !thread->paused) {
        /* Wait for events */
        int nfds = epoll_wait(thread->epoll_fd, thread->events, thread->max_events, 100); /* 100ms timeout */
        
        if (nfds < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by signal, retry */
            }
            WS_ERROR_LOG("epoll_wait failed for thread %u: %s", thread->thread_id, strerror(errno));
            break;
        }

        if (nfds == 0) {
            /* Timeout - process pending messages and continue */
            int processed = ws_mpsc_process_messages(thread->message_queue, &processor, 10);
            if (processed > 0) {
                WS_DEBUG_LOG("Thread %u: Processed %d MPSC messages on timeout", thread->thread_id, processed);
            }
            continue;
        }

        /* Process events */
        for (int i = 0; i < nfds; i++) {
            struct epoll_event *ev = &thread->events[i];
            int fd = ev->data.fd;

            if (fd == thread->wakeup_eventfd) {
                /* Wakeup event - drain eventfd and process MPSC queue */
                uint64_t dummy;
                while (read(thread->wakeup_eventfd, &dummy, sizeof(dummy)) > 0) {
                    /* Continue reading until EAGAIN */
                }
                /* Drain the ENTIRE MPSC queue. The wakeup eventfd is
                 * edge-triggered and was just drained above, so any messages
                 * left queued after a bounded batch would be stranded until the
                 * next producer write — which may never come. That stranded
                 * new-connection messages, leaving accepted sockets unregistered
                 * and unprocessed (they pile up in CLOSE_WAIT and leak). Loop
                 * until the queue is empty so nothing is left behind. */
                int batch, total = 0;
                do {
                    batch = ws_mpsc_process_messages(thread->message_queue, &processor, 256);
                    if (batch > 0) total += batch;
                } while (batch > 0);
                if (total > 0) {
                    WS_DEBUG_LOG("Thread %u: Processed %d MPSC messages on wakeup", thread->thread_id, total);
                }
            } else {
                /* Connection event - handle I/O. A single wakeup can carry
                 * several flags for one fd (EPOLLIN|EPOLLOUT|EPOLLHUP); once we
                 * close the connection, skip the rest so we don't operate on (or
                 * re-close) a freed fd whose number may have been reused. */
                int closed = 0;

                if (ev->events & EPOLLIN) {
                    /* Data available for reading */
                    if (handle_connection_read(thread, fd) < 0) {
                        WS_DEBUG_LOG("Thread %u: Connection fd=%d read failed, closing", thread->thread_id, fd);
                        close_connection(thread, fd);
                        closed = 1;
                    }
                }

                if (!closed && (ev->events & EPOLLOUT)) {
                    /* Socket ready for writing — drains buffered output; closes
                     * the connection itself (returns <0) on write error. */
                    if (handle_connection_write(thread, fd) < 0) closed = 1;
                }

                if (!closed && (ev->events & (EPOLLHUP | EPOLLERR))) {
                    /* Connection closed or error */
                    WS_DEBUG_LOG("Thread %u: Connection fd=%d closed/error", thread->thread_id, fd);
                    close_connection(thread, fd);
                }

                atomic_fetch_add(&thread->events_processed, 1);
            }
        }

        thread->last_activity_time = time(NULL);
    }

    thread->running = false;
    WS_DEBUG_LOG("Event thread %u stopping", thread->thread_id);
    return NULL;
}
