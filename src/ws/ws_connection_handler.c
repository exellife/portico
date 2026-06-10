/* ============================================================================
 * WSLib - Connection I/O Handling
 * 
 * Connection read/write, handshake processing, and WebSocket frame handling
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

/* Forward declaration for O(1) connection lookup */
extern ws_connection_t* ws_find_connection_by_fd(ws_event_thread_t *thread, int fd);
extern void ws_unregister_fd(ws_event_thread_t *thread, int fd);
extern void ws_register_fd(ws_event_thread_t *thread, int fd, ws_connection_t *conn);

/* ============================================================================
 * Connection I/O Handling
 * ============================================================================ */

/* Arm (want_out=1) or disarm EPOLLOUT for fd, keeping edge-triggered EPOLLIN —
 * mirrors the HTTP backpressure path. Used to wait for writability when a TLS
 * handshake step returns WANT_WRITE. */
static void tls_set_epollout(ws_event_thread_t *thread, int fd, int want_out) {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | (want_out ? (uint32_t)EPOLLOUT : 0u);
    ev.data.fd = fd;
    epoll_ctl(thread->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

/* Drive the TLS accept handshake one step. Called from both the EPOLLIN and the
 * EPOLLOUT paths (a step can need either). On completion the connection drops to
 * WS_STATE_CONNECTING so the normal HTTP/WS dispatch takes over (its reads/writes
 * become SSL-aware in stage 3). Returns 0 to keep the connection, -1 to close. */
static int handle_tls_handshake(ws_event_thread_t *thread, ws_connection_t *conn,
                                ws_server_internal_t *server) {
    switch (ws_tls_do_handshake(conn->ssl)) {
        case WS_TLS_DONE:
            tls_set_epollout(thread, conn->fd, 0);      /* ensure EPOLLOUT disarmed */
            ws_connection_set_state(conn, WS_STATE_CONNECTING);
            /* The client may have pipelined its request into the same flight as
             * the handshake's final record; that data now sits in OpenSSL's
             * buffer and edge-triggered epoll won't refire for it. Drive the
             * initial dispatch once so it is processed. */
            return portico_initial_dispatch(thread, conn, server);
        case WS_TLS_WANT_READ:
            tls_set_epollout(thread, conn->fd, 0);
            return 0;                                    /* wait for next EPOLLIN (ET) */
        case WS_TLS_WANT_WRITE:
            tls_set_epollout(thread, conn->fd, 1);       /* wait for writability */
            return 0;
        default:
            WS_DEBUG_LOG("Thread %u: TLS handshake failed on fd=%d", thread->thread_id, conn->fd);
            return -1;
    }
}

int handle_connection_read(ws_event_thread_t *thread, int fd) {
    if (!thread || fd < 0) {
        return -1;
    }

    /* O(1) connection lookup using FD map (Bottleneck #5 optimization) */
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);
    
    if (!conn) {
        /* This is expected during race conditions - connection already cleaned up */
        WS_DEBUG_LOG("Thread %u: Connection fd=%d not found in thread (likely already closed)", thread->thread_id, fd);
        return -1;
    }

    /* Get server instance */
    ws_server_internal_t *server = (ws_server_internal_t*)thread->server_instance;
    if (!server) {
        WS_ERROR_LOG("Thread %u: No server instance", thread->thread_id);
        return -1;
    }

    /* Handle based on connection state */
    WS_DEBUG_LOG("Thread %u: Connection fd=%d state=%d", thread->thread_id, fd, conn->state);

    if (conn->state == WS_STATE_TLS_HANDSHAKE) {
        /* Encrypted: complete the TLS handshake before any HTTP/WS dispatch. */
        return handle_tls_handshake(thread, conn, server);
    } else if (conn->state == WS_STATE_CONNECTING) {
        /* First read: decide WebSocket handshake vs. plain HTTP (portico). */
        WS_DEBUG_LOG("Thread %u: Initial dispatch for fd=%d", thread->thread_id, fd);
        return portico_initial_dispatch(thread, conn, server);
    } else if (conn->state == WS_STATE_OPEN) {
        /* Process WebSocket frames */
        WS_DEBUG_LOG("Thread %u: Processing WebSocket frames for fd=%d", thread->thread_id, fd);
        return handle_websocket_frames(thread, conn, server);
    } else if (conn->state == WS_STATE_HTTP) {
        /* Plain-HTTP connection (keep-alive): read & process more requests. */
        return portico_http_event(thread, conn, server);
    } else {
        /* Connection in closing/closed state - just close it */
        WS_DEBUG_LOG("Thread %u: Connection fd=%d in state %d, closing",
                     thread->thread_id, fd, conn->state);
        return -1;
    }
}

int handle_websocket_handshake(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server) {
    char buffer[4096];
    ssize_t bytes_read = ws_conn_socket_read(conn, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        if (bytes_read == 0) {
            WS_DEBUG_LOG("Thread %u: Connection fd=%d closed during handshake", thread->thread_id, conn->fd);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            WS_DEBUG_LOG("Thread %u: Read error during handshake on fd=%d: %s", 
                         thread->thread_id, conn->fd, strerror(errno));
        }
        return -1;
    }

    buffer[bytes_read] = '\0';
    WS_DEBUG_LOG("Thread %u: Received handshake data %zd bytes on fd=%d", 
                 thread->thread_id, bytes_read, conn->fd);

    /* Process WebSocket handshake */
    if (ws_process_handshake(conn, buffer, &server->callbacks) == 0) {
        WS_DEBUG_LOG("Thread %u: WebSocket handshake completed for fd=%d", thread->thread_id, conn->fd);
        
        /* Update connection state to OPEN */
        ws_connection_set_state(conn, WS_STATE_OPEN);
        
        /* Call application connect callback */
        if (server->callbacks.on_connect) {
            server->callbacks.on_connect(conn->fd, NULL);
        }
        
        return 0;
    } else {
        WS_DEBUG_LOG("Thread %u: WebSocket handshake failed for fd=%d", thread->thread_id, conn->fd);
        return -1;
    }
}

/* pgforge: distinct result so a clean CLOSE handshake isn't logged as an error. */
#define WS_FRAME_CLOSE_REQUESTED (-2)

int handle_websocket_frames(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server) {
    if (!conn->recv_buffer || conn->recv_buffer_capacity == 0) {
        WS_ERROR_LOG("Thread %u: No receive buffer allocated for fd=%d", thread->thread_id, conn->fd);
        return -1;
    }

    /* Upper bound the per-connection receive buffer: the configured max message
     * size plus a little framing overhead (never below the initial capacity). */
    size_t hard_max = server->config.max_message_size + 64;
    if (hard_max < conn->recv_buffer_capacity) hard_max = conn->recv_buffer_capacity;

    /* Edge-triggered epoll: drain the socket until EAGAIN, growing the receive
     * buffer on demand so frames larger than the initial capacity can be
     * assembled (previously a hard 16KB cap caused "buffer full" disconnects). */
    for (;;) {
        if (conn->recv_buffer_used == conn->recv_buffer_capacity) {
            if (conn->recv_buffer_capacity >= hard_max) {
                WS_ERROR_LOG("Thread %u: frame exceeds max_message_size (%zu) on fd=%d",
                             thread->thread_id, server->config.max_message_size, conn->fd);
                conn->recv_buffer_used = 0;
                return -1;
            }
            size_t new_cap = conn->recv_buffer_capacity * 2;
            if (new_cap > hard_max) new_cap = hard_max;
            uint8_t *grown = realloc(conn->recv_buffer, new_cap);
            if (!grown) {
                WS_ERROR_LOG("Thread %u: recv buffer realloc to %zu failed on fd=%d",
                             thread->thread_id, new_cap, conn->fd);
                return -1;
            }
            conn->recv_buffer = grown;
            conn->recv_buffer_capacity = new_cap;
        }

        size_t space_left = conn->recv_buffer_capacity - conn->recv_buffer_used;
        ssize_t bytes_read = ws_conn_socket_read(conn, conn->recv_buffer + conn->recv_buffer_used,
                                                 space_left);
        if (bytes_read == 0) {
            WS_DEBUG_LOG("Thread %u: Connection fd=%d closed by client", thread->thread_id, conn->fd);
            return -1;
        }
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;  /* socket drained */
            WS_DEBUG_LOG("Thread %u: Read error on fd=%d: %s", thread->thread_id, conn->fd, strerror(errno));
            return -1;
        }

        conn->recv_buffer_used += bytes_read;
        ws_connection_add_bytes_received(conn, bytes_read);

        /* Parse and process every complete frame currently buffered. */
        size_t offset = 0;
        while (offset < conn->recv_buffer_used) {
            ws_frame_t frame;
            memset(&frame, 0, sizeof(frame));

            int parse_result = ws_parse_frame(conn->recv_buffer + offset,
                                              conn->recv_buffer_used - offset, &frame,
                                              server->config.max_message_size);

            if (parse_result < 0) {
                WS_ERROR_LOG("Thread %u: Failed to parse WebSocket frame on fd=%d",
                             thread->thread_id, conn->fd);
                conn->recv_buffer_used = 0;
                return -1;
            }
            if (parse_result == 0) {
                /* Incomplete frame: keep trailing bytes at the front, read more. */
                if (offset > 0) {
                    memmove(conn->recv_buffer, conn->recv_buffer + offset,
                            conn->recv_buffer_used - offset);
                    conn->recv_buffer_used -= offset;
                }
                offset = 0;
                break;
            }

            int proc = process_websocket_frame(thread, conn, server, &frame);
            if (frame.payload && frame.owns_payload) {
                free(frame.payload);
                frame.payload = NULL;
            }
            if (proc == WS_FRAME_CLOSE_REQUESTED) {
                return WS_FRAME_CLOSE_REQUESTED;  /* clean close handshake */
            }
            if (proc < 0) {
                WS_ERROR_LOG("Thread %u: Failed to process WebSocket frame on fd=%d",
                             thread->thread_id, conn->fd);
                conn->recv_buffer_used = 0;
                return -1;
            }
            offset += parse_result;
        }

        /* Drop fully-consumed bytes from the front of the buffer. */
        if (offset > 0) {
            if (offset < conn->recv_buffer_used) {
                memmove(conn->recv_buffer, conn->recv_buffer + offset,
                        conn->recv_buffer_used - offset);
                conn->recv_buffer_used -= offset;
            } else {
                conn->recv_buffer_used = 0;
            }
        }
    }

    return 0;
}

/* Fail the connection per RFC 6455 §7.1.7: send a Close frame with the given
 * status code, mark the connection closing, and signal the read loop to tear it
 * down. Returns WS_FRAME_CLOSE_REQUESTED so callers propagate the clean close. */
static int ws_fail_connection(ws_connection_t *conn, uint16_t code) {
    ws_connection_set_state(conn, WS_STATE_CLOSING);
    ws_send_close_frame(conn, code, "");
    return WS_FRAME_CLOSE_REQUESTED;
}

/* RFC 6455 §7.4.1: 1000-1003, 1007-1011 are defined; 3000-4999 are reserved for
 * application/registered use. Everything else (incl. 1004-1006, 1012-2999, and
 * >4999) is invalid when received in a Close frame. */
static bool ws_close_code_valid(uint16_t code) {
    if (code >= 3000 && code <= 4999) return true;
    switch (code) {
        case 1000: case 1001: case 1002: case 1003:
        case 1007: case 1008: case 1009: case 1010: case 1011:
            return true;
        default:
            return false;
    }
}

int process_websocket_frame(ws_event_thread_t *thread, ws_connection_t *conn, ws_server_internal_t *server, const ws_frame_t *frame) {
    if (!thread || !conn || !server || !frame) {
        return -1;
    }

    /* RFC 6455 §5.5: control frames (opcode >= 0x8) MUST NOT be fragmented and
     * MUST have a payload <= 125 bytes. Violations are protocol errors. */
    if (frame->opcode >= 0x8 && (!frame->fin || frame->payload_len > 125)) {
        WS_ERROR_LOG("Thread %u: Invalid control frame (fin=%d, len=%lu) on fd=%d",
                     thread->thread_id, frame->fin, frame->payload_len, conn->fd);
        return ws_fail_connection(conn, WS_CLOSE_PROTOCOL_ERROR);
    }

    WS_DEBUG_LOG("Thread %u: Processing frame opcode=%d, fin=%d, payload_len=%lu on fd=%d", 
                 thread->thread_id, frame->opcode, frame->fin, frame->payload_len, conn->fd);
    
    /* Debug fragmentation state */
    ws_frame_parser_t *parser = &conn->frame_parser;
    WS_DEBUG_LOG("Thread %u: Fragmentation state: in_fragmented=%d, fragment_opcode=%d on fd=%d", 
                 thread->thread_id, parser->in_fragmented_message, parser->fragment_opcode, conn->fd);

    /* Update frame statistics */
    ws_connection_increment_messages(conn);

    switch (frame->opcode) {
        case WS_OPCODE_TEXT:
            WS_DEBUG_LOG("Thread %u: Processing TEXT frame, fin=%d, payload_len=%lu on fd=%d", 
                         thread->thread_id, frame->fin, frame->payload_len, conn->fd);
            /* Text frame - handle fragmentation */
            return process_fragmented_frame(thread, conn, server, frame);
            
        case WS_OPCODE_BINARY:
            WS_DEBUG_LOG("Thread %u: Processing BINARY frame, fin=%d, payload_len=%lu on fd=%d", 
                         thread->thread_id, frame->fin, frame->payload_len, conn->fd);
            /* Binary frame - handle fragmentation */
            return process_fragmented_frame(thread, conn, server, frame);

        case WS_OPCODE_PING:
            /* Ping frame - respond with pong */
            WS_DEBUG_LOG("Thread %u: Received ping on fd=%d, sending pong", thread->thread_id, conn->fd);
            if (ws_send_pong_frame(conn, frame->payload, frame->payload_len) < 0) {
                WS_ERROR_LOG("Thread %u: Failed to send pong response on fd=%d", thread->thread_id, conn->fd);
                return -1;
            }
            break;

        case WS_OPCODE_PONG:
            /* Pong frame - just log it */
            WS_DEBUG_LOG("Thread %u: Received pong on fd=%d", thread->thread_id, conn->fd);
            if (server->callbacks.on_pong) {
                server->callbacks.on_pong(conn->fd, frame->payload, frame->payload_len, NULL);
            }
            break;

        case WS_OPCODE_CLOSE:
            /* Close frame */
            WS_DEBUG_LOG("Thread %u: Received close frame on fd=%d", thread->thread_id, conn->fd);
            
            /* RFC 6455 §5.5.1: a Close payload is either empty or >= 2 bytes
             * (2-byte code + optional reason). A 1-byte payload is malformed. */
            if (frame->payload_len == 1) {
                WS_ERROR_LOG("Thread %u: 1-byte close payload on fd=%d", thread->thread_id, conn->fd);
                return ws_fail_connection(conn, WS_CLOSE_PROTOCOL_ERROR);
            }

            /* No-status close (empty payload): echo a bare close, code 1005 is
             * never put on the wire. */
            uint16_t close_code = WS_CLOSE_NORMAL;
            const uint8_t *reason = NULL;
            size_t reason_len = 0;

            if (frame->payload_len >= 2) {
                close_code = (uint16_t)((frame->payload[0] << 8) | frame->payload[1]);
                reason = frame->payload + 2;
                reason_len = frame->payload_len - 2;

                /* §7.4.1: reject undefined/reserved close codes. */
                if (!ws_close_code_valid(close_code)) {
                    WS_ERROR_LOG("Thread %u: Invalid close code %u on fd=%d",
                                 thread->thread_id, close_code, conn->fd);
                    return ws_fail_connection(conn, WS_CLOSE_PROTOCOL_ERROR);
                }

                /* §7.1.5: the close reason MUST be valid UTF-8. */
                if (reason_len > 0 && !ws_utf8_valid(reason, reason_len)) {
                    WS_ERROR_LOG("Thread %u: Invalid UTF-8 in close reason on fd=%d",
                                 thread->thread_id, conn->fd);
                    return ws_fail_connection(conn, WS_CLOSE_INVALID_UTF8);
                }
            }

            ws_connection_set_state(conn, WS_STATE_CLOSING);

            /* Echo the peer's close code back (§7.1.4). Reason is not echoed —
             * a bare code is a compliant response. */
            if (frame->payload_len >= 2) {
                ws_send_close_frame(conn, close_code, "");
            } else {
                ws_send_close_frame(conn, 0, NULL); /* empty payload */
            }

            if (server->callbacks.on_close) {
                server->callbacks.on_close(conn->fd, close_code, "", NULL);
            }

            return WS_FRAME_CLOSE_REQUESTED; /* clean close handshake — not an error */

        case WS_OPCODE_CONTINUATION:
            /* Continuation frame - handle fragmentation */
            return process_continuation_frame(thread, conn, server, frame);

        default:
            /* Unknown opcode */
            WS_ERROR_LOG("Thread %u: Unknown WebSocket opcode %d on fd=%d", 
                         thread->thread_id, frame->opcode, conn->fd);
            return -1;
    }

    return 0;
}

/* ============================================================================
 * WebSocket Message Fragmentation Support
 * ============================================================================ */

/* Process a fragmented frame (first frame or single frame) */
int process_fragmented_frame(ws_event_thread_t *thread, ws_connection_t *conn, 
                           ws_server_internal_t *server, const ws_frame_t *frame) {
    ws_frame_parser_t *parser = &conn->frame_parser;
    
    if (parser->in_fragmented_message) {
        WS_ERROR_LOG("Thread %u: Received new frame while in fragmented message on fd=%d", 
                     thread->thread_id, conn->fd);
        return -1; /* Protocol error */
    }
    
    /* Check if this is a fragmented message (FIN = 0) */
    if (!frame->fin) {
        /* Start of fragmented message */
        WS_DEBUG_LOG("Thread %u: Starting fragmented message, opcode=%d on fd=%d", 
                     thread->thread_id, frame->opcode, conn->fd);
        
        parser->in_fragmented_message = true;
        parser->fragment_opcode = frame->opcode;
        parser->fragment_total_size = frame->payload_len;
        
        /* Allocate initial buffer (start with 64KB, expand as needed) */
        size_t initial_size = frame->payload_len > 65536 ? frame->payload_len * 2 : 65536;
        parser->fragment_buffer = malloc(initial_size);
        if (!parser->fragment_buffer) {
            WS_ERROR_LOG("Thread %u: Failed to allocate fragment buffer on fd=%d", 
                         thread->thread_id, conn->fd);
            parser->in_fragmented_message = false;
            return -1;
        }
        parser->fragment_buffer_size = initial_size;
        
        /* Copy first fragment (payload may be NULL for a zero-length frame). */
        if (frame->payload_len)
            memcpy(parser->fragment_buffer, frame->payload, frame->payload_len);
        
        WS_DEBUG_LOG("Thread %u: Stored first fragment of %zu bytes on fd=%d", 
                     thread->thread_id, frame->payload_len, conn->fd);
        return 0;
    } else {
        /* Complete single frame message */
        WS_DEBUG_LOG("Thread %u: Processing complete single frame, opcode=%d, payload_len=%lu on fd=%d", 
                     thread->thread_id, frame->opcode, frame->payload_len, conn->fd);
        
        if (frame->opcode == WS_OPCODE_TEXT) {
            /* RFC 6455 §5.6: text frames MUST carry valid UTF-8. */
            if (!ws_utf8_valid(frame->payload, frame->payload_len)) {
                WS_ERROR_LOG("Thread %u: Invalid UTF-8 in text frame on fd=%d",
                             thread->thread_id, conn->fd);
                return ws_fail_connection(conn, WS_CLOSE_INVALID_UTF8);
            }
        }

        if (frame->opcode == WS_OPCODE_TEXT && server->callbacks.on_text_message) {
            WS_DEBUG_LOG("Thread %u: Calling on_text_message callback with %lu bytes on fd=%d",
                         thread->thread_id, frame->payload_len, conn->fd);

            /* Ensure null termination for text frames */
            char *text_data = malloc(frame->payload_len + 1);
            if (!text_data) {
                WS_ERROR_LOG("Thread %u: Failed to allocate memory for text frame", thread->thread_id);
                return -1;
            }
            if (frame->payload_len)
                memcpy(text_data, frame->payload, frame->payload_len);
            text_data[frame->payload_len] = '\0';
            
            /* Log first 50 chars of message for debugging */
            WS_DEBUG_LOG("Thread %u: Text message content (first 50 chars): %.50s", thread->thread_id, text_data);
            
            server->callbacks.on_text_message(conn->fd, text_data, frame->payload_len, conn->user_data);
            free(text_data);
        } else if (frame->opcode == WS_OPCODE_BINARY && server->callbacks.on_binary_message) {
            WS_DEBUG_LOG("Thread %u: Calling on_binary_message callback with %lu bytes on fd=%d", 
                         thread->thread_id, frame->payload_len, conn->fd);
            server->callbacks.on_binary_message(conn->fd, frame->payload, frame->payload_len, conn->user_data);
        } else {
            WS_DEBUG_LOG("Thread %u: No callback registered for opcode=%d on fd=%d", 
                         thread->thread_id, frame->opcode, conn->fd);
        }
        return 0;
    }
}

/* Process a continuation frame */
int process_continuation_frame(ws_event_thread_t *thread, ws_connection_t *conn,
                             ws_server_internal_t *server, const ws_frame_t *frame) {
    ws_frame_parser_t *parser = &conn->frame_parser;
    
    if (!parser->in_fragmented_message) {
        WS_ERROR_LOG("Thread %u: Received continuation frame without fragmented message on fd=%d",
                     thread->thread_id, conn->fd);
        return -1; /* Protocol error */
    }

    /* pgforge SECURITY (H-6): bound the *cumulative* reassembled size. Each
     * single frame is already capped at max_message_size by ws_parse_frame, but
     * without this check an attacker can stream unbounded FIN=0 continuation
     * frames and grow fragment_buffer (1->2->4 MB ...) until the worker thread
     * OOMs — a memory-exhaustion DoS that takes down every connection on the
     * thread. Reject once the message would exceed max_message_size, per
     * RFC 6455 §7.4.1 (close code 1009). Overflow-safe: fragment_total_size is
     * an invariant <= max_message_size, so the subtraction never underflows. */
    size_t max_msg = server->config.max_message_size;
    if (frame->payload_len > max_msg - parser->fragment_total_size) {
        WS_ERROR_LOG("Thread %u: reassembled message exceeds max_message_size (%zu) on fd=%d",
                     thread->thread_id, max_msg, conn->fd);
        cleanup_fragmentation_state(conn);
        return ws_fail_connection(conn, WS_CLOSE_MESSAGE_TOO_BIG);
    }

    /* Check if buffer needs expansion */
    size_t needed_size = parser->fragment_total_size + frame->payload_len;
    if (needed_size > parser->fragment_buffer_size) {
        size_t new_size = needed_size * 2; /* Double the size for future fragments */
        uint8_t *new_buffer = realloc(parser->fragment_buffer, new_size);
        if (!new_buffer) {
            WS_ERROR_LOG("Thread %u: Failed to expand fragment buffer on fd=%d", 
                         thread->thread_id, conn->fd);
            cleanup_fragmentation_state(conn);
            return -1;
        }
        parser->fragment_buffer = new_buffer;
        parser->fragment_buffer_size = new_size;
        
        WS_DEBUG_LOG("Thread %u: Expanded fragment buffer to %zu bytes on fd=%d", 
                     thread->thread_id, new_size, conn->fd);
    }
    
    /* Append fragment data (payload may be NULL for a zero-length continuation). */
    if (frame->payload_len)
        memcpy(parser->fragment_buffer + parser->fragment_total_size,
               frame->payload, frame->payload_len);
    parser->fragment_total_size += frame->payload_len;
    
    WS_DEBUG_LOG("Thread %u: Appended fragment of %zu bytes (total: %zu) on fd=%d", 
                 thread->thread_id, frame->payload_len, parser->fragment_total_size, conn->fd);
    
    /* Check if this is the final fragment */
    if (frame->fin) {
        /* Complete message assembled */
        WS_DEBUG_LOG("Thread %u: Completed fragmented message of %zu bytes on fd=%d", 
                     thread->thread_id, parser->fragment_total_size, conn->fd);
        
        /* RFC 6455 §5.6: a reassembled text message MUST be valid UTF-8. */
        if (parser->fragment_opcode == WS_OPCODE_TEXT &&
            !ws_utf8_valid(parser->fragment_buffer, parser->fragment_total_size)) {
            WS_ERROR_LOG("Thread %u: Invalid UTF-8 in reassembled text on fd=%d",
                         thread->thread_id, conn->fd);
            cleanup_fragmentation_state(conn);
            return ws_fail_connection(conn, WS_CLOSE_INVALID_UTF8);
        }

        /* Deliver complete message to application */
        if (parser->fragment_opcode == WS_OPCODE_TEXT && server->callbacks.on_text_message) {
            /* Ensure null termination for text messages */
            char *text_data = malloc(parser->fragment_total_size + 1);
            if (text_data) {
                memcpy(text_data, parser->fragment_buffer, parser->fragment_total_size);
                text_data[parser->fragment_total_size] = '\0';
                
                server->callbacks.on_text_message(conn->fd, text_data, parser->fragment_total_size, conn->user_data);
                free(text_data);
            } else {
                WS_ERROR_LOG("Thread %u: Failed to allocate memory for complete text message", thread->thread_id);
            }
        } else if (parser->fragment_opcode == WS_OPCODE_BINARY && server->callbacks.on_binary_message) {
            server->callbacks.on_binary_message(conn->fd, parser->fragment_buffer, 
                                               parser->fragment_total_size, conn->user_data);
        }
        
        /* Clean up fragmentation state */
        cleanup_fragmentation_state(conn);
    }
    
    return 0;
}

/* Clean up fragmentation state */
void cleanup_fragmentation_state(ws_connection_t *conn) {
    ws_frame_parser_t *parser = &conn->frame_parser;
    
    if (parser->fragment_buffer) {
        free(parser->fragment_buffer);
        parser->fragment_buffer = NULL;
    }
    
    parser->in_fragmented_message = false;
    parser->fragment_opcode = 0;
    parser->fragment_buffer_size = 0;
    parser->fragment_total_size = 0;
}

int handle_connection_write(ws_event_thread_t *thread, int fd) {
    if (!thread || fd < 0) {
        return -1;
    }

    /* O(1) connection lookup using FD map */
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);

    if (!conn) {
        WS_ERROR_LOG("Thread %u: Connection fd=%d not found for write", thread->thread_id, fd);
        return -1;
    }

    /* A writable event during the TLS handshake means a WANT_WRITE step can now
     * proceed — drive it instead of the HTTP drain. */
    if (conn->state == WS_STATE_TLS_HANDSHAKE) {
        ws_server_internal_t *server = (ws_server_internal_t *)thread->server_instance;
        if (handle_tls_handshake(thread, conn, server) < 0) {
            close_connection(thread, fd);
            return -1;
        }
        return 0;
    }

    /* EPOLLOUT is armed only by the HTTP backpressure path; drain pending bytes
     * there. A -1 return means the write failed or a deferred close finished. */
    if (portico_conn_on_writable(thread, conn) < 0) {
        close_connection(thread, fd);
        return -1;
    }
    return 0;
}

void close_connection(ws_event_thread_t *thread, int fd) {
    if (!thread || fd < 0) {
        return;
    }
    /* O(1) connection lookup using FD map */
    ws_connection_t *conn = ws_find_connection_by_fd(thread, fd);

    /* Always release the fd at the OS layer: unregister from the FD map, drop it
     * from epoll, and close it. EPOLL_CTL_DEL/close on an fd we no longer track
     * just error harmlessly, so this is safe to reach with conn == NULL — and
     * NOT closing the fd in that case leaks it (the socket lingers in CLOSE_WAIT
     * and its epoll registration keeps firing). Double-close within a single
     * wakeup is prevented by the event loop's per-fd `closed` guard; once the fd
     * is EPOLL_CTL_DEL'd and closed here, no further events can reference it. */
    /* TLS: send a best-effort close_notify while the fd is still open (runs on
     * the event thread, so it's safe to touch the SSL object here). */
    if (conn && conn->ssl) ws_tls_conn_shutdown(conn->ssl);

    ws_unregister_fd(thread, fd);
    epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);

    /* Without a connection struct there is nothing more to tear down. */
    if (!conn) {
        return;
    }

    /* Update connection count */
    atomic_fetch_sub(&thread->active_connections, 1);

    WS_DEBUG_LOG("Thread %u: Closed connection fd=%d, remaining: %u/%u", 
                 thread->thread_id, fd, 
                 atomic_load(&thread->active_connections), thread->max_connections);

    /* Get server instance for callbacks */
    ws_server_internal_t *server = (ws_server_internal_t*)thread->server_instance;
    if (server && server->callbacks.on_disconnect) {
        /* Pass connection's user data to callback */
        void *user_data = conn ? conn->user_data : NULL;
        server->callbacks.on_disconnect(fd, user_data);
    }
    
    /* Clean up connection state if found */
    if (conn) {
        /* FIXED: Save pool_index before cleanup zeros it out */
        uint32_t pool_index = conn->pool_index;
        
        /* Clean up any fragmentation state */
        cleanup_fragmentation_state(conn);
        
        /* Remove from global hash table first */
        ws_server_internal_t *server = (ws_server_internal_t*)thread->server_instance;
        if (server && server->global_hash) {
            ws_connection_hash_remove(server->global_hash, fd);
        }
        
        /* Release the initial reference and check if connection can be freed */
        if (ws_connection_unref(conn)) {
            /* This was the last reference - safe to cleanup and reuse */
            ws_connection_cleanup(conn);
            
            /* Return connection to free stack using saved pool_index */
            if (thread->free_connection_count < thread->max_connections) {
                thread->free_connection_stack[thread->free_connection_count] = pool_index;
                thread->free_connection_count++;
            }
        } else {
            /* Other threads still have references - mark as closed but don't reuse yet */
            ws_connection_set_state(conn, WS_STATE_CLOSED);
            WS_DEBUG_LOG("Connection fd=%d has pending references, deferred cleanup", fd);
        }
    }
}
