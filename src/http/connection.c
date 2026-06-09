/* portico — HTTP connection handling, integrated into the wslib event loop.
 *
 * The first read of every connection lands in portico_initial_dispatch(): if it
 * looks like a WebSocket handshake we hand off to the existing WS path, otherwise
 * the connection becomes WS_STATE_HTTP and requests are served here (keep-alive,
 * pipelining, body framing via Content-Length). Request bytes accumulate in the
 * connection's growable recv_buffer; response handlers come from
 * server->callbacks.on_http_request. */
#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "http_internal.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>

/* Drain the socket into conn->recv_buffer (edge-triggered → read to EAGAIN),
 * growing on demand. Returns 0 on success, -1 if the peer closed or errored. */
static int read_into_recv(ws_connection_t *conn) {
    const size_t hard_max = PORTICO_MAX_HEADER_SIZE + PORTICO_MAX_BODY;
    for (;;) {
        if (conn->recv_buffer_used == conn->recv_buffer_capacity) {
            if (conn->recv_buffer_capacity >= hard_max) return 0;  /* let parser 413/400 */
            /* Floor the growth: a 0 capacity (prior alloc failure) must not make
             * the doubling stall at 0. */
            size_t nc = conn->recv_buffer_capacity ? conn->recv_buffer_capacity * 2 : 16384;
            if (nc > hard_max) nc = hard_max;
            uint8_t *nb = realloc(conn->recv_buffer, nc);
            if (!nb) return -1;
            conn->recv_buffer = nb;
            conn->recv_buffer_capacity = nc;
        }
        size_t space = conn->recv_buffer_capacity - conn->recv_buffer_used;
        ssize_t n = recv(conn->fd, conn->recv_buffer + conn->recv_buffer_used, space, MSG_DONTWAIT);
        if (n == 0) return -1;
        if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
        conn->recv_buffer_used += (size_t)n;
        ws_connection_add_bytes_received(conn, (uint64_t)n);
    }
}

static int ci_contains(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (strncasecmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

/* Process all complete HTTP requests currently buffered. Returns 0 to keep the
 * connection open (awaiting more), or -1 to close it. */
static int process_http_buffer(ws_connection_t *conn, ws_server_internal_t *server) {
    for (;;) {
        if (conn->recv_buffer_used == 0) return 0;

        portico_request_t req;
        int total = portico_http_parse((const char *)conn->recv_buffer,
                                       conn->recv_buffer_used, &req);
        if (total == 0) {
            /* Incomplete: only reject if the HEADERS themselves are oversized.
             * (A large-but-incomplete body is fine — its size is already capped
             * in portico_http_parse, which 413s anything over PORTICO_MAX_BODY.) */
            int headers_done = memmem(conn->recv_buffer, conn->recv_buffer_used,
                                      "\r\n\r\n", 4) != NULL;
            if (!headers_done && conn->recv_buffer_used > PORTICO_MAX_HEADER_SIZE) {
                portico_http_send_status(conn->fd, 431, 0);
                return -1;
            }
            return 0;   /* await more header or body bytes */
        }
        if (total == -1) { portico_http_send_status(conn->fd, 400, 0); return -1; }
        if (total == -2) { portico_http_send_status(conn->fd, 413, 0); return -1; }
        if (total == -3) { portico_http_send_status(conn->fd, 501, 0); return -1; }

        /* Dispatch to the application handler. */
        portico_response_t res;
        memset(&res, 0, sizeof res);
        res.keep_alive = req.keep_alive;

        int hrc = -1;
        if (server->callbacks.on_http_request)
            hrc = server->callbacks.on_http_request(&req, &res, server->callbacks.http_user_data);

        if (!server->callbacks.on_http_request) {
            res.status = 501;  /* server has no HTTP handler */
        } else if (hrc != 0) {
            res.status = 500;  /* handler signalled failure */
            free(res.body); res.body = NULL; res.body_len = 0;
        }

        int sent = portico_http_send_response(conn->fd, &res);
        free(res.body);
        if (sent != 0) return -1;

        /* Consume this request; keep any pipelined bytes. */
        size_t consumed = (size_t)total;
        if (consumed < conn->recv_buffer_used) {
            memmove(conn->recv_buffer, conn->recv_buffer + consumed,
                    conn->recv_buffer_used - consumed);
            conn->recv_buffer_used -= consumed;
        } else {
            conn->recv_buffer_used = 0;
        }

        if (!req.keep_alive) return -1;   /* close after responding */
        /* else loop: serve the next pipelined request, or return 0 when drained */
    }
}

int portico_http_event(ws_event_thread_t *thread, ws_connection_t *conn,
                       ws_server_internal_t *server) {
    (void)thread;
    if (read_into_recv(conn) < 0) return -1;
    return process_http_buffer(conn, server);
}

int portico_initial_dispatch(ws_event_thread_t *thread, ws_connection_t *conn,
                             ws_server_internal_t *server) {
    (void)thread;
    if (read_into_recv(conn) < 0) return -1;

    /* Need the full header block before we can classify the connection. */
    void *term = memmem(conn->recv_buffer, conn->recv_buffer_used, "\r\n\r\n", 4);
    if (!term) {
        if (conn->recv_buffer_used > PORTICO_MAX_HEADER_SIZE) {
            portico_http_send_status(conn->fd, 431, 0);
            return -1;
        }
        return 0;  /* wait for more */
    }
    size_t headers_len = (size_t)((char *)term - (char *)conn->recv_buffer) + 4;

    /* A WebSocket handshake is the only request carrying Sec-WebSocket-Key. */
    if (ci_contains((const char *)conn->recv_buffer, headers_len, "sec-websocket-key")) {
        char *reqstr = malloc(headers_len + 1);
        if (!reqstr) return -1;
        memcpy(reqstr, conn->recv_buffer, headers_len);
        reqstr[headers_len] = '\0';
        int rc = ws_process_handshake(conn->fd, reqstr, &server->callbacks);
        free(reqstr);
        if (rc != 0) return -1;

        ws_connection_set_state(conn, WS_STATE_OPEN);
        if (server->callbacks.on_connect)
            server->callbacks.on_connect(conn->fd, NULL);

        /* Preserve any bytes the client pipelined after the handshake (rare). */
        if (headers_len < conn->recv_buffer_used) {
            memmove(conn->recv_buffer, conn->recv_buffer + headers_len,
                    conn->recv_buffer_used - headers_len);
            conn->recv_buffer_used -= headers_len;
        } else {
            conn->recv_buffer_used = 0;
        }
        return 0;
    }

    /* Plain HTTP. */
    if (!server->callbacks.on_http_request) {
        portico_http_send_status(conn->fd, 501, 0);
        return -1;
    }
    ws_connection_set_state(conn, WS_STATE_HTTP);
    return process_http_buffer(conn, server);
}
