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
#include <sys/epoll.h>
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

/* ---- non-blocking outbound writes (backpressure via EPOLLOUT) ------------- */

#define PORTICO_OUT_MAX (4 * 1024 * 1024)   /* cap on buffered unsent output */

/* Arm (want_out=1) or disarm EPOLLOUT for fd, keeping edge-triggered EPOLLIN. */
static int conn_set_epollout(ws_event_thread_t *thread, int fd, int want_out) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | EPOLLET | (want_out ? (uint32_t)EPOLLOUT : 0u);
    ev.data.fd = fd;
    return epoll_ctl(thread->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

/* Push as many queued bytes as the socket will take right now. Returns 0 on
 * progress/would-block, -1 on a fatal socket error. */
static int conn_out_drain(ws_connection_t *conn) {
    while (conn->out_sent < conn->out_used) {
        ssize_t n = send(conn->fd, conn->out_buffer + conn->out_sent,
                         conn->out_used - conn->out_sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) { conn->out_sent += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    conn->out_used = conn->out_sent = 0;   /* fully drained */
    return 0;
}

/* Append len bytes to the pending-out buffer (growing up to the cap, reclaiming
 * any already-sent prefix first). Returns 0 ok, -1 if the cap would overflow. */
static int conn_out_append(ws_connection_t *conn, const void *buf, size_t len) {
    if (conn->out_sent > 0) {
        size_t rem = conn->out_used - conn->out_sent;
        if (rem) memmove(conn->out_buffer, conn->out_buffer + conn->out_sent, rem);
        conn->out_used = rem;
        conn->out_sent = 0;
    }
    if (conn->out_used + len > PORTICO_OUT_MAX) return -1;
    if (conn->out_used + len > conn->out_capacity) {
        size_t nc = conn->out_capacity ? conn->out_capacity : 8192;
        while (nc < conn->out_used + len) nc *= 2;
        if (nc > PORTICO_OUT_MAX) nc = PORTICO_OUT_MAX;
        uint8_t *nb = realloc(conn->out_buffer, nc);
        if (!nb) return -1;
        conn->out_buffer = nb;
        conn->out_capacity = nc;
    }
    memcpy(conn->out_buffer + conn->out_used, buf, len);
    conn->out_used += len;
    return 0;
}

/* Queue `buf` for sending on `conn`. Sends what it can immediately and buffers
 * the rest (arming EPOLLOUT) rather than blocking the event thread on a slow
 * reader. Returns 0 ok, -1 on fatal error / backpressure overflow. Shared by the
 * HTTP response path and the WS frame send path (a connection is HTTP xor WS, so
 * they never contend for the same out_buffer). */
int portico_conn_send(ws_event_thread_t *thread, ws_connection_t *conn,
                      const void *buf, size_t len) {
    /* Preserve ordering: if a backlog exists, everything queues behind it. */
    if (conn->out_used > conn->out_sent)
        return conn_out_append(conn, buf, len);

    size_t off = 0;
    while (off < len) {
        ssize_t n = send(conn->fd, (const char *)buf + off, len - off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (conn_out_append(conn, (const char *)buf + off, len - off) != 0) return -1;
            return conn_set_epollout(thread, conn->fd, 1);
        }
        return -1;   /* EPIPE / other */
    }
    return 0;   /* fully sent inline */
}

/* Send a fully-built response buffer, taking ownership (frees it). */
static int http_send_owned(ws_event_thread_t *thread, ws_connection_t *conn,
                           uint8_t *buf, size_t len) {
    int rc = portico_conn_send(thread, conn, buf, len);
    free(buf);
    return rc;
}

/* Queue a status-only error reply. Returns 0 ok, -1 fatal. */
static int http_reply_status(ws_event_thread_t *thread, ws_connection_t *conn, int status) {
    uint8_t *b; size_t n;
    if (portico_http_build_status(status, 0, &b, &n) != 0) return -1;
    return http_send_owned(thread, conn, b, n);
}

/* After queuing a final response, choose the return code: defer the close until
 * EPOLLOUT drains any buffered bytes, otherwise close immediately. */
static int http_finish_close(ws_connection_t *conn) {
    if (conn->out_used > conn->out_sent) { conn->out_close_when_drained = 1; return 0; }
    return -1;
}

/* Queue an error status then arrange to close. Always returns a close code
 * (0 = deferred until drained, -1 = now). */
static int http_error_close(ws_event_thread_t *thread, ws_connection_t *conn, int status) {
    if (http_reply_status(thread, conn, status) < 0) return -1;
    return http_finish_close(conn);
}

/* EPOLLOUT handler: drain the pending-out buffer; disarm EPOLLOUT when empty
 * and finish a deferred close. Returns 0 to keep the connection, -1 to close.
 * Generic over HTTP and WS — it just drains conn->out_buffer. */
int portico_conn_on_writable(ws_event_thread_t *thread, ws_connection_t *conn) {
    if (conn_out_drain(conn) < 0) return -1;          /* fatal write error */
    if (conn->out_used > conn->out_sent) return 0;    /* still backlogged, stay armed */
    conn_set_epollout(thread, conn->fd, 0);           /* drained: disarm EPOLLOUT */
    return conn->out_close_when_drained ? -1 : 0;     /* finish deferred close */
}

/* Process all complete HTTP requests currently buffered. Returns 0 to keep the
 * connection open (awaiting more / draining output), or -1 to close it. */
static int process_http_buffer(ws_event_thread_t *thread, ws_connection_t *conn,
                               ws_server_internal_t *server) {
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
            if (!headers_done && conn->recv_buffer_used > PORTICO_MAX_HEADER_SIZE)
                return http_error_close(thread, conn, 431);
            return 0;   /* await more header or body bytes */
        }
        if (total == -1) return http_error_close(thread, conn, 400);
        if (total == -2) return http_error_close(thread, conn, 413);
        if (total == -3) return http_error_close(thread, conn, 501);

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

        uint8_t *resp; size_t resp_len;
        int built = portico_http_build_response(&res, &resp, &resp_len);
        free(res.body);
        if (built != 0) return -1;
        int sent = http_send_owned(thread, conn, resp, resp_len);
        if (sent != 0) return -1;   /* fatal write / backpressure overflow */

        /* Consume this request; keep any pipelined bytes. */
        size_t consumed = (size_t)total;
        if (consumed < conn->recv_buffer_used) {
            memmove(conn->recv_buffer, conn->recv_buffer + consumed,
                    conn->recv_buffer_used - consumed);
            conn->recv_buffer_used -= consumed;
        } else {
            conn->recv_buffer_used = 0;
        }

        if (!req.keep_alive) return http_finish_close(conn);  /* close after responding */
        /* else loop: serve the next pipelined request, or return 0 when drained */
    }
}

int portico_http_event(ws_event_thread_t *thread, ws_connection_t *conn,
                       ws_server_internal_t *server) {
    /* Once we're draining a final response, ignore further input — the EPOLLOUT
     * handler will close the connection when the buffer empties. */
    if (conn->out_close_when_drained) return 0;
    if (read_into_recv(conn) < 0) return -1;
    return process_http_buffer(thread, conn, server);
}

int portico_initial_dispatch(ws_event_thread_t *thread, ws_connection_t *conn,
                             ws_server_internal_t *server) {
    if (read_into_recv(conn) < 0) return -1;

    /* Need the full header block before we can classify the connection. */
    void *term = memmem(conn->recv_buffer, conn->recv_buffer_used, "\r\n\r\n", 4);
    if (!term) {
        if (conn->recv_buffer_used > PORTICO_MAX_HEADER_SIZE)
            return http_error_close(thread, conn, 431);
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
    if (!server->callbacks.on_http_request)
        return http_error_close(thread, conn, 501);
    ws_connection_set_state(conn, WS_STATE_HTTP);
    return process_http_buffer(thread, conn, server);
}
