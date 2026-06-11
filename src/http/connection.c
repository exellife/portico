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
#include "internal/ws_tls.h"
#include "http_internal.h"
#include "portico_aio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>   /* inet_pton — validate proxy-supplied client IPs (M-8) */

/* Defined in ws_connection_handler.c; used by the async file completion to close
 * a connection from outside the normal event-dispatch return path. */
extern void close_connection(ws_event_thread_t *thread, int fd);
static int process_http_buffer(ws_event_thread_t *thread, ws_connection_t *conn,
                               ws_server_internal_t *server);

/* Connection I/O chokepoints: go through the TLS layer when this connection is
 * encrypted, else raw non-blocking socket I/O. Both keep recv()/send() semantics
 * (>0 bytes, 0 = peer closed, -1 with errno EAGAIN on would-block), so the
 * backpressure / edge-triggered-drain logic below is identical for plain & TLS. */
static ssize_t conn_recv(ws_connection_t *conn, void *buf, size_t len) {
#ifdef PORTICO_TLS
    if (conn->ssl) return ws_tls_read(conn->ssl, buf, (int)len);
#endif
    return recv(conn->fd, buf, len, MSG_DONTWAIT);
}
static ssize_t conn_write_raw(ws_connection_t *conn, const void *buf, size_t len) {
#ifdef PORTICO_TLS
    if (conn->ssl) return ws_tls_write(conn->ssl, buf, (int)len);
#endif
    return send(conn->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
}

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
        ssize_t n = conn_recv(conn, conn->recv_buffer + conn->recv_buffer_used, space);
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
        ssize_t n = conn_write_raw(conn, conn->out_buffer + conn->out_sent,
                                   conn->out_used - conn->out_sent);
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
        ssize_t n = conn_write_raw(conn, (const char *)buf + off, len - off);
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

/* True iff `s` (length n) is a syntactically valid IPv4 or IPv6 address. */
static bool valid_ip(const char *s, size_t n) {
    if (n == 0 || n >= INET6_ADDRSTRLEN) return false;
    char buf[INET6_ADDRSTRLEN];
    memcpy(buf, s, n); buf[n] = '\0';
    struct in_addr a4; struct in6_addr a6;
    return inet_pton(AF_INET, buf, &a4) == 1 || inet_pton(AF_INET6, buf, &a6) == 1;
}

/* Fill req->client_ip: the proxy-supplied client when trust_proxy is set, else the
 * direct peer. From X-Forwarded-For we take the RIGHTMOST element — the address our
 * (single) trusted proxy appended is the real peer it saw; the leftmost elements
 * are client-supplied and forgeable (M-8: trusting them let a client spoof its IP,
 * bypassing the per-IP rate limiter and poisoning audit logs). The result must
 * parse as a real IP, else we ignore it. X-Real-IP (the proxy's single-valued
 * assertion) is honored first, also validated. Deployments behind >1 proxy should
 * front pgforge with the one that sets a trustworthy X-Real-IP. */
static void resolve_client_ip(const ws_connection_t *conn, const ws_server_internal_t *server,
                              portico_request_t *req) {
    if (server->config.trust_proxy) {
        size_t vlen = 0;
        const char *xr = portico_req_header(req, "X-Real-IP", &vlen);
        if (xr && valid_ip(xr, vlen)) {
            memcpy(req->client_ip, xr, vlen); req->client_ip[vlen] = '\0';
            return;
        }
        const char *xff = portico_req_header(req, "X-Forwarded-For", &vlen);
        if (xff && vlen) {
            size_t end = vlen;                                              /* rtrim OWS */
            while (end > 0 && (xff[end-1] == ' ' || xff[end-1] == '\t')) end--;
            size_t start = end;                                            /* last (rightmost) element */
            while (start > 0 && xff[start-1] != ',') start--;
            while (start < end && (xff[start] == ' ' || xff[start] == '\t')) start++;  /* ltrim OWS */
            size_t n = end - start;
            if (valid_ip(xff + start, n)) {
                memcpy(req->client_ip, xff + start, n); req->client_ip[n] = '\0';
                return;
            }
        }
    }
    ws_conn_peer_ip(conn, req->client_ip, sizeof req->client_ip);
}

/* ---- static file serving ------------------------------------------------- */

/* MVP cap: a file is served as ONE async read into one buffer handed to the send
 * path, so bound it well under the out-buffer cap. Larger files need streaming. */
#define PORTICO_FILE_MAX (1024 * 1024)

/* Content-Type from a path's extension; a small common set, octet-stream default. */
static const char *content_type_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    dot++;
    struct { const char *ext, *ct; } m[] = {
        {"html","text/html; charset=utf-8"}, {"htm","text/html; charset=utf-8"},
        {"css","text/css; charset=utf-8"},   {"js","application/javascript; charset=utf-8"},
        {"json","application/json"},          {"txt","text/plain; charset=utf-8"},
        {"svg","image/svg+xml"}, {"png","image/png"}, {"jpg","image/jpeg"},
        {"jpeg","image/jpeg"}, {"gif","image/gif"}, {"ico","image/x-icon"},
        {"webp","image/webp"}, {"woff2","font/woff2"}, {"wasm","application/wasm"},
        {"pdf","application/pdf"}, {"xml","application/xml"}, {NULL,NULL}
    };
    for (int i = 0; m[i].ext; i++) if (strcasecmp(dot, m[i].ext) == 0) return m[i].ct;
    return "application/octet-stream";
}

/* Percent-decode a URL path into out (NUL-terminated). '+' stays literal (it is
 * only space in query strings, not paths). Decoding first is what makes encoded
 * traversal like %2e%2e visible to the realpath check below. */
static void url_decode_path(const char *s, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        if (s[i] == '%' && i + 2 < n && isxdigit((unsigned char)s[i+1]) && isxdigit((unsigned char)s[i+2])) {
            char h[3] = { s[i+1], s[i+2], 0 };
            out[o++] = (char)strtol(h, NULL, 16);
            i += 2;
        } else {
            out[o++] = s[i];
        }
    }
    out[o] = '\0';
    *outlen = o;
}

int portico_res_file(portico_response_t *res, const portico_request_t *req, const char *docroot) {
    if (!res || !req || !docroot) { if (res) res->status = 500; return -1; }

    char decoded[PATH_MAX];
    size_t dlen = 0;
    url_decode_path(req->path, req->path_len, decoded, sizeof decoded, &dlen);
    /* Path must be absolute and contain no NUL (decoded %00 would truncate paths). */
    if (dlen == 0 || decoded[0] != '/' || memchr(decoded, '\0', dlen) != NULL) {
        res->status = 400; return -1;
    }

    /* Resolve docroot + path with realpath() (collapses .. and follows symlinks),
     * then require the result to stay within the real docroot — defeats both
     * ../ traversal and symlinks that point outside the tree. */
    char candidate[PATH_MAX], resolved[PATH_MAX], rootreal[PATH_MAX];
    if ((size_t)snprintf(candidate, sizeof candidate, "%s%s", docroot, decoded) >= sizeof candidate) {
        res->status = 414; return -1;
    }
    if (!realpath(docroot, rootreal))   { res->status = 500; return -1; }
    if (!realpath(candidate, resolved)) { res->status = 404; return -1; }
    size_t rl = strlen(rootreal);
    if (strncmp(resolved, rootreal, rl) != 0 || (resolved[rl] != '/' && resolved[rl] != '\0')) {
        res->status = 403; return -1;   /* escaped the docroot */
    }

    int fd = open(resolved, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { res->status = (errno == EACCES) ? 403 : 404; return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); res->status = 404; return -1; }
    if (st.st_size > PORTICO_FILE_MAX) { close(fd); res->status = 413; return -1; }

    res->is_file = 1;
    res->file_fd = fd;
    res->file_size = (long long)st.st_size;
    portico_res_header(res, "Content-Type", content_type_for(resolved));
    res->status = 200;
    return 0;
}

/* In-flight file transfer, carried from submit to the read completion. */
typedef struct {
    ws_event_thread_t *thread;
    ws_connection_t   *conn;
    uint32_t           generation;   /* conn's generation at submit (slot-reuse guard) */
    int                file_fd;
    uint8_t           *buf;
    size_t             size;
    int                status;
    int                keep_alive;
    char               headers[PORTICO_RES_HEADERS_CAP];
    size_t             headers_len;
} http_file_ctx_t;

/* Build + queue the file response from the bytes just read. Returns 0 to keep the
 * connection (keep-alive), 1 to close it (read error, send error, or no keep-alive). */
static int file_emit(ws_event_thread_t *thread, ws_connection_t *conn,
                     http_file_ctx_t *ctx, ssize_t nread) {
    if (nread < 0) {
        uint8_t *b; size_t n;
        if (portico_http_build_status(500, 0, &b, &n) == 0) {
            portico_conn_send(thread, conn, b, n); free(b);
        }
        return 1;
    }
    portico_response_t res;
    memset(&res, 0, sizeof res);
    res.status = ctx->status;
    memcpy(res.headers, ctx->headers, ctx->headers_len);
    res.headers_len = ctx->headers_len;
    res.body = (char *)ctx->buf;
    res.body_len = (size_t)nread;
    res.keep_alive = ctx->keep_alive;

    uint8_t *resp; size_t rlen;
    if (portico_http_build_response(&res, &resp, &rlen) != 0) return 1;
    int sent = portico_conn_send(thread, conn, resp, rlen);
    free(resp);
    if (sent != 0) return 1;
    return ctx->keep_alive ? 0 : 1;
}

/* aio read completion (runs on the owning event thread, in portico_aio_drain). */
static void file_read_complete(void *user, ssize_t nread) {
    http_file_ctx_t *ctx = user;
    ws_connection_t *conn = ctx->conn;

    /* Slot-reuse guard (mirrors the MPSC path): if the connection was closed and
     * its slot recycled while the read was in flight, the generation won't match —
     * drop the result and never touch the now-foreign connection. The connections
     * array is stable memory, so reading conn->generation is always safe. */
    if (conn->generation == ctx->generation && (int)conn->fd >= 0 &&
        conn->state == WS_STATE_HTTP) {
        conn->http_async_inflight = 0;
        int close_it = file_emit(ctx->thread, conn, ctx, nread);
        if (!close_it) {
            /* keep-alive: resume any pipelined requests buffered while parked. */
            ws_server_internal_t *server = (ws_server_internal_t *)ctx->thread->server_instance;
            if (process_http_buffer(ctx->thread, conn, server) < 0) close_it = 1;
        }
        if (close_it) {
            if (conn->out_used > conn->out_sent) conn->out_close_when_drained = 1;
            else close_connection(ctx->thread, (int)conn->fd);
        }
    }

    close(ctx->file_fd);
    free(ctx->buf);
    free(ctx);
}

/* Begin serving res->file_fd on `conn`: capture state, consume this request, and
 * submit the async read (parking the connection). Falls back to a synchronous read
 * if async I/O is unavailable or the submit is refused. Returns -1 to close now,
 * 0 to keep the connection parked / deferred-closing, 1 to continue the request
 * loop (a synchronous keep-alive response was sent). */
static int http_serve_file(ws_event_thread_t *thread, ws_connection_t *conn,
                           portico_response_t *res, size_t consumed) {
    size_t size = (size_t)res->file_size;
    uint8_t *buf = malloc(size ? size : 1);
    http_file_ctx_t *ctx = buf ? malloc(sizeof *ctx) : NULL;
    if (!buf || !ctx) {
        free(buf); close(res->file_fd);
        return http_error_close(thread, conn, 500);
    }
    ctx->thread = thread; ctx->conn = conn; ctx->generation = conn->generation;
    ctx->file_fd = res->file_fd; ctx->buf = buf; ctx->size = size;
    ctx->status = res->status; ctx->keep_alive = res->keep_alive;
    memcpy(ctx->headers, res->headers, res->headers_len);
    ctx->headers_len = res->headers_len;

    /* Consume this request now; any pipelined bytes stay buffered but are not
     * processed until the response completes (the parked flag preserves order). */
    if (consumed < conn->recv_buffer_used) {
        memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->recv_buffer_used - consumed);
        conn->recv_buffer_used -= consumed;
    } else {
        conn->recv_buffer_used = 0;
    }

    if (thread->aio) {
        conn->http_async_inflight = 1;
        if (portico_aio_pread(thread->aio, ctx->file_fd, buf, size, 0,
                              file_read_complete, ctx) == 0)
            return 0;   /* parked — completion responds + resumes */
        conn->http_async_inflight = 0;   /* submit refused → fall through */
    }

    /* Synchronous fallback (no aio, or submit refused): read inline, respond, and
     * tell the caller's loop whether to continue (keep-alive) or close. */
    ssize_t n;
    do { n = pread(ctx->file_fd, buf, size, 0); } while (n < 0 && errno == EINTR);
    int close_it = file_emit(thread, conn, ctx, n);
    close(ctx->file_fd); free(ctx->buf); free(ctx);
    if (close_it) return http_finish_close(conn);   /* 0 deferred, -1 now */
    return 1;                                        /* keep-alive: continue the loop */
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

        resolve_client_ip(conn, server, &req);   /* before dispatch */

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
            if (res.is_file) { close(res.file_fd); res.is_file = 0; }  /* don't leak the fd */
        } else if (res.is_file) {
            /* Static file response: serve it asynchronously (read off-thread). This
             * consumes the request and parks the connection, or — falling back —
             * sends synchronously. fr: -1 close now, 0 parked/deferred, 1 continue. */
            int fr = http_serve_file(thread, conn, &res, (size_t)total);
            if (fr <= 0) return fr;
            continue;
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
    /* A static-file read is in flight: drain the socket into recv_buffer (so
     * pipelined bytes aren't stranded by edge-triggered epoll), but don't process
     * requests until the completion fires — it resumes processing in order. */
    if (conn->http_async_inflight) return 0;
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
        int rc = ws_process_handshake(conn, reqstr, &server->callbacks);
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
