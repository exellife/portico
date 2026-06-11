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
#include <time.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>   /* inet_pton — validate proxy-supplied client IPs (M-8) */

/* Defined in ws_connection_handler.c; used by the async file completion to close
 * a connection from outside the normal event-dispatch return path. */
extern void close_connection(ws_event_thread_t *thread, int fd);
static int process_http_buffer(ws_event_thread_t *thread, ws_connection_t *conn,
                               ws_server_internal_t *server);

/* Streamed (chunked) file response context; the machinery is in the static-file
 * section below. Declared up here so the writable/cleanup hooks can reference it. */
typedef struct http_stream {
    ws_event_thread_t *thread;
    ws_connection_t   *conn;
    uint32_t           generation;   /* conn's generation at submit (slot-reuse guard) */
    int                file_fd;
    uint8_t           *buf;          /* one chunk (PORTICO_STREAM_CHUNK) */
    long long          offset;       /* next file offset to read */
    long long          end;          /* one past the last byte to serve (start+length) */
    int                keep_alive;
    int                reading;       /* an aio read is in flight for this stream */
} http_stream_t;
static void stream_free(http_stream_t *s);
static int  stream_advance(http_stream_t *s);
static void stream_chunk_complete(void *user, ssize_t nread);

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
    /* Mid-stream and the socket just drained → pull the next file chunk. */
    if (conn->file_stream)
        return stream_advance((http_stream_t *)conn->file_stream);
    return conn->out_close_when_drained ? -1 : 0;     /* finish deferred close */
}

/* Abort an in-progress streamed file response (called from ws_connection_cleanup
 * before the connection slot is wiped). If a read is in flight, its completion
 * owns the context and will free it (its slot-reuse guard now fails); otherwise
 * free it here. Either way the fd/buffer are released exactly once. */
void portico_http_stream_abort(ws_connection_t *conn) {
    http_stream_t *s = (http_stream_t *)conn->file_stream;
    if (!s) return;
    conn->file_stream = NULL;
    if (!s->reading) stream_free(s);   /* no in-flight read: free now */
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

/* Files larger than this are STREAMED (chunked read↔send) instead of read whole
 * into one buffer; at or below it, the simple single-read path is used. */
#define PORTICO_STREAM_CHUNK  (256 * 1024)
/* Single-read path cap (small files, or the no-aio fallback): bounded well under
 * the out-buffer cap. Bigger files require the async streaming path. */
#define PORTICO_SINGLE_MAX    (4 * 1024 * 1024)
/* Sanity ceiling on any served file. */
#define PORTICO_FILE_MAX      (2LL * 1024 * 1024 * 1024)

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

/* RFC 1123 HTTP-date, English/locale-independent (strftime's %a/%b are localized). */
static void http_date(time_t t, char *out, size_t cap) {
    static const char *D[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char *M[] = {"Jan","Feb","Mar","Apr","May","Jun",
                              "Jul","Aug","Sep","Oct","Nov","Dec"};
    struct tm tm; gmtime_r(&t, &tm);
    snprintf(out, cap, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             D[tm.tm_wday], tm.tm_mday, M[tm.tm_mon], tm.tm_year + 1900,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* Parse an RFC 1123 HTTP-date; (time_t)-1 on failure. */
static time_t parse_http_date(const char *s) {
    struct tm tm; memset(&tm, 0, sizeof tm);
    if (!strptime(s, "%a, %d %b %Y %H:%M:%S GMT", &tm)) return (time_t)-1;
    return timegm(&tm);
}

/* Strong validator: "<mtime_sec>-<mtime_nsec>-<size>" (quoted). */
static void file_etag(const struct stat *st, char *out, size_t cap) {
    snprintf(out, cap, "\"%llx-%llx-%llx\"",
             (unsigned long long)st->st_mtim.tv_sec,
             (unsigned long long)st->st_mtim.tv_nsec,
             (unsigned long long)st->st_size);
}

/* True if an If-None-Match header `hdr` matches `etag` ("*" matches anything;
 * comma list; a leading weak "W/" marker is ignored for the comparison). */
static int etag_matches(const char *hdr, const char *etag) {
    if (strchr(hdr, '*')) return 1;
    for (const char *p = hdr; *p; ) {
        while (*p == ' ' || *p == ',' || *p == '\t') p++;
        if (p[0] == 'W' && p[1] == '/') p += 2;
        if (*p && strncmp(p, etag, strlen(etag)) == 0) return 1;
        while (*p && *p != ',') p++;
    }
    return 0;
}

/* Parse a single "bytes=" range against `size`. Returns 0 satisfiable (sets
 * start and len), 1 unsatisfiable (416), or -1 ignore-and-serve-full (200). */
static int parse_range(const char *v, long long size, long long *start, long long *len) {
    if (strncmp(v, "bytes=", 6) != 0) return -1;
    v += 6;
    if (strchr(v, ',')) return -1;                /* multiple ranges → serve full */
    const char *dash = strchr(v, '-');
    if (!dash) return -1;
    long long s, e; char *end;
    if (dash == v) {                              /* "-N": final N bytes */
        long long suf = strtoll(v + 1, &end, 10);
        if (end == v + 1 || *end != '\0' || suf <= 0) return -1;
        if (suf > size) suf = size;
        s = size - suf; e = size - 1;
    } else {
        s = strtoll(v, &end, 10);
        if (end != dash || s < 0) return -1;
        if (dash[1] == '\0') {
            e = size - 1;
        } else {
            e = strtoll(dash + 1, &end, 10);
            if (*end != '\0' || e < 0) return -1;
            if (e >= size) e = size - 1;
        }
    }
    if (size == 0 || s >= size || s > e) return 1; /* unsatisfiable → 416 */
    *start = s; *len = e - s + 1;
    return 0;
}

/* Copy a request header value into a NUL-terminated buffer; 1 if present. */
static int req_header_copy(const portico_request_t *req, const char *name, char *out, size_t cap) {
    size_t vlen = 0;
    const char *v = portico_req_header(req, name, &vlen);
    if (!v || vlen == 0 || vlen >= cap) { out[0] = '\0'; return 0; }
    memcpy(out, v, vlen); out[vlen] = '\0';
    return 1;
}

int portico_res_static(portico_response_t *res, const portico_request_t *req,
                       const portico_static_opts_t *opts) {
    if (!res || !req || !opts || !opts->docroot) { if (res) res->status = 500; return -1; }
    const char *docroot = opts->docroot;
    const char *index   = opts->index ? opts->index : "index.html";   /* "" disables */

    /* URL-prefix stripping: serve this docroot mounted under opts->url_prefix
     * (e.g. "/static"). The prefix must be a whole leading path segment; the mount
     * root (path == prefix) maps to "/". A no-prefix path passes through. */
    const char *upath = req->path;
    size_t ulen = req->path_len;
    if (opts->url_prefix && *opts->url_prefix) {
        size_t pl = strlen(opts->url_prefix);
        if (ulen < pl || memcmp(upath, opts->url_prefix, pl) != 0) { res->status = 404; return -1; }
        upath += pl; ulen -= pl;
        if (ulen == 0) { upath = "/"; ulen = 1; }      /* mount root → directory index */
        else if (upath[0] != '/') { res->status = 404; return -1; }   /* not a full segment */
    }

    char decoded[PATH_MAX];
    size_t dlen = 0;
    url_decode_path(upath, ulen, decoded, sizeof decoded, &dlen);
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
    if (fstat(fd, &st) != 0) { close(fd); res->status = 404; return -1; }

    /* Directory → serve its index file (no directory listing). Re-resolve through
     * realpath so the index can't be a symlink escaping the docroot either. */
    if (S_ISDIR(st.st_mode)) {
        close(fd);
        /* No directory listing: serve the index file; if it's absent/unreadable,
         * 403 (the convention nginx/Apache use, not a 404 that maps the tree). */
        if (!*index) { res->status = 403; return -1; }
        char ipath[PATH_MAX];
        if ((size_t)snprintf(ipath, sizeof ipath, "%s/%s", resolved, index) >= sizeof ipath) {
            res->status = 414; return -1;
        }
        if (!realpath(ipath, resolved) ||
            strncmp(resolved, rootreal, rl) != 0 || (resolved[rl] != '/' && resolved[rl] != '\0')) {
            res->status = 403; return -1;
        }
        fd = open(resolved, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { res->status = 403; return -1; }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); res->status = 403; return -1; }
    }
    if (!S_ISREG(st.st_mode)) { close(fd); res->status = 404; return -1; }
    if (st.st_size > PORTICO_FILE_MAX) { close(fd); res->status = 413; return -1; }

    /* Validators for conditional + range requests. */
    char etag[64], lastmod[40], hbuf[256];
    file_etag(&st, etag, sizeof etag);
    http_date(st.st_mtim.tv_sec, lastmod, sizeof lastmod);
    long long total = (long long)st.st_size;

    /* Conditional GET (RFC 7232): If-None-Match wins over If-Modified-Since; a
     * match → 304 Not Modified (no body — the client's cache is current). */
    int not_modified = 0;
    if (req_header_copy(req, "If-None-Match", hbuf, sizeof hbuf)) {
        if (etag_matches(hbuf, etag)) not_modified = 1;
    } else if (req_header_copy(req, "If-Modified-Since", hbuf, sizeof hbuf)) {
        time_t ims = parse_http_date(hbuf);
        if (ims != (time_t)-1 && st.st_mtim.tv_sec <= ims) not_modified = 1;
    }
    if (not_modified) {
        close(fd);
        portico_res_header(res, "ETag", etag);
        portico_res_header(res, "Last-Modified", lastmod);
        res->status = 304;
        res->is_file = 0;
        return 0;
    }

    /* Range (RFC 7233): honor it unless an If-Range validator shows the client's
     * cached partial is stale, in which case serve the full 200 instead. */
    long long start = 0, length = total;
    int is_range = 0;
    if (req_header_copy(req, "Range", hbuf, sizeof hbuf)) {
        int honor = 1;
        char ir[256];
        if (req_header_copy(req, "If-Range", ir, sizeof ir)) {
            if (ir[0] == '"' || (ir[0] == 'W' && ir[1] == '/'))
                honor = (strstr(ir, etag) != NULL);          /* etag validator */
            else { time_t d = parse_http_date(ir); honor = (d != (time_t)-1 && st.st_mtim.tv_sec <= d); }
        }
        if (honor) {
            long long rs, rl;
            int rr = parse_range(hbuf, total, &rs, &rl);
            if (rr == 0) { start = rs; length = rl; is_range = 1; }
            else if (rr == 1) {                              /* 416 Range Not Satisfiable */
                close(fd);
                char cr[64]; snprintf(cr, sizeof cr, "bytes */%lld", total);
                portico_res_header(res, "Content-Range", cr);
                portico_res_header(res, "Accept-Ranges", "bytes");
                res->status = 416; res->is_file = 0;
                return -1;
            }
            /* rr == -1: malformed/multi range → ignore, serve full */
        }
    }

    portico_res_header(res, "Content-Type", content_type_for(resolved));
    portico_res_header(res, "Accept-Ranges", "bytes");
    portico_res_header(res, "ETag", etag);
    portico_res_header(res, "Last-Modified", lastmod);
    if (is_range) {
        char cr[80];
        snprintf(cr, sizeof cr, "bytes %lld-%lld/%lld", start, start + length - 1, total);
        portico_res_header(res, "Content-Range", cr);
        res->status = 206;     /* Partial Content */
    } else {
        res->status = 200;
    }
    res->is_file = 1;
    res->file_fd = fd;
    res->file_offset = start;
    res->file_size = length;   /* bytes to serve (range length, or full size) */
    return 0;
}

int portico_res_file(portico_response_t *res, const portico_request_t *req, const char *docroot) {
    portico_static_opts_t opts = { .docroot = docroot, .url_prefix = NULL, .index = NULL };
    return portico_res_static(res, req, &opts);
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

/* ---- streamed (chunked) file response, for files over PORTICO_STREAM_CHUNK ----
 *
 * The body is sent chunk by chunk: read a chunk off-thread → send it → when the
 * socket has drained, read the next. Two-sided backpressure: a read in flight is
 * the disk wait; out_buffer non-empty is the socket wait (EPOLLOUT resumes us).
 * Memory stays bounded to one chunk + the out-buffer regardless of file size.
 *
 * Ownership of the heap stream context `s` (also referenced by conn->file_stream):
 *  - while s->reading, the in-flight aio read owns s; its completion frees it.
 *  - otherwise the function that detaches (clears conn->file_stream) frees s.
 *  - on a mid-stream connection close, portico_http_stream_abort handles it. */
static void stream_free(http_stream_t *s) {
    close(s->file_fd);
    free(s->buf);
    free(s);
}

/* Truncate-and-close: a read or send failed mid-stream (headers already went out,
 * so the status can't change). Detach + free s; the caller closes the connection. */
static int stream_fail(http_stream_t *s) {
    s->conn->file_stream = NULL;
    s->conn->http_async_inflight = 0;
    stream_free(s);
    return -1;
}

/* All bytes sent/queued. Detach + free s, then resume (keep-alive → pipelined,
 * else arrange close). Returns 0 to keep the connection, -1 to close it now. */
static int stream_finish(http_stream_t *s) {
    ws_event_thread_t *thread = s->thread;
    ws_connection_t  *conn = s->conn;
    int keep_alive = s->keep_alive;
    conn->file_stream = NULL;
    conn->http_async_inflight = 0;
    stream_free(s);
    if (keep_alive) {
        ws_server_internal_t *server = (ws_server_internal_t *)thread->server_instance;
        return process_http_buffer(thread, conn, server);
    }
    if (conn->out_used > conn->out_sent) { conn->out_close_when_drained = 1; return 0; }
    return -1;
}

/* Pump the stream: submit the next chunk read, or (socket backed up) wait for
 * EPOLLOUT, or finish. Returns 0 to keep the connection, -1 to close it now.
 * Never closes directly — the caller (completion or EPOLLOUT handler) does. */
static int stream_advance(http_stream_t *s) {
    ws_connection_t *conn = s->conn;
    if (s->reading) return 0;                              /* a read is already in flight */
    for (;;) {
        if (conn->out_used > conn->out_sent) return 0;     /* socket backed up: wait EPOLLOUT */
        if (s->offset >= s->end) return stream_finish(s);  /* done */

        size_t want = (size_t)(s->end - s->offset);
        if (want > PORTICO_STREAM_CHUNK) want = PORTICO_STREAM_CHUNK;

        if (s->thread->aio) {
            s->reading = 1;
            if (portico_aio_pread(s->thread->aio, s->file_fd, s->buf, want, s->offset,
                                  stream_chunk_complete, s) == 0)
                return 0;                                  /* in flight — completion resumes */
            s->reading = 0;                                /* submit refused → read inline below */
        }
        ssize_t n;
        do { n = pread(s->file_fd, s->buf, want, s->offset); } while (n < 0 && errno == EINTR);
        if (n <= 0) return stream_fail(s);
        if (portico_conn_send(s->thread, conn, s->buf, (size_t)n) != 0) return stream_fail(s);
        s->offset += n;
        /* loop: try the next chunk (or hit the EPOLLOUT wait at the top) */
    }
}

/* aio chunk-read completion (runs on the owning event thread, in portico_aio_drain). */
static void stream_chunk_complete(void *user, ssize_t nread) {
    http_stream_t *s = user;
    ws_connection_t *conn = s->conn;
    s->reading = 0;

    /* Slot-reuse guard: connection closed/recycled mid-stream → drop (the state
     * is wiped to non-HTTP on cleanup, or the generation differs after reuse). */
    if (!(conn->generation == s->generation && conn->state == WS_STATE_HTTP &&
          conn->file_stream == s)) {
        stream_free(s);
        return;
    }
    ws_event_thread_t *thread = s->thread;
    conn->last_activity = (uint32_t)time(NULL);   /* progress: don't reap an active stream */

    int rc;
    if (nread <= 0) {
        rc = stream_fail(s);                       /* short/failed read mid-stream */
    } else if (portico_conn_send(thread, conn, s->buf, (size_t)nread) != 0) {
        rc = stream_fail(s);
    } else {
        s->offset += nread;
        rc = (s->offset >= s->end) ? stream_finish(s) : stream_advance(s);
    }
    /* s is freed by now if rc < 0 (or if it finished); only touch `conn`. */
    if (rc < 0) {
        if (conn->out_used > conn->out_sent) conn->out_close_when_drained = 1;
        else close_connection(thread, (int)conn->fd);
    }
}

/* Start streaming res->file_fd: send headers (Content-Length known up front),
 * park the connection, submit the first chunk read. Returns -1 to close now, 0 to
 * keep the connection parked (completions/EPOLLOUT drive the rest). */
static int stream_start(ws_event_thread_t *thread, ws_connection_t *conn,
                        portico_response_t *res, size_t consumed) {
    http_stream_t *s = malloc(sizeof *s);
    uint8_t *buf = s ? malloc(PORTICO_STREAM_CHUNK) : NULL;
    if (!s || !buf) { free(s); free(buf); close(res->file_fd); return http_error_close(thread, conn, 500); }
    s->thread = thread; s->conn = conn; s->generation = conn->generation;
    s->file_fd = res->file_fd; s->buf = buf;
    s->offset = res->file_offset;                 /* range start (0 for a full file) */
    s->end = res->file_offset + res->file_size;   /* one past the last byte to serve */
    s->keep_alive = res->keep_alive; s->reading = 0;

    /* Consume this request (park the connection). */
    if (consumed < conn->recv_buffer_used) {
        memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->recv_buffer_used - consumed);
        conn->recv_buffer_used -= consumed;
    } else {
        conn->recv_buffer_used = 0;
    }

    /* Response headers up front — length is known, so a normal Content-Length
     * (no chunked transfer-encoding). res->headers already carries Content-Type. */
    char hdr[PORTICO_RES_HEADERS_CAP + 256];
    int hn = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\n%.*sContent-Length: %lld\r\nConnection: %s\r\n\r\n",
        res->status, portico_http_reason(res->status),
        (int)res->headers_len, res->headers, res->file_size,
        res->keep_alive ? "keep-alive" : "close");
    if (hn < 0 || (size_t)hn >= sizeof hdr) { stream_free(s); return http_error_close(thread, conn, 500); }

    conn->file_stream = s;
    conn->http_async_inflight = 1;
    if (portico_conn_send(thread, conn, hdr, (size_t)hn) != 0) {
        conn->file_stream = NULL; conn->http_async_inflight = 0;
        stream_free(s);
        return -1;
    }
    /* Submit the first chunk read (stream_advance: aio in flight, or sync chunks
     * until backpressure). It returns 0 parked / -1 close. */
    int rc = stream_advance(s);   /* on -1, stream_advance already freed s */
    if (rc < 0) {
        if (conn->out_used > conn->out_sent) { conn->out_close_when_drained = 1; return 0; }
        return -1;
    }
    return 0;
}

/* Begin serving res->file_fd on `conn`: capture state, consume this request, and
 * submit the async read (parking the connection). Falls back to a synchronous read
 * if async I/O is unavailable or the submit is refused. Returns -1 to close now,
 * 0 to keep the connection parked / deferred-closing, 1 to continue the request
 * loop (a synchronous keep-alive response was sent). */
static int http_serve_file(ws_event_thread_t *thread, ws_connection_t *conn,
                           portico_response_t *res, size_t consumed) {
    /* Large files go through the streaming path (needs async I/O). */
    if (thread->aio && res->file_size > PORTICO_STREAM_CHUNK)
        return stream_start(thread, conn, res, consumed);
    /* The single-read path can't exceed the out-buffer-bounded cap; without aio,
     * a too-large file has no streaming path, so refuse it. */
    if (res->file_size > PORTICO_SINGLE_MAX) {
        close(res->file_fd);
        if (consumed < conn->recv_buffer_used) {
            memmove(conn->recv_buffer, conn->recv_buffer + consumed, conn->recv_buffer_used - consumed);
            conn->recv_buffer_used -= consumed;
        } else { conn->recv_buffer_used = 0; }
        return http_error_close(thread, conn, 503);
    }
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
        if (portico_aio_pread(thread->aio, ctx->file_fd, buf, size, res->file_offset,
                              file_read_complete, ctx) == 0)
            return 0;   /* parked — completion responds + resumes */
        conn->http_async_inflight = 0;   /* submit refused → fall through */
    }

    /* Synchronous fallback (no aio, or submit refused): read inline, respond, and
     * tell the caller's loop whether to continue (keep-alive) or close. */
    ssize_t n;
    do { n = pread(ctx->file_fd, buf, size, res->file_offset); } while (n < 0 && errno == EINTR);
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
