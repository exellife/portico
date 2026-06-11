/* Minimal verifying HTTPS client for the ACME flow. Blocking, one connection per
 * request (ACME is low-volume), built on the OpenSSL portico already links. The
 * security-critical part is verification: the peer cert chain is checked against
 * the trust store AND the hostname is checked against the cert (SSL_set1_host) —
 * without the latter, any valid cert would pass and a MITM could impersonate the CA. */
#include "acme_internal.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef PORTICO_TLS

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HTTPS_TIMEOUT_SEC 30

/* Parse "https://host[:port]/path" → host, port, path. Returns 0 / -1. */
static int parse_url(const char *url, char *host, size_t hostcap,
                     char *port, size_t portcap, char *path, size_t pathcap) {
    if (strncmp(url, "https://", 8) != 0) return -1;
    const char *h = url + 8;
    const char *slash = strchr(h, '/');
    const char *hostend = slash ? slash : h + strlen(h);
    const char *colon = memchr(h, ':', (size_t)(hostend - h));

    size_t hlen = (size_t)((colon ? colon : hostend) - h);
    if (hlen == 0 || hlen >= hostcap) return -1;
    memcpy(host, h, hlen); host[hlen] = '\0';

    if (colon) {
        size_t plen = (size_t)(hostend - colon - 1);
        if (plen == 0 || plen >= portcap) return -1;
        memcpy(port, colon + 1, plen); port[plen] = '\0';
    } else {
        snprintf(port, portcap, "443");
    }
    snprintf(path, pathcap, "%s", slash ? slash : "/");
    return 0;
}

/* TCP connect with send/recv timeouts. Returns fd or -1. */
static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = HTTPS_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Copy header `name`'s value (case-insensitive, trimmed) from a header block. */
static void get_header(const char *hdrs, size_t len, const char *name, char *out, size_t cap) {
    out[0] = '\0';
    size_t nlen = strlen(name);
    for (const char *p = hdrs; p < hdrs + len; ) {
        const char *eol = memchr(p, '\n', (size_t)(hdrs + len - p));
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(hdrs + len - p);
        if (linelen > nlen && p[nlen] == ':' && strncasecmp(p, name, nlen) == 0) {
            const char *v = p + nlen + 1;
            const char *vend = p + linelen;
            while (v < vend && (*v == ' ' || *v == '\t')) v++;
            while (vend > v && (vend[-1] == '\r' || vend[-1] == ' ' || vend[-1] == '\t')) vend--;
            size_t vlen = (size_t)(vend - v);
            if (vlen >= cap) vlen = cap - 1;
            memcpy(out, v, vlen); out[vlen] = '\0';
            return;
        }
        if (!eol) break;
        p = eol + 1;
    }
}

/* Decode a Transfer-Encoding: chunked body. Returns malloc'd bytes (NUL-terminated). */
static char *dechunk(const char *in, size_t in_len, size_t *out_len) {
    char *out = malloc(in_len + 1);
    if (!out) return NULL;
    size_t o = 0, i = 0;
    while (i < in_len) {
        char *endp;
        long sz = strtol(in + i, &endp, 16);
        if (endp == in + i) break;
        const char *nl = memchr(endp, '\n', in_len - (size_t)(endp - in));
        if (!nl) break;
        i = (size_t)(nl - in) + 1;
        if (sz <= 0) break;                           /* final chunk */
        if (i + (size_t)sz > in_len) sz = (long)(in_len - i);
        memcpy(out + o, in + i, (size_t)sz); o += (size_t)sz;
        i += (size_t)sz;
        while (i < in_len && (in[i] == '\r' || in[i] == '\n')) i++;
    }
    out[o] = '\0';
    *out_len = o;
    return out;
}

/* Read the whole TLS stream to EOF into a malloc'd, NUL-terminated buffer. */
static char *read_all(SSL *ssl, size_t *out_len) {
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        int n = SSL_read(ssl, buf + len, 4096);
        if (n > 0) { len += (size_t)n; continue; }
        int e = SSL_get_error(ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
        break;   /* clean close or error — return what we have */
    }
    char *fit = realloc(buf, len + 1);
    if (fit) buf = fit;
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

int portico_https_request(const char *method, const char *url, const char *ca_file,
                          const char *headers, const void *body, size_t body_len,
                          portico_http_response_t *resp) {
    if (!resp) return -1;
    memset(resp, 0, sizeof *resp);
    resp->status = -1;

    char host[256], port[16], path[2048];
    if (parse_url(url, host, sizeof host, port, sizeof port, path, sizeof path) != 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    int trust_ok = ca_file ? (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) == 1)
                           : (SSL_CTX_set_default_verify_paths(ctx) == 1);
    if (!trust_ok) { SSL_CTX_free(ctx); return -1; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);   /* fail the handshake on a bad chain */

    int fd = tcp_connect(host, port);
    if (fd < 0) { SSL_CTX_free(ctx); return -1; }

    SSL *ssl = SSL_new(ctx);
    int rc = -1;
    if (!ssl) goto done;
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);              /* SNI */
    if (SSL_set1_host(ssl, host) != 1) goto done;     /* verify cert matches hostname */
    if (SSL_connect(ssl) != 1) goto done;             /* handshake + full verification */

    /* Build + send the request. The Host header MUST carry a non-default port — some
     * ACME servers (e.g. Pebble) build their directory's resource URLs from it, so
     * dropping ":14000" yields portless URLs that then fail to connect. */
    char host_hdr[280];
    if (strcmp(port, "443") == 0) snprintf(host_hdr, sizeof host_hdr, "%s", host);
    else                          snprintf(host_hdr, sizeof host_hdr, "%s:%s", host, port);

    char head[4096];
    int hn;
    if (body)
        hn = snprintf(head, sizeof head,
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: portico-acme\r\n%s"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n",
            method, path, host_hdr, headers ? headers : "", body_len);
    else
        hn = snprintf(head, sizeof head,
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: portico-acme\r\n%s"
            "Connection: close\r\n\r\n",
            method, path, host_hdr, headers ? headers : "");
    if (hn <= 0 || (size_t)hn >= sizeof head) goto done;
    if (SSL_write(ssl, head, hn) != hn) goto done;
    if (body && body_len && SSL_write(ssl, body, (int)body_len) != (int)body_len) goto done;

    /* Read + parse the response. */
    size_t raw_len = 0;
    char *raw = read_all(ssl, &raw_len);
    if (!raw) goto done;

    char *sep = NULL;
    for (size_t i = 0; i + 3 < raw_len; i++)
        if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n') { sep = raw + i; break; }
    if (!sep) { free(raw); goto done; }

    size_t hdr_len = (size_t)(sep - raw);
    if (strncmp(raw, "HTTP/1.", 7) == 0) {
        const char *sp = memchr(raw, ' ', hdr_len);
        if (sp) resp->status = atoi(sp + 1);
    }
    get_header(raw, hdr_len, "Replay-Nonce",  resp->nonce,        sizeof resp->nonce);
    get_header(raw, hdr_len, "Location",      resp->location,     sizeof resp->location);
    get_header(raw, hdr_len, "Content-Type",  resp->content_type, sizeof resp->content_type);

    char te[32]; get_header(raw, hdr_len, "Transfer-Encoding", te, sizeof te);
    const char *bstart = sep + 4;
    size_t blen = raw_len - (size_t)(bstart - raw);
    if (strcasecmp(te, "chunked") == 0) {
        resp->body = dechunk(bstart, blen, &resp->body_len);
    } else {
        resp->body = malloc(blen + 1);
        if (resp->body) { memcpy(resp->body, bstart, blen); resp->body[blen] = '\0'; resp->body_len = blen; }
    }
    free(raw);
    rc = 0;   /* a complete HTTP exchange (status is set) */

done:
    if (ssl) SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return rc;
}

#else  /* portico built without OpenSSL */

int portico_https_request(const char *method, const char *url, const char *ca_file,
                          const char *headers, const void *body, size_t body_len,
                          portico_http_response_t *resp) {
    (void)method; (void)url; (void)ca_file; (void)headers; (void)body; (void)body_len;
    if (resp) { memset(resp, 0, sizeof *resp); resp->status = -1; }
    return -1;
}

#endif /* PORTICO_TLS */
