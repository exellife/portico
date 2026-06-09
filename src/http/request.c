#include "http_internal.h"
#include "picohttpparser.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

/* ---- request helpers ------------------------------------------------------- */

int portico_req_method_is(const portico_request_t *req, const char *m) {
    size_t n = strlen(m);
    return req->method_len == n && memcmp(req->method, m, n) == 0;
}

int portico_req_path_is(const portico_request_t *req, const char *p) {
    size_t n = strlen(p);
    return req->path_len == n && memcmp(req->path, p, n) == 0;
}

const char *portico_req_header(const portico_request_t *req, const char *name,
                               size_t *len_out) {
    size_t n = strlen(name);
    for (size_t i = 0; i < req->num_headers; i++) {
        const portico_header_t *h = &req->headers[i];
        if (h->name_len == n && strncasecmp(h->name, name, n) == 0) {
            if (len_out) *len_out = h->value_len;
            return h->value;
        }
    }
    return NULL;
}

/* ---- parsing --------------------------------------------------------------- */

static long header_long(const portico_request_t *req, const char *name, long dflt) {
    size_t vlen;
    const char *v = portico_req_header(req, name, &vlen);
    if (!v) return dflt;
    char tmp[32];
    if (vlen == 0 || vlen >= sizeof tmp) return dflt;
    memcpy(tmp, v, vlen); tmp[vlen] = '\0';
    char *end;
    long val = strtol(tmp, &end, 10);
    return (end == tmp) ? dflt : val;
}

static int header_token_present(const portico_request_t *req, const char *name,
                                const char *token) {
    size_t vlen;
    const char *v = portico_req_header(req, name, &vlen);
    if (!v) return 0;
    size_t tlen = strlen(token);
    for (size_t i = 0; i + tlen <= vlen; i++)
        if (strncasecmp(v + i, token, tlen) == 0) return 1;
    return 0;
}

int portico_http_parse(const char *buf, size_t len, portico_request_t *req) {
    const char *method, *path;
    size_t method_len, path_len;
    int minor_version;
    struct phr_header headers[PORTICO_MAX_HEADERS];
    size_t num_headers = PORTICO_MAX_HEADERS;

    memset(req, 0, sizeof *req);   /* never leave req uninitialized on early return */

    int pret = phr_parse_request(buf, len, &method, &method_len, &path, &path_len,
                                 &minor_version, headers, &num_headers, 0);
    if (pret == -2) return 0;    /* incomplete headers */
    if (pret == -1) return -1;   /* malformed */

    req->method = method; req->method_len = method_len;
    req->minor_version = minor_version;

    /* split path and query */
    const char *q = memchr(path, '?', path_len);
    if (q) {
        req->path = path; req->path_len = (size_t)(q - path);
        req->query = q + 1; req->query_len = path_len - req->path_len - 1;
    } else {
        req->path = path; req->path_len = path_len;
        req->query = NULL; req->query_len = 0;
    }

    req->num_headers = num_headers;
    for (size_t i = 0; i < num_headers; i++) {
        req->headers[i].name = headers[i].name;
        req->headers[i].name_len = headers[i].name_len;
        req->headers[i].value = headers[i].value;
        req->headers[i].value_len = headers[i].value_len;
    }

    /* body framing via Content-Length (chunked not yet supported) */
    long clen = header_long(req, "Content-Length", 0);
    if (clen < 0) return -1;
    if (clen > PORTICO_MAX_BODY) return -2;

    size_t total = (size_t)pret + (size_t)clen;
    if (len < total) return 0;   /* body not fully arrived */

    req->body = (clen > 0) ? (buf + pret) : NULL;
    req->body_len = (size_t)clen;

    /* keep-alive: HTTP/1.1 default on unless Connection: close; 1.0 default off. */
    if (minor_version >= 1)
        req->keep_alive = !header_token_present(req, "Connection", "close");
    else
        req->keep_alive = header_token_present(req, "Connection", "keep-alive");

    return (int)total;
}
