#include "http_internal.h"
#include "picohttpparser.h"

#include <limits.h>
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

/* Resolve the request's body framing in a smuggling-resistant way (RFC 7230
 * §3.3.3). Sets *clen_out to the Content-Length (0 if absent). Returns:
 *    0  ok
 *   -1  ambiguous/illegal framing -> caller replies 400
 *   -3  Transfer-Encoding present  -> caller replies 501 (chunked unsupported)
 * Rules enforced:
 *   - Transfer-Encoding in any form is rejected (we don't decode chunked, and
 *     silently ignoring it lets a chunked-aware proxy smuggle a second request).
 *   - Multiple Content-Length headers, or a single header carrying a comma list,
 *     are rejected unless every value is identical.
 *   - A Content-Length value must be a non-empty run of ASCII digits only —
 *     no sign, whitespace, or trailing junk that a peer might parse differently. */
static int resolve_body_framing(const portico_request_t *req, long *clen_out) {
    *clen_out = 0;

    int have_clen = 0;
    long agreed = 0;
    for (size_t i = 0; i < req->num_headers; i++) {
        const portico_header_t *h = &req->headers[i];
        if (h->name_len == 17 && strncasecmp(h->name, "Transfer-Encoding", 17) == 0)
            return -3;   /* not implemented */
        if (!(h->name_len == 14 && strncasecmp(h->name, "Content-Length", 14) == 0))
            continue;

        /* A value may itself be a comma-separated list (e.g. "5, 5"); every
         * element must be a valid digit-run and they must all agree. */
        size_t start = 0;
        const char *v = h->value;
        size_t vlen = h->value_len;
        for (size_t j = 0; j <= vlen; j++) {
            if (j == vlen || v[j] == ',') {
                /* trim spaces/tabs around [start, j) */
                size_t a = start, b = j;
                while (a < b && (v[a] == ' ' || v[a] == '\t')) a++;
                while (b > a && (v[b-1] == ' ' || v[b-1] == '\t')) b--;
                if (a == b) return -1;            /* empty element */
                long val = 0;
                for (size_t k = a; k < b; k++) {
                    if (v[k] < '0' || v[k] > '9') return -1;   /* non-digit */
                    if (val > (LONG_MAX - (v[k] - '0')) / 10) return -1; /* overflow */
                    val = val * 10 + (v[k] - '0');
                }
                if (have_clen && val != agreed) return -1;     /* disagreement */
                agreed = val; have_clen = 1;
                start = j + 1;
            }
        }
    }

    *clen_out = have_clen ? agreed : 0;
    return 0;
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
    long clen;
    int fr = resolve_body_framing(req, &clen);
    if (fr != 0) return fr;   /* -1 -> 400, -3 -> 501 */
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
