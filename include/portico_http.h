/* ============================================================================
 * portico — HTTP request/response types and the request-handler API.
 *
 * Standalone (no wslib dependency) so wslib.h can reference the handler typedef
 * without a circular include. Request field pointers are zero-copy into the
 * connection's receive buffer and are only valid for the duration of the
 * handler call — copy anything you need to keep.
 * ============================================================================ */
#ifndef PORTICO_HTTP_H
#define PORTICO_HTTP_H

#include <stddef.h>

#define PORTICO_MAX_HEADERS 64

typedef struct {
    const char *name;  size_t name_len;
    const char *value; size_t value_len;
} portico_header_t;

typedef struct {
    const char       *method;  size_t method_len;
    const char       *path;    size_t path_len;    /* path only (query stripped) */
    const char       *query;   size_t query_len;   /* after '?', or NULL */
    int               minor_version;               /* HTTP/1.<this> */
    portico_header_t  headers[PORTICO_MAX_HEADERS];
    size_t            num_headers;
    const char       *body;    size_t body_len;
    int               keep_alive;
    /* Resolved client IP (numeric, NUL-terminated). Unlike the pointers above,
     * this is an owned buffer, valid for the handler call. Proxy-aware: the
     * X-Real-IP / leftmost X-Forwarded-For when trust_proxy is set and present,
     * otherwise the direct peer. 46 == INET6_ADDRSTRLEN. */
    char              client_ip[46];
} portico_request_t;

typedef struct portico_response portico_response_t;

/* Application HTTP handler: inspect `req`, fill `res`, return 0.
 * If unset or it leaves the response empty, portico replies 404/500. */
typedef int (*portico_http_handler_fn)(const portico_request_t *req,
                                       portico_response_t *res, void *user_data);

/* ---- request helpers ---- */

/* True if the method equals `m` (exact, case-sensitive — methods are uppercase). */
int portico_req_method_is(const portico_request_t *req, const char *m);
/* True if the path equals `p` exactly. */
int portico_req_path_is(const portico_request_t *req, const char *p);
/* Case-insensitive header lookup; returns value pointer (not NUL-terminated) and
 * its length via len_out, or NULL if absent. */
const char *portico_req_header(const portico_request_t *req, const char *name,
                               size_t *len_out);

/* The resolved client IP (numeric, NUL-terminated). Proxy-aware when the server
 * was configured with trust_proxy (X-Real-IP / leftmost X-Forwarded-For), else
 * the direct peer address. Use for rate limiting, blacklists, and audit logs. */
const char *portico_req_client_ip(const portico_request_t *req);

/* ---- response builders (call from within the handler) ---- */

void portico_res_status(portico_response_t *res, int status);
/* Append a response header. Content-Length/Connection are added automatically. */
void portico_res_header(portico_response_t *res, const char *name, const char *value);
/* Set the body (copied). content_type may be NULL to leave it unset. */
void portico_res_body(portico_response_t *res, const void *data, size_t len,
                      const char *content_type);
void portico_res_json(portico_response_t *res, const char *json);
void portico_res_text(portico_response_t *res, int status, const char *text);

/* Serve a static file. Resolves `req`'s URL path under `docroot` — percent-decoded
 * and traversal/symlink-safe (the resolved path must stay within docroot) — opens
 * it, and arranges for its contents to be sent as the response body via async I/O
 * (the read happens off the event thread; the response is produced after the
 * handler returns). Sets Content-Type from the file extension if not already set.
 *
 * Always produces a complete response: 200 for a readable regular file, else an
 * error status (404 not found, 403 forbidden / escapes docroot, 413 too large,
 * 400 bad path). Call it from the handler and `return 0` — do not also fill the
 * response yourself. Returns 0 if a file was accepted for sending, non-zero if an
 * error status was set instead. */
int portico_res_file(portico_response_t *res, const portico_request_t *req,
                     const char *docroot);

/* Options for serving a docroot as a mounted static site. */
typedef struct {
    const char *docroot;      /* filesystem root (required) */
    const char *url_prefix;   /* strip this leading URL segment before resolving,
                               * e.g. "/static" (no trailing slash); NULL = none */
    const char *index;        /* directory index filename; NULL = "index.html",
                               * "" = disable (a directory request → 403) */
    int         precompressed;/* when set, serve a sibling <file>.br/.gz if it exists
                               * and the client accepts it (Content-Encoding + Vary) */
} portico_static_opts_t;

/* Like portico_res_file but with URL-prefix stripping and a directory index, so a
 * folder can be mounted under a URL prefix and "/" (or any subdir) serves its
 * index file. Same async + traversal/symlink-safety + Range/conditional behavior.
 * portico_res_file(res, req, docroot) == this with no prefix and index.html. */
int portico_res_static(portico_response_t *res, const portico_request_t *req,
                       const portico_static_opts_t *opts);

#endif /* PORTICO_HTTP_H */
