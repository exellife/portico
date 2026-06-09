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

/* ---- response builders (call from within the handler) ---- */

void portico_res_status(portico_response_t *res, int status);
/* Append a response header. Content-Length/Connection are added automatically. */
void portico_res_header(portico_response_t *res, const char *name, const char *value);
/* Set the body (copied). content_type may be NULL to leave it unset. */
void portico_res_body(portico_response_t *res, const void *data, size_t len,
                      const char *content_type);
void portico_res_json(portico_response_t *res, const char *json);
void portico_res_text(portico_response_t *res, int status, const char *text);

#endif /* PORTICO_HTTP_H */
