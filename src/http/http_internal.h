/* portico — internal HTTP plumbing (not part of the public API). */
#ifndef PORTICO_HTTP_INTERNAL_H
#define PORTICO_HTTP_INTERNAL_H

#include "portico_http.h"
#include <stddef.h>

#define PORTICO_RES_HEADERS_CAP 4096
#define PORTICO_MAX_BODY        (16 * 1024 * 1024)   /* request body hard cap */
#define PORTICO_MAX_HEADER_SIZE (32 * 1024)          /* request header hard cap */

struct portico_response {
    int    status;                              /* default 200 */
    char   headers[PORTICO_RES_HEADERS_CAP];    /* user "Name: value\r\n" lines */
    size_t headers_len;
    char  *body;
    size_t body_len;
    int    owns_body;
    int    keep_alive;                          /* inherited from request */
    int    content_type_set;
};

/* Parse one request from `buf` (length `len`) using picohttpparser.
 * Returns: >0 = total request length consumed (header + body) and fills `req`;
 *           0 = incomplete, need more bytes;
 *          -1 = malformed (reply 400);
 *          -2 = body exceeds PORTICO_MAX_BODY (reply 413). */
int portico_http_parse(const char *buf, size_t len, portico_request_t *req);

/* Reason phrase for a status code (e.g. 404 -> "Not Found"). */
const char *portico_http_reason(int status);

/* Robustly write `len` bytes to `fd` (handles partial sends / EAGAIN).
 * Returns 0 on success, -1 on error. */
int portico_send_all(int fd, const void *buf, size_t len);

/* Serialize `res` and send it on `fd`. Returns 0 on success, -1 on error. */
int portico_http_send_response(int fd, portico_response_t *res);

/* Send a minimal status-only response (used for protocol-level errors). */
int portico_http_send_status(int fd, int status, int keep_alive);

#endif /* PORTICO_HTTP_INTERNAL_H */
