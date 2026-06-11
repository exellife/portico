/* portico — internal HTTP plumbing (not part of the public API). */
#ifndef PORTICO_HTTP_INTERNAL_H
#define PORTICO_HTTP_INTERNAL_H

#include "portico_http.h"
#include <stddef.h>
#include <stdint.h>

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
    /* Static file serving (set by portico_res_file). When is_file is set, the
     * body is `file_size` bytes of file_fd starting at file_offset (served via an
     * async read), not `body`. file_offset/file_size also express a byte Range. */
    int       is_file;
    int       file_fd;
    long long file_offset;
    long long file_size;
};

/* Parse one request from `buf` (length `len`) using picohttpparser.
 * Returns: >0 = total request length consumed (header + body) and fills `req`;
 *           0 = incomplete, need more bytes;
 *          -1 = malformed / ambiguous framing (reply 400);
 *          -2 = body exceeds PORTICO_MAX_BODY (reply 413);
 *          -3 = uses Transfer-Encoding, which is unsupported (reply 501). */
int portico_http_parse(const char *buf, size_t len, portico_request_t *req);

/* Reason phrase for a status code (e.g. 404 -> "Not Found"). */
const char *portico_http_reason(int status);

/* Serialize `res` into a freshly malloc'd buffer (caller frees *out).
 * Returns 0 on success (sets *out / *out_len), -1 on error. */
int portico_http_build_response(portico_response_t *res, uint8_t **out, size_t *out_len);

/* Build a minimal status-only response (protocol errors) into a malloc'd
 * buffer (caller frees *out). Returns 0 on success, -1 on error. */
int portico_http_build_status(int status, int keep_alive, uint8_t **out, size_t *out_len);

#endif /* PORTICO_HTTP_INTERNAL_H */
