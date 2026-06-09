#include "http_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- response builders ----------------------------------------------------- */

void portico_res_status(portico_response_t *res, int status) {
    res->status = status;
}

void portico_res_header(portico_response_t *res, const char *name, const char *value) {
    int n = snprintf(res->headers + res->headers_len,
                     PORTICO_RES_HEADERS_CAP - res->headers_len,
                     "%s: %s\r\n", name, value);
    if (n > 0 && (size_t)n < PORTICO_RES_HEADERS_CAP - res->headers_len)
        res->headers_len += (size_t)n;
    if (strcasecmp(name, "Content-Type") == 0) res->content_type_set = 1;
}

void portico_res_body(portico_response_t *res, const void *data, size_t len,
                      const char *content_type) {
    free(res->body);
    res->body = malloc(len ? len : 1);
    if (!res->body) { res->body_len = 0; res->owns_body = 0; return; }
    if (len) memcpy(res->body, data, len);
    res->body_len = len;
    res->owns_body = 1;
    if (content_type && !res->content_type_set)
        portico_res_header(res, "Content-Type", content_type);
}

void portico_res_json(portico_response_t *res, const char *json) {
    portico_res_body(res, json, strlen(json), "application/json");
}

void portico_res_text(portico_response_t *res, int status, const char *text) {
    res->status = status;
    portico_res_body(res, text, strlen(text), "text/plain; charset=utf-8");
}

/* ---- status reasons -------------------------------------------------------- */

const char *portico_http_reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        default:  return "OK";
    }
}

/* ---- serialize ------------------------------------------------------------- */

int portico_http_build_response(portico_response_t *res, uint8_t **out, size_t *out_len) {
    if (res->status == 0) res->status = 200;

    char head[PORTICO_RES_HEADERS_CAP + 256];
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 %d %s\r\n%.*sContent-Length: %zu\r\nConnection: %s\r\n\r\n",
                      res->status, portico_http_reason(res->status),
                      (int)res->headers_len, res->headers,
                      res->body_len,
                      res->keep_alive ? "keep-alive" : "close");
    if (hn <= 0 || (size_t)hn >= sizeof head) return -1;

    size_t total = (size_t)hn + res->body_len;
    uint8_t *buf = malloc(total ? total : 1);
    if (!buf) return -1;
    memcpy(buf, head, (size_t)hn);
    if (res->body_len) memcpy(buf + hn, res->body, res->body_len);
    *out = buf;
    *out_len = total;
    return 0;
}

int portico_http_build_status(int status, int keep_alive, uint8_t **out, size_t *out_len) {
    char tmp[160];
    int n = snprintf(tmp, sizeof tmp,
                     "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: %s\r\n\r\n",
                     status, portico_http_reason(status),
                     keep_alive ? "keep-alive" : "close");
    if (n <= 0 || (size_t)n >= sizeof tmp) return -1;
    uint8_t *buf = malloc((size_t)n);
    if (!buf) return -1;
    memcpy(buf, tmp, (size_t)n);
    *out = buf;
    *out_len = (size_t)n;
    return 0;
}
