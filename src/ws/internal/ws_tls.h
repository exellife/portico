/* ============================================================================
 * portico — optional TLS termination (OpenSSL).
 *
 * Thin wrapper so the rest of wslib needs no OpenSSL headers: the SSL_CTX and
 * per-connection SSL objects are passed around as void*. When portico is built
 * without OpenSSL (PORTICO_TLS undefined) every function is a safe no-op and
 * ws_tls_available() returns 0, so a plaintext build links and runs unchanged.
 * ============================================================================ */
#ifndef WS_TLS_H
#define WS_TLS_H

#include <stddef.h>

/* 1 if portico was built with TLS support, else 0. */
int ws_tls_available(void);

/* Build a server SSL_CTX from PEM cert/key files (secure defaults: TLS 1.2+,
 * server cipher preference). Returns the context (as void*) or NULL on any
 * failure / when TLS is unavailable. Free with ws_tls_ctx_free. */
void *ws_tls_ctx_create(const char *cert_file, const char *key_file);
void  ws_tls_ctx_free(void *ctx);

/* ---- per-connection (server side) ----------------------------------------- */

/* ws_tls_do_handshake return codes. */
#define WS_TLS_DONE        1   /* handshake complete */
#define WS_TLS_WANT_READ   0   /* needs more bytes — wait for EPOLLIN */
#define WS_TLS_WANT_WRITE  2   /* needs to write — wait for EPOLLOUT */
#define WS_TLS_ERROR     (-1)  /* fatal — close the connection */

/* Create a server-side SSL bound to fd (BIO_NOCLOSE: SSL_free never closes fd —
 * portico owns the fd). Returns the SSL (void*) or NULL. */
void *ws_tls_conn_new(void *ctx, int fd);
void  ws_tls_conn_free(void *ssl);

/* Drive the TLS accept handshake one step; returns a WS_TLS_* code. */
int   ws_tls_do_handshake(void *ssl);

#endif /* WS_TLS_H */
