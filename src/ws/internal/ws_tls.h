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

#endif /* WS_TLS_H */
