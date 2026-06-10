#include "ws_tls.h"

#include <stdio.h>

#ifdef PORTICO_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

/* OpenSSL 1.1.0+/3.x auto-initialize on first use, so no explicit library init
 * is needed here. The SSL_CTX is created once at server start and shared. */

int ws_tls_available(void) { return 1; }

void *ws_tls_ctx_create(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) return NULL;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "portico tls: SSL_CTX_new failed\n");
        return NULL;
    }

    /* Secure defaults: refuse < TLS 1.2, disable renegotiation, let the server
     * pick the cipher, and tolerate the non-blocking write pattern we use later
     * (partial writes / a moving write buffer across retries). */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
        fprintf(stderr, "portico tls: failed to load certificate '%s'\n", cert_file);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "portico tls: failed to load private key '%s'\n", key_file);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "portico tls: private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

void ws_tls_ctx_free(void *ctx) {
    if (ctx) SSL_CTX_free((SSL_CTX *)ctx);
}

void *ws_tls_conn_new(void *ctx, int fd) {
    if (!ctx) return NULL;
    SSL *ssl = SSL_new((SSL_CTX *)ctx);
    if (!ssl) return NULL;
    /* SSL_set_fd uses a BIO_NOCLOSE socket BIO, so SSL_free never closes fd —
     * portico's close_connection remains the sole owner of the descriptor. */
    if (SSL_set_fd(ssl, fd) != 1) { SSL_free(ssl); return NULL; }
    SSL_set_accept_state(ssl);
    return ssl;
}

void ws_tls_conn_free(void *ssl) {
    if (ssl) SSL_free((SSL *)ssl);
}

int ws_tls_do_handshake(void *ssl) {
    SSL *s = (SSL *)ssl;
    int r = SSL_accept(s);
    if (r == 1) return WS_TLS_DONE;
    switch (SSL_get_error(s, r)) {
        case SSL_ERROR_WANT_READ:  return WS_TLS_WANT_READ;
        case SSL_ERROR_WANT_WRITE: return WS_TLS_WANT_WRITE;
        default:                   return WS_TLS_ERROR;
    }
}

#else  /* portico built without OpenSSL */

int   ws_tls_available(void) { return 0; }
void *ws_tls_ctx_create(const char *cert_file, const char *key_file) {
    (void)cert_file; (void)key_file;
    return NULL;
}
void  ws_tls_ctx_free(void *ctx) { (void)ctx; }
void *ws_tls_conn_new(void *ctx, int fd) { (void)ctx; (void)fd; return NULL; }
void  ws_tls_conn_free(void *ssl) { (void)ssl; }
int   ws_tls_do_handshake(void *ssl) { (void)ssl; return WS_TLS_ERROR; }

#endif /* PORTICO_TLS */
