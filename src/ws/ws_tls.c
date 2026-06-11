#include "ws_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#ifdef PORTICO_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

/* OpenSSL 1.1.0+/3.x auto-initialize on first use, so no explicit library init
 * is needed here. The SSL_CTX is created once at server start and shared. */

int ws_tls_available(void) { return 1; }

/* A TLS context group: the default cert (presented when SNI is absent or matches
 * nothing) plus per-host certs selected during the handshake via SNI. The server
 * holds this as its opaque tls_ctx; connections SSL_new() from `def`. */
typedef struct {
    SSL_CTX *def;
    struct { char *host; SSL_CTX *ctx; } *certs;
    size_t   n;
} ws_tls_group_t;

/* Build a hardened SSL_CTX from a cert/key pair (the shared secure defaults). */
static SSL_CTX *make_ctx(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) return NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { fprintf(stderr, "portico tls: SSL_CTX_new failed\n"); return NULL; }

    /* Refuse < TLS 1.2, disable renegotiation, server picks the cipher, and
     * tolerate the non-blocking write pattern (partial writes / moving buffer). */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
        fprintf(stderr, "portico tls: failed to load certificate '%s'\n", cert_file);
        SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "portico tls: failed to load private key '%s'\n", key_file);
        SSL_CTX_free(ctx); return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "portico tls: private key does not match certificate\n");
        SSL_CTX_free(ctx); return NULL;
    }
    return ctx;
}

/* `host` matches `pat`: case-insensitive exact, or a leading "*." wildcard that
 * covers exactly one label (e.g. "*.example.com" matches "a.example.com"). */
static int host_match(const char *pat, const char *host) {
    if (pat[0] == '*' && pat[1] == '.') {
        const char *dot = strchr(host, '.');
        return dot && strcasecmp(pat + 2, dot + 1) == 0;
    }
    return strcasecmp(pat, host) == 0;
}

/* SNI handshake callback: swap in the per-host cert matching the ClientHello
 * server_name; with no match the default cert stays. (All ctxs share the same
 * security options, so SSL_set_SSL_CTX only changes the certificate.) */
static int sni_cb(SSL *ssl, int *al, void *arg) {
    ws_tls_group_t *g = (ws_tls_group_t *)arg;
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    (void)al;
    if (host)
        for (size_t i = 0; i < g->n; i++)
            if (host_match(g->certs[i].host, host)) { SSL_set_SSL_CTX(ssl, g->certs[i].ctx); break; }
    return SSL_TLSEXT_ERR_OK;
}

void *ws_tls_ctx_create(const char *cert_file, const char *key_file) {
    SSL_CTX *def = make_ctx(cert_file, key_file);
    if (!def) return NULL;
    ws_tls_group_t *g = calloc(1, sizeof *g);
    if (!g) { SSL_CTX_free(def); return NULL; }
    g->def = def;
    /* Wire SNI selection onto the default ctx (the one connections SSL_new from). */
    SSL_CTX_set_tlsext_servername_callback(def, sni_cb);
    SSL_CTX_set_tlsext_servername_arg(def, g);
    return g;
}

int ws_tls_ctx_add_sni(void *group, const char *hostname,
                       const char *cert_file, const char *key_file) {
    ws_tls_group_t *g = (ws_tls_group_t *)group;
    if (!g || !hostname || !cert_file || !key_file) return -1;
    SSL_CTX *ctx = make_ctx(cert_file, key_file);
    if (!ctx) return -1;
    char *h = strdup(hostname);
    void *nc = h ? realloc(g->certs, (g->n + 1) * sizeof *g->certs) : NULL;
    if (!nc) { free(h); SSL_CTX_free(ctx); return -1; }
    g->certs = nc;
    g->certs[g->n].host = h;
    g->certs[g->n].ctx  = ctx;
    g->n++;
    return 0;
}

void ws_tls_ctx_free(void *group) {
    ws_tls_group_t *g = (ws_tls_group_t *)group;
    if (!g) return;
    for (size_t i = 0; i < g->n; i++) { free(g->certs[i].host); SSL_CTX_free(g->certs[i].ctx); }
    free(g->certs);
    if (g->def) SSL_CTX_free(g->def);
    free(g);
}

void *ws_tls_conn_new(void *group, int fd) {
    ws_tls_group_t *g = (ws_tls_group_t *)group;
    if (!g || !g->def) return NULL;
    SSL *ssl = SSL_new(g->def);
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

void ws_tls_conn_shutdown(void *ssl) {
    if (ssl) SSL_shutdown((SSL *)ssl);   /* sends our close_notify; best-effort */
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

int ws_tls_read(void *ssl, void *buf, int len) {
    SSL *s = (SSL *)ssl;
    int n = SSL_read(s, buf, len);
    if (n > 0) return n;
    switch (SSL_get_error(s, n)) {
        case SSL_ERROR_ZERO_RETURN:                   /* peer's close_notify */
            return 0;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:                    /* needs more I/O — wait */
            errno = EAGAIN; return -1;
        default:
            errno = EIO; return -1;
    }
}

int ws_tls_write(void *ssl, const void *buf, int len) {
    SSL *s = (SSL *)ssl;
    int n = SSL_write(s, buf, len);
    if (n > 0) return n;
    switch (SSL_get_error(s, n)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:                    /* socket full / needs read — backpressure */
            errno = EAGAIN; return -1;
        default:
            errno = EIO; return -1;
    }
}

#else  /* portico built without OpenSSL */

int   ws_tls_available(void) { return 0; }
void *ws_tls_ctx_create(const char *cert_file, const char *key_file) {
    (void)cert_file; (void)key_file;
    return NULL;
}
int   ws_tls_ctx_add_sni(void *group, const char *hostname, const char *cert_file, const char *key_file) {
    (void)group; (void)hostname; (void)cert_file; (void)key_file; return -1;
}
void  ws_tls_ctx_free(void *ctx) { (void)ctx; }
void *ws_tls_conn_new(void *ctx, int fd) { (void)ctx; (void)fd; return NULL; }
void  ws_tls_conn_free(void *ssl) { (void)ssl; }
void  ws_tls_conn_shutdown(void *ssl) { (void)ssl; }
int   ws_tls_do_handshake(void *ssl) { (void)ssl; return WS_TLS_ERROR; }
int   ws_tls_read(void *ssl, void *buf, int len) { (void)ssl; (void)buf; (void)len; errno = EIO; return -1; }
int   ws_tls_write(void *ssl, const void *buf, int len) { (void)ssl; (void)buf; (void)len; errno = EIO; return -1; }

#endif /* PORTICO_TLS */
