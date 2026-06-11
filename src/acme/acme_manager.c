/* The issue/renew manager — the piece that makes built-in ACME a feature portico
 * USES rather than a library beside it. It keeps a current certificate on disk for
 * a set of domains: on startup it issues one if missing/expiring (synchronously, so
 * the TLS listener can come up with a valid cert), serves HTTP-01 challenges on its
 * own plaintext sidecar listener, and a background thread renews ahead of expiry —
 * firing on_renewed() so the app can hot-reload without a restart.
 *
 * Deliberately a sidecar: it owns a small :80 responder and never reaches into the
 * server. The only coupling back to portico is the on_renewed callback the app wires
 * to ws_server_reload_tls(), so the dependency arrow stays portico → portico_acme. */
#include "acme_internal.h"

#ifdef PORTICO_TLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int portico_acme_cert_days_left(const char *cert_path) {
    if (!cert_path) return -1;
    FILE *f = fopen(cert_path, "r");
    if (!f) return -1;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);   /* leaf is first in the chain */
    fclose(f);
    if (!x) return -1;
    int day = 0, sec = 0;
    int ok = ASN1_TIME_diff(&day, &sec, NULL, X509_get0_notAfter(x));   /* now → notAfter */
    X509_free(x);
    return ok ? day : -1;
}

int portico_acme_cert_needs_renewal(const char *cert_path, int renew_within_days) {
    int d = portico_acme_cert_days_left(cert_path);
    return (d < 0) || (d <= renew_within_days);   /* missing/expired/parse-fail ⇒ renew */
}

struct portico_acme_manager {
    portico_acme_manager_config_t cfg;
    portico_acme_responder_t     *responder;
    int        bound_port;
    int        stop_fd;        /* eventfd to interrupt the renewal sleep */
    pthread_t  thread;
    int        thread_started;
};

/* Write the public cert chain (0644 — it is not secret; the key is written 0600 by
 * the CSR/key path). */
static int write_public(const char *path, const char *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t w = write(fd, data, len);
    int ok = (w == (ssize_t)len);
    if (close(fd) != 0) ok = 0;
    return ok ? 0 : -1;
}

int portico_acme_manager_ensure(portico_acme_manager_t *m) {
    if (!m) return -1;
    if (!portico_acme_cert_needs_renewal(m->cfg.cert_path, m->cfg.renew_within_days))
        return 0;   /* still current — do not bother the CA */

    portico_acme_config_t oc = {
        .directory_url    = m->cfg.directory_url,
        .account_key_path = m->cfg.account_key_path,
        .email            = m->cfg.email,
        .ca_file          = m->cfg.ca_file,
        .provision        = portico_acme_responder_provision,
        .unprovision      = portico_acme_responder_unprovision,
        .ud               = m->responder,
    };
    char *pem = NULL;
    if (portico_acme_obtain(&oc, m->cfg.domains, m->cfg.ndomains, m->cfg.cert_key_path, &pem) != 0)
        return -1;
    int wr = write_public(m->cfg.cert_path, pem, strlen(pem));
    free(pem);
    if (wr != 0) {
        fprintf(stderr, "acme: issued a cert but failed to write '%s'\n", m->cfg.cert_path);
        return -1;
    }
    if (m->cfg.on_renewed) m->cfg.on_renewed(m->cfg.ud);   /* app hot-reloads TLS */
    return 1;
}

static void *renew_loop(void *arg) {
    portico_acme_manager_t *m = arg;
    for (;;) {
        struct pollfd p = { .fd = m->stop_fd, .events = POLLIN };
        int pr = poll(&p, 1, m->cfg.check_interval_secs * 1000);
        if (pr > 0) break;                       /* stop requested */
        if (pr < 0 && errno == EINTR) continue;
        portico_acme_manager_ensure(m);          /* best-effort; retried next period */
    }
    return NULL;
}

portico_acme_manager_t *portico_acme_manager_start(const portico_acme_manager_config_t *cfg) {
    if (!cfg || !cfg->cert_path || !cfg->cert_key_path || !cfg->domains || cfg->ndomains == 0)
        return NULL;

    portico_acme_manager_t *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cfg = *cfg;
    if (m->cfg.renew_within_days   <= 0) m->cfg.renew_within_days   = 30;
    if (m->cfg.check_interval_secs <= 0) m->cfg.check_interval_secs = 12 * 3600;
    m->stop_fd = -1;

    m->responder = portico_acme_responder_new();
    if (!m->responder) { free(m); return NULL; }

    int port = portico_acme_responder_listen(m->responder, m->cfg.challenge_port);
    if (port < 0) { portico_acme_responder_free(m->responder); free(m); return NULL; }
    m->bound_port = port;

    /* Initial issuance is synchronous: the server must not start TLS without a cert. */
    if (portico_acme_manager_ensure(m) < 0) {
        portico_acme_responder_stop(m->responder);
        portico_acme_responder_free(m->responder);
        free(m);
        return NULL;
    }

    m->stop_fd = eventfd(0, EFD_NONBLOCK);
    if (m->stop_fd >= 0 && pthread_create(&m->thread, NULL, renew_loop, m) == 0) {
        m->thread_started = 1;
    } else {
        /* The cert is in place; we just won't auto-renew. Degraded, not fatal. */
        if (m->stop_fd >= 0) { close(m->stop_fd); m->stop_fd = -1; }
        fprintf(stderr, "acme: renewal thread did not start; auto-renew disabled\n");
    }
    return m;
}

int portico_acme_manager_challenge_port(const portico_acme_manager_t *m) {
    return m ? m->bound_port : -1;
}

void portico_acme_manager_stop(portico_acme_manager_t *m) {
    if (!m) return;
    if (m->thread_started) {
        uint64_t one = 1;
        if (write(m->stop_fd, &one, sizeof one) < 0) { /* thread also wakes on timeout */ }
        pthread_join(m->thread, NULL);
    }
    if (m->stop_fd >= 0) close(m->stop_fd);
    if (m->responder) {
        portico_acme_responder_stop(m->responder);
        portico_acme_responder_free(m->responder);
    }
    free(m);
}

#else  /* portico built without OpenSSL — issuance/renewal need the TLS client */

int portico_acme_cert_days_left(const char *cert_path) { (void)cert_path; return -1; }
int portico_acme_cert_needs_renewal(const char *cert_path, int d) { (void)cert_path; (void)d; return 1; }
portico_acme_manager_t *portico_acme_manager_start(const portico_acme_manager_config_t *cfg) {
    (void)cfg; return NULL;
}
int portico_acme_manager_ensure(portico_acme_manager_t *m) { (void)m; return -1; }
int portico_acme_manager_challenge_port(const portico_acme_manager_t *m) { (void)m; return -1; }
void portico_acme_manager_stop(portico_acme_manager_t *m) { (void)m; }

#endif /* PORTICO_TLS */
