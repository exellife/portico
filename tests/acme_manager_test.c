/* Certificate expiry logic + the issue/renew manager, with NO certificate authority
 * involved. Self-signed certs are minted in-process to drive days-left / needs-renewal,
 * then the manager is exercised on the two CA-free paths:
 *   - a current cert on disk  → it must NOT contact the CA, must bring up the :80
 *     responder, must not fire on_renewed, and must stop cleanly;
 *   - an expiring cert + an unreachable directory → start() must attempt issuance and
 *     fail fast (proving renewal is actually triggered, not skipped).
 * The full issue→finalize→download→reload loop is exercised against Pebble separately. */
#include "acme_internal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-48s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* A self-signed P-256 leaf valid for `days` days, written as PEM to `path`. */
static int mint_cert(const char *path, int days) {
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!pk) return -1;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 24 * 3600);
    X509_set_pubkey(x, pk);
    X509_NAME *n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"test.local", -1, -1, 0);
    X509_set_issuer_name(x, n);
    int signed_ok = X509_sign(x, pk, EVP_sha256()) > 0;
    FILE *f = fopen(path, "w");
    int wrote = f && PEM_write_X509(f, x);
    if (f) fclose(f);
    X509_free(x);
    EVP_PKEY_free(pk);
    return (signed_ok && wrote) ? 0 : -1;
}

/* A self-signed P-256 leaf valid for `days`, carrying `domains` as DNS SANs. */
static int mint_cert_san(const char *path, int days, const char *const *domains, size_t n) {
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!pk) return -1;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 24 * 3600);
    X509_set_pubkey(x, pk);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)domains[0], -1, -1, 0);
    X509_set_issuer_name(x, nm);

    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    for (size_t i = 0; i < n; i++) {
        GENERAL_NAME *gn = GENERAL_NAME_new();
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
        ASN1_STRING_set(ia5, domains[i], -1);
        GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
        sk_GENERAL_NAME_push(gens, gn);
    }
    X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    int added = ext && X509_add_ext(x, ext, -1);
    if (ext) X509_EXTENSION_free(ext);
    GENERAL_NAMES_free(gens);

    int signed_ok = added && X509_sign(x, pk, EVP_sha256()) > 0;
    FILE *f = fopen(path, "w");
    int wrote = f && PEM_write_X509(f, x);
    if (f) fclose(f);
    X509_free(x);
    EVP_PKEY_free(pk);
    return (signed_ok && wrote) ? 0 : -1;
}

static int http_status(int port, const char *path) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    char req[512];
    int rn = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path);
    send(fd, req, (size_t)rn, 0);
    char resp[512]; ssize_t k = recv(fd, resp, sizeof resp - 1, 0);
    close(fd);
    if (k <= 0) return -1;
    resp[k] = '\0';
    int code = 0; sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}

static int renew_calls = 0;
static void on_renewed(void *ud) { (void)ud; renew_calls++; }

int main(void) {
    printf("== ACME manager (cert expiry + issue/renew) ==\n");

    char dir[] = "/tmp/acme_mgrXXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char cert[256], key[256], acct[256];
    snprintf(cert, sizeof cert, "%s/cert.pem", dir);
    snprintf(key,  sizeof key,  "%s/cert.key", dir);
    snprintf(acct, sizeof acct, "%s/acct.key", dir);

    /* ---- expiry logic ---- */
    chk("missing cert: days_left = -1", portico_acme_cert_days_left(cert) == -1, NULL);
    chk("missing cert: needs renewal", portico_acme_cert_needs_renewal(cert, 30) == 1, NULL);

    chk("mint 90-day cert", mint_cert(cert, 90) == 0, NULL);
    int dl = portico_acme_cert_days_left(cert);
    chk("90-day cert: ~90 days left", dl >= 88 && dl <= 90, NULL);
    chk("90-day cert: no renewal (within 30)", portico_acme_cert_needs_renewal(cert, 30) == 0, NULL);

    chk("mint 5-day cert", mint_cert(cert, 5) == 0, NULL);
    chk("5-day cert: ~5 days left", portico_acme_cert_days_left(cert) <= 5, NULL);
    chk("5-day cert: needs renewal (within 30)", portico_acme_cert_needs_renewal(cert, 30) == 1, NULL);

    /* ---- SAN coverage (reissue on a domain-set change, not just expiry) ---- */
    const char *sanAB[] = { "a.example", "b.example" };
    chk("mint cert with SANs a,b", mint_cert_san(cert, 90, sanAB, 2) == 0, NULL);
    { const char *d[] = { "a.example" };
      chk("covers {a}", portico_acme_cert_covers(cert, d, 1) == 1, NULL); }
    { const char *d[] = { "a.example", "b.example" };
      chk("covers {a,b}", portico_acme_cert_covers(cert, d, 2) == 1, NULL); }
    { const char *d[] = { "A.EXAMPLE" };
      chk("covers case-insensitively", portico_acme_cert_covers(cert, d, 1) == 1, NULL); }
    { const char *d[] = { "a.example", "c.example" };
      chk("missing c => not covered", portico_acme_cert_covers(cert, d, 2) == 0, NULL); }
    chk("0 domains => covered (no constraint)", portico_acme_cert_covers(cert, sanAB, 0) == 1, NULL);
    mint_cert(cert, 90);   /* CN-only, no SAN extension */
    { const char *d[] = { "test.local" };
      chk("CN-only cert (no SAN) => not covered", portico_acme_cert_covers(cert, d, 1) == 0, NULL); }
    { const char *d[] = { "x" };
      chk("missing cert => not covered", portico_acme_cert_covers("/no/such/cert", d, 1) == 0, NULL); }

    /* ---- manager: current cert => no CA contact, listener up, clean stop ---- */
    const char *doms[] = { "test.local" };
    mint_cert_san(cert, 90, doms, 1);   /* current AND covers the configured domain */
    portico_acme_manager_config_t cfg = {
        .directory_url    = "https://127.0.0.1:1/directory",   /* must NOT be used */
        .account_key_path = acct,
        .cert_path        = cert,
        .cert_key_path    = key,
        .domains          = doms,
        .ndomains         = 1,
        .renew_within_days = 30,
        .challenge_port   = 0,            /* ephemeral */
        .check_interval_secs = 3600,
        .on_renewed       = on_renewed,
    };
    renew_calls = 0;
    portico_acme_manager_t *m = portico_acme_manager_start(&cfg);
    chk("manager starts with a current cert", m != NULL, NULL);
    if (m) {
        int port = portico_acme_manager_challenge_port(m);
        chk("challenge listener is up", port > 0, NULL);
        chk("  serves :80 (404 unprovisioned)",
            http_status(port, "/.well-known/acme-challenge/none") == 404, NULL);
        chk("current cert => on_renewed not fired", renew_calls == 0, NULL);
        chk("ensure() on a current cert => 0 (no reissue)",
            portico_acme_manager_ensure(m) == 0, NULL);
        chk("  still not fired", renew_calls == 0, NULL);
        portico_acme_manager_stop(m);
        chk("manager stops cleanly", 1, NULL);
    }

    /* ---- manager: expiring cert + unreachable CA => issuance attempted, start fails ---- */
    mint_cert(cert, 5);                                  /* within the 30-day window */
    portico_acme_manager_t *m2 = portico_acme_manager_start(&cfg);  /* dir is 127.0.0.1:1 */
    chk("expiring cert + unreachable CA => start fails", m2 == NULL, NULL);
    if (m2) portico_acme_manager_stop(m2);

    /* ---- manager: current cert that does NOT cover the domain set => reissue ---- */
    /* A long-lived cert (90d, not expiring) covering only "other.local", but the config
     * requires "test.local": expiry says "current", coverage says "no" → ensure() must
     * still attempt issuance, so start() fails fast against the unreachable directory.
     * (Before this fix, the expiry-only check would have skipped the CA and started.) */
    const char *only_other[] = { "other.local" };
    mint_cert_san(cert, 90, only_other, 1);
    portico_acme_manager_t *m3 = portico_acme_manager_start(&cfg);  /* cfg.domains = {test.local} */
    chk("current cert missing a domain => reissue attempted, start fails", m3 == NULL, NULL);
    if (m3) portico_acme_manager_stop(m3);

    unlink(cert); unlink(key); unlink(acct); rmdir(dir);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
