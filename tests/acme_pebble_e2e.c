/* Full ACME issuance against a local CA (Pebble): drive the manager end-to-end —
 * account → order → HTTP-01 validation (Pebble's VA fetches the token from our
 * responder) → finalize(CSR) → download the chain → write to disk — then VERIFY the
 * issued certificate. This is the first exercise of the back half of the client
 * (finalize / poll-order / download / chain) that the public staging CA couldn't
 * reach without a public domain. Driven by tests/acme_pebble_test.sh, which stands
 * up Pebble + challtestsrv; this binary just needs the env it sets. */
#include "acme_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static int chk(const char *n, int c) { printf("  %-5s %s\n", c ? "ok" : "FAIL", n); return c; }

int main(void) {
    const char *dir = getenv("PEBBLE_DIR");
    const char *ca  = getenv("PEBBLE_CA");
    const char *domain = getenv("PEBBLE_DOMAIN");
    if (!dir || !ca || !domain) {
        fprintf(stderr, "need PEBBLE_DIR / PEBBLE_CA / PEBBLE_DOMAIN in the environment\n");
        return 2;
    }
    int port = getenv("PEBBLE_CHALLENGE_PORT") ? atoi(getenv("PEBBLE_CHALLENGE_PORT")) : 5002;

    char tmp[] = "/tmp/pebble_e2eXXXXXX";
    if (!mkdtemp(tmp)) { perror("mkdtemp"); return 2; }
    char cert[300], key[300], acct[300];
    snprintf(cert, sizeof cert, "%s/cert.pem", tmp);
    snprintf(key,  sizeof key,  "%s/cert.key", tmp);
    snprintf(acct, sizeof acct, "%s/acct.key", tmp);

    const char *doms[] = { domain };
    portico_acme_manager_config_t cfg = {
        .directory_url    = dir,
        .account_key_path = acct,
        .cert_path        = cert,
        .cert_key_path    = key,
        .ca_file          = ca,            /* trust Pebble's test root for the API TLS */
        .domains          = doms,
        .ndomains         = 1,
        .challenge_port   = port,          /* where Pebble's VA fetches the token */
        .renew_within_days = 30,
        .check_interval_secs = 999999,     /* don't auto-renew mid-test */
    };

    printf("== Pebble end-to-end (%s) ==\n", domain);
    printf("issuing via %s, serving HTTP-01 on :%d ...\n", dir, port);
    portico_acme_manager_t *m = portico_acme_manager_start(&cfg);

    int fails = 0;
    if (!chk("full ACME loop issued a certificate", m != NULL)) {
        rmdir(tmp);
        return 1;   /* the script will dump pebble's log */
    }

    FILE *f = fopen(cert, "r");
    X509 *x = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    fails += !chk("issued cert parses (PEM chain on disk)", x != NULL);

    if (x) {
        BIO *b = BIO_new(BIO_s_mem());
        X509_print_ex(b, x, 0, 0);
        char *txt = NULL; long tl = BIO_get_mem_data(b, &txt);
        char want[320]; snprintf(want, sizeof want, "DNS:%s", domain);
        fails += !chk("cert SAN carries the requested domain",
                      txt && memmem(txt, (size_t)tl, want, strlen(want)) != NULL);
        fails += !chk("cert is CA-signed (subject != issuer)",
                      X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) != 0);
        BIO_free(b);

        EVP_PKEY *cpk = X509_get_pubkey(x);
        FILE *kf = fopen(key, "r");
        EVP_PKEY *dk = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
        if (kf) fclose(kf);
        fails += !chk("issued cert matches the saved certificate key",
                      cpk && dk && EVP_PKEY_eq(cpk, dk) == 1);
        EVP_PKEY_free(cpk); EVP_PKEY_free(dk);
        X509_free(x);
    }

    portico_acme_manager_stop(m);
    unlink(cert); unlink(key); unlink(acct); rmdir(tmp);

    printf("\n%s\n", fails ? "FAIL"
        : "PASS — issued, validated (HTTP-01), finalized, downloaded, and verified.");
    return fails ? 1 : 0;
}
