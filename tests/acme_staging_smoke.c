/* Drives the real RFC 8555 state machine against Let's Encrypt STAGING: fetch the
 * directory, register a throwaway account, place an order, and read back the http-01
 * challenge token for each authorization — proving JWS signing, nonce handling,
 * account registration and order placement all work against the actual CA.
 *
 * Challenge VALIDATION + finalize need the token served on a PUBLIC :80, so they are
 * exercised in the end-to-end task, not here. Self-skips unless PORTICO_ACME_STAGING
 * is set (this hits the network and creates a staging account each run). */
#include "acme_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STAGING_DIR "https://acme-staging-v02.api.letsencrypt.org/directory"

int main(void) {
    if (!getenv("PORTICO_ACME_STAGING")) {
        printf("acme staging smoke: SKIPPED "
               "(set PORTICO_ACME_STAGING=1 to run against Let's Encrypt staging)\n");
        return 0;
    }
    const char *domain = getenv("PORTICO_ACME_DOMAIN");
    if (!domain) domain = "smoke.portico-acme-test.net";   /* any non-special name; not validated here */

    /* Fresh account key per run (new staging account, no state carried over). */
    char keypath[] = "/tmp/acme_smoke_keyXXXXXX";
    int fd = mkstemp(keypath);
    if (fd >= 0) close(fd);
    unlink(keypath);

    portico_acme_key_t *k = portico_acme_key_load_or_create(keypath);
    if (!k) { fprintf(stderr, "FAIL: no account key (built without TLS?)\n"); return 1; }
    portico_acme_session_t *s = portico_acme_session_new(k, STAGING_DIR, NULL);
    if (!s) { fprintf(stderr, "FAIL: session_new\n"); portico_acme_key_free(k); return 1; }

    int rc = 1;
    printf("== Let's Encrypt STAGING smoke (%s) ==\n", domain);

    /* Contact is optional; LE staging polices the email domain (rejects example.com),
     * so register without one unless a real address is supplied. */
    const char *email = getenv("PORTICO_ACME_EMAIL");
    if (portico_acme_connect(s, email) != 0) {
        fprintf(stderr, "FAIL: directory + newAccount\n"); goto out;
    }
    printf("ok   directory + newAccount  (account registered, kid established)\n");

    const char *doms[] = { domain };
    char order_url[2048], finalize_url[2048], authz[8][512];
    size_t nauthz = 0;
    if (portico_acme_order(s, doms, 1, order_url, sizeof order_url,
                           finalize_url, sizeof finalize_url, authz, 8, &nauthz) != 0) {
        fprintf(stderr, "FAIL: newOrder\n"); goto out;
    }
    printf("ok   newOrder                (%zu authorization(s))\n", nauthz);

    for (size_t i = 0; i < nauthz; i++) {
        char status[32], token[256], chal[2048], ka[512];
        if (portico_acme_http01(s, authz[i], status, sizeof status,
                                token, sizeof token, chal, sizeof chal) != 0) {
            fprintf(stderr, "FAIL: authz fetch\n"); goto out;
        }
        portico_acme_key_authz(k, token, ka, sizeof ka);
        printf("ok   authz[%zu] status=%s\n"
               "       token    = %s\n"
               "       key authz= %s\n"
               "       serve at   http://%s/.well-known/acme-challenge/%s\n",
               i, status, token, ka, domain, token);
    }

    printf("\nPASS — the live protocol works through account / order / authorization.\n"
           "       (validation + finalize need a public domain — see the e2e task.)\n");
    rc = 0;
out:
    portico_acme_session_free(s);
    portico_acme_key_free(k);
    unlink(keypath);
    return rc;
}
