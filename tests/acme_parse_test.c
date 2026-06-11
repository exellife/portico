/* ACME JSON document parsers — the directory, order and authorization responses the
 * state machine consumes — plus the http-01 key authorization. Pure and offline:
 * fixtures shaped like real Let's Encrypt responses, no network. */
#include "acme_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-44s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* Real-shaped LE staging directory (extra members present, order shuffled). */
static const char *DIRECTORY =
    "{\"keyChange\":\"https://acme-staging-v02.api.letsencrypt.org/acme/key-change\","
    "\"newAccount\":\"https://acme-staging-v02.api.letsencrypt.org/acme/new-acct\","
    "\"newNonce\":\"https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce\","
    "\"newOrder\":\"https://acme-staging-v02.api.letsencrypt.org/acme/new-order\","
    "\"revokeCert\":\"https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert\","
    "\"meta\":{\"termsOfService\":\"https://example/tos\",\"website\":\"https://letsencrypt.org\"}}";

/* A freshly-created order: pending, two identifiers => two authorizations, finalize
 * present, certificate absent. */
static const char *ORDER_PENDING =
    "{\"status\":\"pending\",\"expires\":\"2026-06-12T00:00:00Z\","
    "\"identifiers\":[{\"type\":\"dns\",\"value\":\"a.example.com\"},"
                     "{\"type\":\"dns\",\"value\":\"b.example.com\"}],"
    "\"authorizations\":[\"https://acme/authz/AAA\",\"https://acme/authz/BBB\"],"
    "\"finalize\":\"https://acme/finalize/9/42\"}";

/* The same order after issuance: valid, certificate URL now present. */
static const char *ORDER_VALID =
    "{\"status\":\"valid\",\"finalize\":\"https://acme/finalize/9/42\","
    "\"certificate\":\"https://acme/cert/ff00\","
    "\"authorizations\":[\"https://acme/authz/AAA\"]}";

/* An authorization carrying all three challenge types; only http-01 is ours. */
static const char *AUTHZ =
    "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a.example.com\"},"
    "\"challenges\":["
      "{\"type\":\"dns-01\",\"url\":\"https://acme/chal/dns\",\"token\":\"DNSTOKEN\"},"
      "{\"type\":\"http-01\",\"url\":\"https://acme/chal/http\",\"token\":\"HTTP-TOKEN-xyz\",\"status\":\"pending\"},"
      "{\"type\":\"tls-alpn-01\",\"url\":\"https://acme/chal/alpn\",\"token\":\"ALPNTOKEN\"}]}";

int main(void) {
    printf("== ACME document parsers ==\n");

    /* Directory. */
    char nn[256], na[256], no[256];
    chk("directory parses", acme_parse_directory(DIRECTORY, nn, na, no, 256) == 0, NULL);
    chk("  newNonce url", strcmp(nn, "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce") == 0, NULL);
    chk("  newAccount url", strcmp(na, "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct") == 0, NULL);
    chk("  newOrder url", strcmp(no, "https://acme-staging-v02.api.letsencrypt.org/acme/new-order") == 0, NULL);
    chk("directory missing a field => -1",
        acme_parse_directory("{\"newNonce\":\"x\",\"newOrder\":\"y\"}", nn, na, no, 256) == -1, NULL);

    /* Pending order: status, finalize, two authz, no certificate. */
    char st[32], fin[256], cert[256], authz[8][512]; size_t n = 0;
    chk("pending order parses",
        acme_parse_order(ORDER_PENDING, st, sizeof st, fin, sizeof fin, cert, sizeof cert, authz, 8, &n) == 0, NULL);
    chk("  status=pending", strcmp(st, "pending") == 0, NULL);
    chk("  finalize url", strcmp(fin, "https://acme/finalize/9/42") == 0, NULL);
    chk("  certificate empty (not issued)", cert[0] == '\0', NULL);
    chk("  2 authorizations", n == 2, NULL);
    chk("  authz[0]", strcmp(authz[0], "https://acme/authz/AAA") == 0, NULL);
    chk("  authz[1]", strcmp(authz[1], "https://acme/authz/BBB") == 0, NULL);

    /* Valid order: certificate URL appears. */
    chk("valid order parses",
        acme_parse_order(ORDER_VALID, st, sizeof st, fin, sizeof fin, cert, sizeof cert, authz, 8, &n) == 0, NULL);
    chk("  status=valid", strcmp(st, "valid") == 0, NULL);
    chk("  certificate url", strcmp(cert, "https://acme/cert/ff00") == 0, NULL);

    /* Authorization: must select http-01 out of three challenge types. */
    char astatus[32], token[256], chal[256];
    chk("authz parses, picks http-01",
        acme_parse_authz(AUTHZ, astatus, sizeof astatus, token, sizeof token, chal, sizeof chal) == 0, NULL);
    chk("  status=pending", strcmp(astatus, "pending") == 0, NULL);
    chk("  http-01 token", strcmp(token, "HTTP-TOKEN-xyz") == 0, NULL);
    chk("  http-01 url", strcmp(chal, "https://acme/chal/http") == 0, NULL);
    chk("authz with no http-01 => -1",
        acme_parse_authz("{\"status\":\"pending\",\"challenges\":[{\"type\":\"dns-01\",\"url\":\"u\",\"token\":\"t\"}]}",
                         astatus, sizeof astatus, token, sizeof token, chal, sizeof chal) == -1, NULL);

    /* Key authorization = token "." thumbprint. Needs a key (TLS build); skip if
     * portico was built without OpenSSL (load_or_create returns NULL there). */
    char kp[] = "/tmp/acme_ka_keyXXXXXX";
    int fd = mkstemp(kp); if (fd >= 0) close(fd); unlink(kp);
    portico_acme_key_t *k = portico_acme_key_load_or_create(kp);
    if (k) {
        char tp[128];
        if (portico_acme_thumbprint(k, tp, sizeof tp) > 0) {
            char ka[512], expect[640];
            int kn = portico_acme_key_authz(k, "HTTP-TOKEN-xyz", ka, sizeof ka);
            snprintf(expect, sizeof expect, "HTTP-TOKEN-xyz.%s", tp);
            chk("key authz = token.thumbprint", kn > 0 && strcmp(ka, expect) == 0, NULL);
        }
        portico_acme_key_free(k);
        unlink(kp);
    } else {
        printf("  (key authorization check skipped — built without TLS)\n");
    }

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
