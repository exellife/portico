/* ACME account key + JWS/ES256. Security-sensitive, so: a fixed-key known-answer
 * vector for the JWK + RFC 7638 thumbprint (the thumbprint was cross-checked against
 * an independent Python computation), key persistence, and — since ECDSA is
 * randomized — the JWS signature is VERIFIED cryptographically rather than compared
 * to fixed bytes. No network. */
#include "acme_internal.h"
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-42s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* Fixed P-256 key + its known JWK / thumbprint (thumbprint verified via Python). */
static const char FIXED_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpoogQwFwW1iadghi\n"
    "dhZwPwMrtwRwXV5sYQZntm0kl0WhRANCAAShH8ioYCzF2v34VGG94KKSpT1SXCgP\n"
    "TA3qnf3D2uGw6+SP3AjMOBs1rTPYD9olLo4qAmLkbS8tpYjSe3ky3wlx\n"
    "-----END PRIVATE KEY-----\n";
static const char FIXED_JWK[] =
    "{\"crv\":\"P-256\",\"kty\":\"EC\","
    "\"x\":\"oR_IqGAsxdr9-FRhveCikqU9UlwoD0wN6p39w9rhsOs\","
    "\"y\":\"5I_cCMw4GzWtM9gP2iUujioCYuRtLy2liNJ7eTLfCXE\"}";
static const char FIXED_TP[] = "LINke8XMexxWudLhTGE-DQ829qvbs3X1RCAbY7CENDo";

static char *write_temp(const char *s) {
    char *p = strdup("/tmp/acme_jwsXXXXXX");
    int fd = mkstemp(p);
    if (fd < 0) { free(p); return NULL; }
    if (write(fd, s, strlen(s)) < 0) { /* ignore */ }
    close(fd);
    return p;
}

/* Verify a flattened JWS object's ES256 signature against `pub`. */
static int verify_jws(const char *jws_json, EVP_PKEY *pub) {
    cJSON *j = cJSON_Parse(jws_json);
    if (!j) return 0;
    const char *prot = cJSON_GetStringValue(cJSON_GetObjectItem(j, "protected"));
    const char *pay  = cJSON_GetStringValue(cJSON_GetObjectItem(j, "payload"));
    const char *sig  = cJSON_GetStringValue(cJSON_GetObjectItem(j, "signature"));
    int v = 0;
    if (prot && pay && sig) {
        char input[16384];
        int in = snprintf(input, sizeof input, "%s.%s", prot, pay);
        unsigned char raw[64];
        if (portico_b64url_decode(sig, strlen(sig), raw, sizeof raw) == 64 && in > 0) {
            ECDSA_SIG *es = ECDSA_SIG_new();
            ECDSA_SIG_set0(es, BN_bin2bn(raw, 32, NULL), BN_bin2bn(raw + 32, 32, NULL));
            unsigned char der[160], *dp = der;
            int dl = i2d_ECDSA_SIG(es, &dp);
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            if (dl > 0 && EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pub) == 1)
                v = EVP_DigestVerify(md, der, (size_t)dl, (const unsigned char *)input, (size_t)in) == 1;
            EVP_MD_CTX_free(md);
            ECDSA_SIG_free(es);
        }
    }
    cJSON_Delete(j);
    return v;
}

/* Decode a JWS member's base64url into a NUL-terminated buffer. */
static void decode_member(const char *jws, const char *member, char *out, size_t cap) {
    out[0] = '\0';
    cJSON *j = cJSON_Parse(jws);
    const char *b = j ? cJSON_GetStringValue(cJSON_GetObjectItem(j, member)) : NULL;
    if (b) {
        int n = portico_b64url_decode(b, strlen(b), (unsigned char *)out, cap - 1);
        out[n > 0 ? n : 0] = '\0';
    }
    cJSON_Delete(j);
}

int main(void) {
    printf("== ACME account key + JWS/ES256 ==\n");

    char *kp = write_temp(FIXED_PEM);
    portico_acme_key_t *k = portico_acme_key_load_or_create(kp);
    chk("load fixed key", k != NULL, NULL);

    char jwk[256]; portico_acme_jwk(k, jwk, sizeof jwk);
    chk("JWK == known-answer", strcmp(jwk, FIXED_JWK) == 0, jwk);
    char tp[64]; portico_acme_thumbprint(k, tp, sizeof tp);
    chk("thumbprint == known-answer (RFC 7638)", strcmp(tp, FIXED_TP) == 0, tp);

    /* Persistence: a fresh path generates a key; reloading the same path yields it. */
    { char *p2 = strdup("/tmp/acme_persXXXXXX"); int fd = mkstemp(p2); close(fd); unlink(p2);
      portico_acme_key_t *a = portico_acme_key_load_or_create(p2);  /* generates + saves */
      char ta[64]; portico_acme_thumbprint(a, ta, sizeof ta);
      portico_acme_key_t *b = portico_acme_key_load_or_create(p2);  /* loads the saved key */
      char tb[64]; portico_acme_thumbprint(b, tb, sizeof tb);
      chk("persisted key reloads identically", strcmp(ta, tb) == 0, NULL);
      portico_acme_key_free(a); portico_acme_key_free(b); unlink(p2); free(p2); }

    /* Independent public key (from the same PEM) for signature verification. */
    FILE *f = fopen(kp, "r");
    EVP_PKEY *pub = f ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);

    /* JWS with the full jwk (newAccount style). */
    char jws[4096], dec[1024];
    int jn = portico_acme_jws(k, NULL, "nonce123", "https://acme.example/new-order",
                              "{\"x\":1}", jws, sizeof jws);
    chk("jws built (jwk mode)", jn > 0, NULL);
    chk("jws signature verifies (ES256)", verify_jws(jws, pub), NULL);
    decode_member(jws, "protected", dec, sizeof dec);
    chk("protected: ES256 + jwk + nonce + url, no kid",
        strstr(dec, "\"alg\":\"ES256\"") && strstr(dec, "\"jwk\"") &&
        strstr(dec, "nonce123") && strstr(dec, "new-order") && !strstr(dec, "\"kid\""), dec);
    decode_member(jws, "payload", dec, sizeof dec);
    chk("payload round-trips", strcmp(dec, "{\"x\":1}") == 0, dec);

    /* JWS with kid (every request after registration); empty payload = POST-as-GET. */
    jn = portico_acme_jws(k, "https://acme.example/acct/1", "n2",
                          "https://acme.example/order/9", "", jws, sizeof jws);
    chk("kid jws signature verifies", verify_jws(jws, pub), NULL);
    decode_member(jws, "protected", dec, sizeof dec);
    chk("kid mode: has kid, no jwk", strstr(dec, "\"kid\"") && !strstr(dec, "\"jwk\""), dec);

    EVP_PKEY_free(pub); portico_acme_key_free(k); unlink(kp); free(kp);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
