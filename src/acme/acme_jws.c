/* ACME account key (EC P-256) + JWS/ES256 signing — the crypto every ACME POST is
 * wrapped in. The one subtlety that trips people up: JOSE ES256 signatures are the
 * raw fixed-width R||S (64 bytes), NOT OpenSSL's DER, so we convert. */
#include "acme_internal.h"

#include <stdio.h>

#ifdef PORTICO_TLS

#include "acme_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>

struct portico_acme_key { EVP_PKEY *pkey; };

portico_acme_key_t *portico_acme_key_load_or_create(const char *path) {
    EVP_PKEY *pkey = acme_pkey_load_or_create(path);
    if (!pkey) return NULL;
    portico_acme_key_t *k = calloc(1, sizeof *k);
    if (!k) { EVP_PKEY_free(pkey); return NULL; }
    k->pkey = pkey;
    return k;
}

void portico_acme_key_free(portico_acme_key_t *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    free(k);
}

/* Affine X,Y (32 bytes each) of the public point from the uncompressed encoding. */
static int pub_xy(EVP_PKEY *pkey, unsigned char x[32], unsigned char y[32]) {
    unsigned char pub[133]; size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub, &len) != 1)
        return -1;
    if (len != 65 || pub[0] != 0x04) return -1;   /* 0x04 || X(32) || Y(32) */
    memcpy(x, pub + 1, 32);
    memcpy(y, pub + 33, 32);
    return 0;
}

int portico_acme_jwk(const portico_acme_key_t *k, char *out, size_t cap) {
    unsigned char x[32], y[32];
    if (!k || pub_xy(k->pkey, x, y) != 0) return -1;
    char xb[64], yb[64];
    if (portico_b64url_encode(x, 32, xb, sizeof xb) < 0 ||
        portico_b64url_encode(y, 32, yb, sizeof yb) < 0) return -1;
    /* Members in lexicographic order (crv,kty,x,y), no whitespace — RFC 7638 §3.2. */
    int n = snprintf(out, cap, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

int portico_acme_thumbprint(const portico_acme_key_t *k, char *out, size_t cap) {
    char jwk[256];
    int jn = portico_acme_jwk(k, jwk, sizeof jwk);
    if (jn < 0) return -1;
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)jwk, (size_t)jn, h);
    return portico_b64url_encode(h, sizeof h, out, cap);
}

int portico_acme_jws(const portico_acme_key_t *k, const char *kid, const char *nonce,
                     const char *url, const char *payload, char *out, size_t cap) {
    if (!k || !nonce || !url) return -1;

    /* Protected header: kid (account URL) after registration, else the full jwk. */
    char prot[1536];
    int pn;
    if (kid) {
        pn = snprintf(prot, sizeof prot,
            "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}", kid, nonce, url);
    } else {
        char jwk[256];
        if (portico_acme_jwk(k, jwk, sizeof jwk) < 0) return -1;
        pn = snprintf(prot, sizeof prot,
            "{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}", jwk, nonce, url);
    }
    if (pn <= 0 || (size_t)pn >= sizeof prot) return -1;

    char prot_b[2048], pay_b[8192];
    size_t paylen = payload ? strlen(payload) : 0;
    if (portico_b64url_encode((const unsigned char *)prot, (size_t)pn, prot_b, sizeof prot_b) < 0) return -1;
    if (portico_b64url_encode((const unsigned char *)(payload ? payload : ""), paylen, pay_b, sizeof pay_b) < 0) return -1;

    /* Signing input is base64url(protected) "." base64url(payload). */
    char input[10752];
    int in = snprintf(input, sizeof input, "%s.%s", prot_b, pay_b);
    if (in <= 0 || (size_t)in >= sizeof input) return -1;

    /* ES256: ECDSA-P256-SHA256 → DER, then DER → raw R||S (each left-padded to 32). */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    unsigned char der[160]; size_t derlen = sizeof der;
    int ok = EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, k->pkey) == 1 &&
             EVP_DigestSign(md, der, &derlen, (const unsigned char *)input, (size_t)in) == 1;
    EVP_MD_CTX_free(md);
    if (!ok) return -1;

    const unsigned char *dp = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &dp, (long)derlen);
    if (!sig) return -1;
    const BIGNUM *r, *s; ECDSA_SIG_get0(sig, &r, &s);
    unsigned char raw[64];
    int rawok = BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(s, raw + 32, 32) == 32;
    ECDSA_SIG_free(sig);
    if (!rawok) return -1;

    char sig_b[128];
    if (portico_b64url_encode(raw, 64, sig_b, sizeof sig_b) < 0) return -1;

    int n = snprintf(out, cap,
        "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}", prot_b, pay_b, sig_b);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

#else  /* portico built without OpenSSL */

struct portico_acme_key { int unused; };
portico_acme_key_t *portico_acme_key_load_or_create(const char *path) { (void)path; return NULL; }
void portico_acme_key_free(portico_acme_key_t *k) { (void)k; }
int  portico_acme_jwk(const portico_acme_key_t *k, char *o, size_t c) { (void)k;(void)o;(void)c; return -1; }
int  portico_acme_thumbprint(const portico_acme_key_t *k, char *o, size_t c) { (void)k;(void)o;(void)c; return -1; }
int  portico_acme_jws(const portico_acme_key_t *k, const char *kid, const char *nonce,
                      const char *url, const char *payload, char *o, size_t c) {
    (void)k;(void)kid;(void)nonce;(void)url;(void)payload;(void)o;(void)c; return -1;
}

#endif /* PORTICO_TLS */
