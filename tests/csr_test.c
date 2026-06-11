/* Certificate key + CSR. Builds a CSR for several domains, decodes the base64url
 * back to DER, parses it as PKCS#10, VERIFIES its signature (the "openssl req
 * -verify" check), asserts every domain is present as a SAN, and confirms the cert
 * key was persisted (0600) and reused. No network. */
#include "acme_internal.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-40s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}
static int contains(const char *h, long hl, const char *n) {
    return memmem(h, (size_t)hl, n, strlen(n)) != NULL;
}

int main(void) {
    printf("== ACME certificate key + CSR ==\n");

    /* Fresh path so make_csr creates the key itself (tests its 0600). */
    char kp[] = "/tmp/acme_certXXXXXX";
    int fd = mkstemp(kp); close(fd); unlink(kp);

    const char *doms[] = { "a.example.com", "b.example.com", "www.a.example.com" };
    char csr[8192];
    int n = portico_acme_make_csr(kp, doms, 3, csr, sizeof csr);
    chk("CSR built (base64url)", n > 0, NULL);

    unsigned char der[8192];
    int dl = portico_b64url_decode(csr, (size_t)(n > 0 ? n : 0), der, sizeof der);
    chk("CSR base64url decodes", dl > 0, NULL);

    const unsigned char *dp = der;
    X509_REQ *req = (dl > 0) ? d2i_X509_REQ(NULL, &dp, dl) : NULL;
    chk("CSR parses as PKCS#10", req != NULL, NULL);

    EVP_PKEY *pub = req ? X509_REQ_get_pubkey(req) : NULL;
    chk("CSR signature verifies", req && pub && X509_REQ_verify(req, pub) == 1, NULL);

    /* SAN list via the printed CSR. */
    BIO *b = BIO_new(BIO_s_mem());
    if (req) X509_REQ_print_ex(b, req, 0, 0);
    char *txt = NULL; long tl = BIO_get_mem_data(b, &txt);
    chk("CSR carries all 3 SANs",
        txt && contains(txt, tl, "DNS:a.example.com") &&
        contains(txt, tl, "DNS:b.example.com") &&
        contains(txt, tl, "DNS:www.a.example.com"), NULL);
    BIO_free(b);

    /* Key persisted with private-key perms and reused by the CSR. */
    struct stat st;
    chk("cert key persisted at 0600",
        stat(kp, &st) == 0 && (st.st_mode & 0777) == 0600, NULL);
    FILE *f = fopen(kp, "r");
    EVP_PKEY *fromfile = f ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    chk("CSR uses the persisted cert key", fromfile && pub && EVP_PKEY_eq(fromfile, pub) == 1, NULL);

    EVP_PKEY_free(pub); EVP_PKEY_free(fromfile); X509_REQ_free(req); unlink(kp);
    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
