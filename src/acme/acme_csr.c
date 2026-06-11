/* Certificate key + PKCS#10 CSR for the ACME finalize step. The CSR lists the
 * domains as Subject Alternative Names (mandatory — browsers ignore the CN) and is
 * base64url(DER)-encoded as ACME requires. */
#include "acme_internal.h"

#ifdef PORTICO_TLS

#include "acme_crypto.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int portico_acme_make_csr(const char *key_path, const char *const *domains,
                          size_t ndomains, char *out, size_t cap) {
    if (!domains || ndomains == 0 || !out) return -1;
    EVP_PKEY *pkey = acme_pkey_load_or_create(key_path);
    if (!pkey) return -1;

    int rc = -1, derlen;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *san = NULL;
    unsigned char *der = NULL;
    char sanstr[4096];
    size_t o = 0;

    req = X509_REQ_new();
    if (!req || X509_REQ_set_version(req, 0) != 1 || X509_REQ_set_pubkey(req, pkey) != 1) goto done;

    /* Subject CN = first domain (the CA ignores it; a non-empty subject is tidy). */
    name = X509_NAME_new();
    if (!name) goto done;
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)domains[0], -1, -1, 0);
    if (X509_REQ_set_subject_name(req, name) != 1) goto done;

    /* subjectAltName from "DNS:a,DNS:b,...". */
    for (size_t i = 0; i < ndomains; i++) {
        int w = snprintf(sanstr + o, sizeof sanstr - o, "%sDNS:%s", i ? "," : "", domains[i]);
        if (w < 0 || (size_t)w >= sizeof sanstr - o) goto done;
        o += (size_t)w;
    }
    san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, sanstr);
    exts = sk_X509_EXTENSION_new_null();
    if (!san || !exts || sk_X509_EXTENSION_push(exts, san) <= 0) goto done;
    san = NULL;   /* owned by exts now */
    if (X509_REQ_add_extensions(req, exts) != 1) goto done;

    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) goto done;

    derlen = i2d_X509_REQ(req, &der);
    if (derlen <= 0) goto done;
    rc = portico_b64url_encode(der, (size_t)derlen, out, cap);

done:
    OPENSSL_free(der);
    if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (san) X509_EXTENSION_free(san);
    if (name) X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return rc;
}

#else  /* portico built without OpenSSL */

int portico_acme_make_csr(const char *key_path, const char *const *domains,
                          size_t ndomains, char *out, size_t cap) {
    (void)key_path; (void)domains; (void)ndomains; (void)out; (void)cap; return -1;
}

#endif /* PORTICO_TLS */
