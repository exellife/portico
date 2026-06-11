/* Shared EC P-256 key load-or-create (account key and certificate key both use it). */
#include "acme_internal.h"

#ifdef PORTICO_TLS

#include "acme_crypto.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

EVP_PKEY *acme_pkey_load_or_create(const char *path) {
    EVP_PKEY *pkey = NULL;
    FILE *f = path ? fopen(path, "r") : NULL;
    if (f) { pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); }
    if (pkey) return pkey;

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!c) return NULL;
    if (EVP_PKEY_keygen_init(c) == 1 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_X9_62_prime256v1) == 1)
        EVP_PKEY_keygen(c, &pkey);
    EVP_PKEY_CTX_free(c);
    if (!pkey) return NULL;

    if (path) {   /* persist with private-key perms */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            FILE *w = fdopen(fd, "w");
            if (w) { PEM_write_PrivateKey(w, pkey, NULL, NULL, 0, NULL, NULL); fclose(w); }
            else close(fd);
        }
    }
    return pkey;
}

#endif /* PORTICO_TLS */
