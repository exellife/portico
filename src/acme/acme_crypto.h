/* Internal OpenSSL helpers shared by the ACME crypto units (acme_jws.c, acme_csr.c).
 * Only included by files compiled with PORTICO_TLS — keeps OpenSSL out of the
 * OpenSSL-free acme_internal.h (which non-TLS test units include). */
#ifndef PORTICO_ACME_CRYPTO_H
#define PORTICO_ACME_CRYPTO_H

#include <openssl/evp.h>

/* Load the EC P-256 private key PEM at `path`, or generate one and save it there
 * (0600). Returns an EVP_PKEY (caller EVP_PKEY_free) or NULL. path may be NULL to
 * generate an unsaved ephemeral key. */
EVP_PKEY *acme_pkey_load_or_create(const char *path);

#endif /* PORTICO_ACME_CRYPTO_H */
