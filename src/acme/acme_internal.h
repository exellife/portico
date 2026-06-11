/* ============================================================================
 * portico ACME client — internal helpers (not a public header).
 *
 * Built bottom-up: this file accumulates the primitives the RFC 8555 flow needs.
 * First up: base64url, the encoding used throughout ACME/JWS.
 * ============================================================================ */
#ifndef PORTICO_ACME_INTERNAL_H
#define PORTICO_ACME_INTERNAL_H

#include <stddef.h>

/* base64url (RFC 4648 §5): the base64 alphabet with '-'/'_' and NO '=' padding.
 *
 * encode: write `len` bytes of `in` as a NUL-terminated base64url string into
 * `out` (needs up to 4*ceil(len/3)+1 bytes). Returns the string length (excluding
 * the NUL), or -1 if `out` is too small.
 *
 * decode: decode `len` chars of `in` into `out`. Returns the byte count, or -1 on
 * invalid input (bad char, length ≡ 1 mod 4, '+'/'/'/'=' present) or short `out`. */
int portico_b64url_encode(const unsigned char *in, size_t len, char *out, size_t outcap);
int portico_b64url_decode(const char *in, size_t len, unsigned char *out, size_t outcap);

#endif /* PORTICO_ACME_INTERNAL_H */
