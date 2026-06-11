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

/* ---- minimal verifying HTTPS client (blocking) -----------------------------
 * ACME is low-volume request/response, so this is a plain blocking client run
 * from the renewal context, NOT the async event loop. It VERIFIES the peer (chain
 * + hostname) — we are authenticating Let's Encrypt. */
typedef struct {
    int    status;             /* HTTP status, or -1 on transport/TLS/verify failure */
    char  *body;               /* malloc'd, NUL-terminated (caller frees); NULL if none */
    size_t body_len;
    char   nonce[256];         /* Replay-Nonce header value, "" if absent */
    char   location[2048];     /* Location header value, "" if absent */
    char   content_type[128];  /* Content-Type header value, "" if absent */
} portico_http_response_t;

/* Perform one HTTPS request. `method` is "GET"/"POST"/"HEAD"; `url` a full
 * https:// URL. `ca_file` NULL verifies against the system root CAs, else trusts
 * that PEM only (pinning / tests). `headers` is extra "Name: value\r\n" lines or
 * NULL; `body`/`body_len` the request body (NULL for none). The peer certificate
 * is verified (chain AND hostname); on failure the call returns -1. Returns 0 on a
 * completed HTTP exchange (inspect resp->status) or -1 on transport/verify error.
 * Caller frees resp->body. */
int portico_https_request(const char *method, const char *url, const char *ca_file,
                          const char *headers, const void *body, size_t body_len,
                          portico_http_response_t *resp);

/* ---- account key + JWS (ES256) — the crypto every ACME POST is wrapped in ----
 * The account key is an EC P-256 key (OpenSSL 3.0+); persisted so the account is
 * registered once. Signatures use ES256 (ECDSA P-256 + SHA-256) in the JOSE raw
 * R||S form, NOT DER. */
typedef struct portico_acme_key portico_acme_key_t;   /* opaque (wraps EVP_PKEY) */

/* Load the account key PEM from `path`, or generate a new P-256 key and save it
 * there (0600). Returns the key (free with portico_acme_key_free) or NULL. */
portico_acme_key_t *portico_acme_key_load_or_create(const char *path);
void                portico_acme_key_free(portico_acme_key_t *k);

/* Canonical JWK JSON for the public key — {"crv":"P-256","kty":"EC","x":..,"y":..}
 * (members lexicographically ordered, no whitespace — also the thumbprint input).
 * Writes NUL-terminated into `out`; returns length or -1. */
int portico_acme_jwk(const portico_acme_key_t *k, char *out, size_t cap);

/* RFC 7638 JWK thumbprint: base64url(SHA-256(canonical JWK)). The key half of the
 * HTTP-01 key authorization. Writes NUL-terminated into `out`; returns length / -1. */
int portico_acme_thumbprint(const portico_acme_key_t *k, char *out, size_t cap);

/* Flattened JWS (RFC 7515) signing `payload` (NUL-terminated JSON, or "" for
 * POST-as-GET). The protected header carries alg=ES256, the given `nonce` and
 * `url`, and identifies the key by `kid` (account URL) when non-NULL, else by the
 * full `jwk` (newAccount uses jwk; everything afterward uses kid). Writes the JWS
 * JSON object into `out`; returns length or -1. */
int portico_acme_jws(const portico_acme_key_t *k, const char *kid, const char *nonce,
                     const char *url, const char *payload, char *out, size_t cap);

/* ---- certificate key + CSR -------------------------------------------------
 * Generate/persist the CERTIFICATE key (EC P-256, 0600) at `key_path` and build a
 * PKCS#10 CSR for `domains` carrying them as Subject Alternative Names (mandatory —
 * browsers ignore the CN), DER-encoded then base64url for the ACME finalize step.
 * Writes the base64url CSR into `out`; returns length or -1. */
int portico_acme_make_csr(const char *key_path, const char *const *domains,
                          size_t ndomains, char *out, size_t cap);

#endif /* PORTICO_ACME_INTERNAL_H */
