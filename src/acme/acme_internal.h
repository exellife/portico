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

/* HTTP-01 key authorization: token "." base64url(SHA-256(JWK)) — the exact bytes
 * served at /.well-known/acme-challenge/<token>. Writes NUL-terminated; returns
 * length or -1. */
int portico_acme_key_authz(const portico_acme_key_t *k, const char *token,
                           char *out, size_t cap);

/* ---- ACME JSON document parsers (cJSON; pure, no network — unit-tested) -------
 * Each extracts the fields the state machine needs from a server response body.
 * Strings are written NUL-terminated into caller buffers; return 0 / -1. */

/* Directory: the resource URLs. */
int acme_parse_directory(const char *json, char *new_nonce, char *new_account,
                         char *new_order, size_t cap);

/* Order: status, the finalize URL, the certificate URL (empty until issued), and
 * the authorization URLs (filled into `authz`, count into `n_authz`). */
int acme_parse_order(const char *json, char *status, size_t sc,
                     char *finalize, size_t fc, char *certificate, size_t cc,
                     char authz[][512], size_t max_authz, size_t *n_authz);

/* Authorization: status + the http-01 challenge's token and url. */
int acme_parse_authz(const char *json, char *status, size_t sc,
                     char *token, size_t tc, char *chal_url, size_t uc);

/* ---- the RFC 8555 state machine -------------------------------------------
 * A session ties an account key to a directory + trust store and tracks the
 * Replay-Nonce and account `kid` across the flow. The steps are exposed so the
 * staging smoke can drive account/order/authz directly; portico_acme_obtain()
 * composes them into a full issuance. */
typedef struct portico_acme_session portico_acme_session_t;

/* `akey`, `ca_file` and `directory_url` are borrowed (caller keeps them alive and
 * owns akey). `ca_file` NULL verifies against the system roots. */
portico_acme_session_t *portico_acme_session_new(portico_acme_key_t *akey,
                                                 const char *directory_url,
                                                 const char *ca_file);
void portico_acme_session_free(portico_acme_session_t *s);

/* Fetch the directory and register/look-up the account (sets the kid every later
 * request is signed under). `email` is an optional contact. Returns 0 / -1. */
int portico_acme_connect(portico_acme_session_t *s, const char *email);

/* Place a newOrder for `domains`; fills the order URL, finalize URL and the per-
 * domain authorization URLs. Returns 0 / -1. */
int portico_acme_order(portico_acme_session_t *s, const char *const *domains, size_t n,
                       char *order_url, size_t ocap, char *finalize_url, size_t fcap,
                       char authz_urls[][512], size_t max_authz, size_t *n_authz);

/* Fetch one authorization (POST-as-GET); returns its status and http-01 token+url. */
int portico_acme_http01(portico_acme_session_t *s, const char *authz_url,
                        char *status, size_t sc, char *token, size_t tc,
                        char *chal_url, size_t uc);

/* Provisioning bridge to the HTTP-01 responder: serve `keyauth` at the well-known
 * path for `token` until unprovisioned. */
typedef struct {
    const char *directory_url;      /* ACME directory (staging/production) */
    const char *account_key_path;   /* account key PEM (load or create) */
    const char *email;              /* optional contact, may be NULL */
    const char *ca_file;            /* NULL = system roots */
    void (*provision)(const char *token, const char *keyauth, void *ud);
    void (*unprovision)(const char *token, void *ud);
    void *ud;
} portico_acme_config_t;

/* Full issuance for `domains`: returns the certificate chain (PEM, malloc'd into
 * *cert_pem — caller frees) and writes/uses the certificate key at `cert_key_path`.
 * Returns 0 / -1. */
int portico_acme_obtain(const portico_acme_config_t *cfg,
                        const char *const *domains, size_t ndomains,
                        const char *cert_key_path, char **cert_pem);

/* ---- HTTP-01 challenge responder ------------------------------------------
 * The CA validates by fetching http://<domain>/.well-known/acme-challenge/<token>
 * (plaintext :80, always). This is NOT a separate server: it's a thread-safe
 * token→keyauth store plus the matcher portico's own :80 dispatch calls. A tiny
 * standalone listener is provided for the certbot-`--standalone` case (no portico
 * in front) and to test the route in isolation. Plaintext only — no TLS, no JSON. */
typedef struct portico_acme_responder portico_acme_responder_t;

portico_acme_responder_t *portico_acme_responder_new(void);
void portico_acme_responder_free(portico_acme_responder_t *r);

/* Register / tear down a challenge response (thread-safe). The signatures match the
 * obtain() provision/unprovision callbacks — wire them with the responder as `ud`. */
void portico_acme_responder_provision(const char *token, const char *keyauth, void *ud);
void portico_acme_responder_unprovision(const char *token, void *ud);

/* The matcher portico's plaintext dispatch calls. If `path` is a well-known ACME
 * challenge path whose token is provisioned, copies the key authorization into `out`
 * and returns its length; returns -1 otherwise (not ours, or unknown token). */
int portico_acme_responder_lookup(portico_acme_responder_t *r, const char *path,
                                  char *out, size_t cap);

/* Standalone mode: bind 0.0.0.0:<port> (80 in production; 0 = ephemeral) and serve
 * challenge paths from a background thread. Returns the bound port (>0) or -1.
 * Used only when portico isn't already fronting :80. */
int  portico_acme_responder_listen(portico_acme_responder_t *r, int port);
void portico_acme_responder_stop(portico_acme_responder_t *r);

/* ---- certificate expiry + the issue/renew manager -------------------------
 * Ties the pieces together: keep a current certificate on disk for `domains`,
 * serving HTTP-01 challenges on its OWN plaintext listener (a sidecar alongside
 * portico's TLS listener — no core surgery), and renew before expiry, signalling
 * the app to hot-reload via a callback. The callback keeps the dependency arrow
 * one-way (portico → portico_acme): the manager never calls into the server, the
 * app wires on_renewed to ws_server_reload_tls(). */

/* Whole days until the leaf cert in the PEM at `cert_path` expires (negative if
 * already expired), or -1 if the file is missing / unreadable / unparseable. */
int portico_acme_cert_days_left(const char *cert_path);

/* True if that cert is missing, unparseable, expired, or within `renew_within_days`
 * of expiry — i.e. it should be (re)issued now. */
int portico_acme_cert_needs_renewal(const char *cert_path, int renew_within_days);

typedef struct {
    const char        *directory_url;      /* ACME directory (staging/production) */
    const char        *account_key_path;   /* account key PEM (load or create) */
    const char        *cert_path;          /* issued chain (PEM) is written here */
    const char        *cert_key_path;      /* certificate key is written here */
    const char        *email;              /* optional contact */
    const char        *ca_file;            /* NULL = system roots; set for Pebble */
    const char *const *domains;            /* borrowed; caller keeps it alive */
    size_t             ndomains;
    int                renew_within_days;   /* renew when fewer days remain (0 ⇒ 30) */
    int                challenge_port;      /* 80 in production; 0 ⇒ ephemeral (tests) */
    int                check_interval_secs; /* renewal poll period (0 ⇒ 12h) */
    void             (*on_renewed)(void *ud);   /* fired after a successful (re)issue */
    void              *ud;
} portico_acme_manager_config_t;

typedef struct portico_acme_manager portico_acme_manager_t;

/* Bring up the HTTP-01 responder, ensure a current cert exists NOW (issuing
 * synchronously if it is missing/expiring), then start the background renewal
 * thread. Returns the manager, or NULL (e.g. issuance was needed and failed). */
portico_acme_manager_t *portico_acme_manager_start(const portico_acme_manager_config_t *cfg);

/* One pass: (re)issue if the cert needs renewal — serving challenges, writing
 * cert+key to disk, firing on_renewed — else leave it. 1 = reissued, 0 = still
 * current, -1 = error. Run by start() and the renewal thread; safe to call too. */
int portico_acme_manager_ensure(portico_acme_manager_t *m);

/* The plaintext port the responder bound (useful when challenge_port was 0). */
int portico_acme_manager_challenge_port(const portico_acme_manager_t *m);

void portico_acme_manager_stop(portico_acme_manager_t *m);

#endif /* PORTICO_ACME_INTERNAL_H */
