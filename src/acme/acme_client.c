/* The RFC 8555 state machine — where the primitives (HTTPS client, JWS, CSR,
 * base64url, cJSON) become an actual ACME client talking to a CA.
 *
 * The flow: GET directory → register account (newAccount, sets the kid) → place an
 * order (newOrder) → for each identifier fetch its authorization, serve the http-01
 * key authorization, and tell the CA to validate → poll until valid → finalize with
 * the CSR → poll until issued → download the certificate chain.
 *
 * Every authenticated request is a JWS POST whose protected header carries a single-
 * use Replay-Nonce; we track the freshest nonce from each response and retry once on
 * the CA's badNonce. "POST-as-GET" (empty signed payload) is how RFC 8555 reads a
 * resource — there are no unauthenticated GETs past the directory. */
#include "acme_internal.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- JSON parsers (pure; no network/TLS — unit-tested offline) ------------- */

static const char *jstr(const cJSON *o, const char *key) {
    return cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, key));
}

int acme_parse_directory(const char *json, char *new_nonce, char *new_account,
                         char *new_order, size_t cap) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return -1;
    const char *a = jstr(j, "newNonce"), *b = jstr(j, "newAccount"), *c = jstr(j, "newOrder");
    int ok = a && b && c;
    if (ok) {
        snprintf(new_nonce, cap, "%s", a);
        snprintf(new_account, cap, "%s", b);
        snprintf(new_order, cap, "%s", c);
    }
    cJSON_Delete(j);
    return ok ? 0 : -1;
}

int acme_parse_order(const char *json, char *status, size_t sc,
                     char *finalize, size_t fc, char *certificate, size_t cc,
                     char authz[][512], size_t max_authz, size_t *n_authz) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return -1;
    const char *st = jstr(j, "status"), *fin = jstr(j, "finalize"), *cert = jstr(j, "certificate");
    if (st) snprintf(status, sc, "%s", st);
    if (finalize) finalize[0] = '\0';
    if (certificate) certificate[0] = '\0';
    if (fin && finalize) snprintf(finalize, fc, "%s", fin);
    if (cert && certificate) snprintf(certificate, cc, "%s", cert);   /* absent until issued */

    size_t n = 0;
    cJSON *auths = cJSON_GetObjectItemCaseSensitive(j, "authorizations"), *a;
    cJSON_ArrayForEach(a, auths) {
        const char *u = cJSON_GetStringValue(a);
        if (u && n < max_authz) snprintf(authz[n++], 512, "%s", u);
    }
    if (n_authz) *n_authz = n;
    cJSON_Delete(j);
    return st ? 0 : -1;
}

int acme_parse_authz(const char *json, char *status, size_t sc,
                     char *token, size_t tc, char *chal_url, size_t uc) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return -1;
    const char *st = jstr(j, "status");
    if (st) snprintf(status, sc, "%s", st);

    const char *tok = NULL, *url = NULL;
    cJSON *chs = cJSON_GetObjectItemCaseSensitive(j, "challenges"), *c;
    cJSON_ArrayForEach(c, chs) {
        const char *type = jstr(c, "type");
        if (type && strcmp(type, "http-01") == 0) { tok = jstr(c, "token"); url = jstr(c, "url"); break; }
    }
    int ok = st && tok && url;
    if (tok) snprintf(token, tc, "%s", tok);
    if (url) snprintf(chal_url, uc, "%s", url);
    cJSON_Delete(j);
    return ok ? 0 : -1;
}

/* token "." base64url(SHA-256(JWK)) — the bytes served for the http-01 challenge. */
int portico_acme_key_authz(const portico_acme_key_t *k, const char *token,
                           char *out, size_t cap) {
    char tp[128];
    if (!token || portico_acme_thumbprint(k, tp, sizeof tp) < 0) return -1;
    int n = snprintf(out, cap, "%s.%s", token, tp);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

#ifdef PORTICO_TLS

#include <unistd.h>   /* sleep */

#define ACME_MAX_DOMAINS 64

struct portico_acme_session {
    portico_acme_key_t *akey;      /* borrowed */
    const char *ca_file;           /* borrowed; NULL = system roots */
    char dir_url[1024];
    char new_nonce[1024], new_account[1024], new_order[1024];
    char nonce[256];               /* freshest Replay-Nonce */
    char kid[2048];                /* account URL, set after newAccount */
};

portico_acme_session_t *portico_acme_session_new(portico_acme_key_t *akey,
                                                 const char *directory_url,
                                                 const char *ca_file) {
    if (!akey || !directory_url) return NULL;
    portico_acme_session_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->akey = akey;
    s->ca_file = ca_file;
    snprintf(s->dir_url, sizeof s->dir_url, "%s", directory_url);
    return s;
}

void portico_acme_session_free(portico_acme_session_t *s) { free(s); }

/* "status" of an order/authorization response. */
static int json_status(const char *json, char *out, size_t cap) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return -1;
    const char *st = jstr(j, "status");
    if (st) snprintf(out, cap, "%s", st);
    cJSON_Delete(j);
    return st ? 0 : -1;
}

/* Fetch a fresh nonce (HEAD newNonce). */
static int get_nonce(portico_acme_session_t *s) {
    if (!s->new_nonce[0]) return -1;
    portico_http_response_t r;
    if (portico_https_request("HEAD", s->new_nonce, s->ca_file, NULL, NULL, 0, &r) != 0) return -1;
    int ok = r.nonce[0] != '\0';
    if (ok) snprintf(s->nonce, sizeof s->nonce, "%s", r.nonce);
    free(r.body);
    return ok ? 0 : -1;
}

/* JWS-sign `payload` (NULL/"" => POST-as-GET) and POST it to `url`, managing the
 * nonce and retrying once on a badNonce. resp is filled (caller frees resp->body). */
static int acme_post(portico_acme_session_t *s, const char *url, const char *payload,
                     portico_http_response_t *resp) {
    memset(resp, 0, sizeof *resp);
    resp->status = -1;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!s->nonce[0] && get_nonce(s) != 0) return -1;
        char jws[16384];
        const char *kid = s->kid[0] ? s->kid : NULL;
        if (portico_acme_jws(s->akey, kid, s->nonce, url, payload ? payload : "", jws, sizeof jws) < 0)
            return -1;
        s->nonce[0] = '\0';   /* the nonce is single-use; refresh from the response */
        free(resp->body); resp->body = NULL;
        if (portico_https_request("POST", url, s->ca_file,
                "Content-Type: application/jose+json\r\n", jws, strlen(jws), resp) != 0)
            return -1;
        if (resp->nonce[0]) snprintf(s->nonce, sizeof s->nonce, "%s", resp->nonce);
        if (resp->status == 400 && resp->body && strstr(resp->body, "badNonce") && attempt == 0)
            continue;   /* stale nonce — refreshed above, retry exactly once */
        return 0;
    }
    return 0;
}

int portico_acme_connect(portico_acme_session_t *s, const char *email) {
    /* Directory: the only unauthenticated request. */
    portico_http_response_t r;
    if (portico_https_request("GET", s->dir_url, s->ca_file, NULL, NULL, 0, &r) != 0) return -1;
    int ok = r.status == 200 && r.body &&
             acme_parse_directory(r.body, s->new_nonce, s->new_account, s->new_order,
                                  sizeof s->new_nonce) == 0;
    free(r.body);
    if (!ok) return -1;

    /* newAccount: jwk-signed (kid not yet known). 200 = existing, 201 = created;
     * either way the Location header is the account URL we sign under thereafter. */
    char payload[512];
    if (email && email[0])
        snprintf(payload, sizeof payload,
                 "{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:%s\"]}", email);
    else
        snprintf(payload, sizeof payload, "{\"termsOfServiceAgreed\":true}");

    if (acme_post(s, s->new_account, payload, &r) != 0) return -1;
    ok = (r.status == 200 || r.status == 201) && r.location[0];
    if (ok) snprintf(s->kid, sizeof s->kid, "%s", r.location);
    else if (r.body) fprintf(stderr, "acme: newAccount failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

int portico_acme_order(portico_acme_session_t *s, const char *const *domains, size_t n,
                       char *order_url, size_t ocap, char *finalize_url, size_t fcap,
                       char authz_urls[][512], size_t max_authz, size_t *n_authz) {
    if (n == 0) return -1;
    char ids[4096];
    int w = snprintf(ids, sizeof ids, "{\"identifiers\":[");
    size_t o = (w > 0) ? (size_t)w : 0;
    for (size_t i = 0; i < n; i++) {
        w = snprintf(ids + o, sizeof ids - o, "%s{\"type\":\"dns\",\"value\":\"%s\"}",
                     i ? "," : "", domains[i]);
        if (w < 0 || (size_t)w >= sizeof ids - o) return -1;
        o += (size_t)w;
    }
    w = snprintf(ids + o, sizeof ids - o, "]}");
    if (w < 0 || (size_t)w >= sizeof ids - o) return -1;

    portico_http_response_t r;
    if (acme_post(s, s->new_order, ids, &r) != 0) return -1;
    char status[32], cert[1024];
    int ok = r.status == 201 && r.body &&
             acme_parse_order(r.body, status, sizeof status, finalize_url, fcap,
                              cert, sizeof cert, authz_urls, max_authz, n_authz) == 0;
    if (ok && order_url) snprintf(order_url, ocap, "%s", r.location);
    if (!ok && r.body) fprintf(stderr, "acme: newOrder failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

int portico_acme_http01(portico_acme_session_t *s, const char *authz_url,
                        char *status, size_t sc, char *token, size_t tc,
                        char *chal_url, size_t uc) {
    portico_http_response_t r;
    if (acme_post(s, authz_url, "", &r) != 0) return -1;   /* POST-as-GET */
    int ok = r.status == 200 && r.body &&
             acme_parse_authz(r.body, status, sc, token, tc, chal_url, uc) == 0;
    if (!ok && r.body) fprintf(stderr, "acme: authz fetch failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

/* Tell the CA a challenge's response is in place (POST {} to the challenge url). */
static int challenge_ready(portico_acme_session_t *s, const char *chal_url) {
    portico_http_response_t r;
    if (acme_post(s, chal_url, "{}", &r) != 0) return -1;
    int ok = r.status == 200 || r.status == 202;
    if (!ok && r.body) fprintf(stderr, "acme: challenge trigger failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

/* Poll `url` (POST-as-GET) until its status reaches `want`, bounded by ~max_secs.
 * On success, hands the final body to *last_body (caller frees) when requested. */
static int poll_status(portico_acme_session_t *s, const char *url, const char *want,
                       int max_secs, char **last_body) {
    if (last_body) *last_body = NULL;
    for (int waited = 0; ; waited += 2) {
        portico_http_response_t r;
        if (acme_post(s, url, "", &r) != 0) return -1;
        char st[32] = "";
        if (r.status == 200 && r.body) json_status(r.body, st, sizeof st);
        if (strcmp(st, want) == 0) {
            if (last_body) *last_body = r.body; else free(r.body);
            return 0;
        }
        if (!strcmp(st, "invalid") || !strcmp(st, "deactivated") ||
            !strcmp(st, "revoked") || !strcmp(st, "expired")) {
            fprintf(stderr, "acme: %s reached terminal status '%s': %s\n",
                    url, st, r.body ? r.body : "");
            free(r.body);
            return -1;
        }
        free(r.body);
        if (waited >= max_secs) return -1;
        sleep(2);
    }
}

/* Finalize the order: POST the base64url CSR to its finalize URL. */
static int do_finalize(portico_acme_session_t *s, const char *finalize_url, const char *csr_b64) {
    char payload[8192];
    int w = snprintf(payload, sizeof payload, "{\"csr\":\"%s\"}", csr_b64);
    if (w < 0 || (size_t)w >= sizeof payload) return -1;
    portico_http_response_t r;
    if (acme_post(s, finalize_url, payload, &r) != 0) return -1;
    int ok = r.status == 200;
    if (!ok && r.body) fprintf(stderr, "acme: finalize failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

/* Download the issued chain (POST-as-GET); PEM into *pem (caller frees). */
static int download_cert(portico_acme_session_t *s, const char *cert_url, char **pem) {
    portico_http_response_t r;
    if (acme_post(s, cert_url, "", &r) != 0) return -1;
    int ok = r.status == 200 && r.body && r.body_len > 0;
    if (ok) { *pem = r.body; r.body = NULL; }
    else if (r.body) fprintf(stderr, "acme: cert download failed (%d): %s\n", r.status, r.body);
    free(r.body);
    return ok ? 0 : -1;
}

int portico_acme_obtain(const portico_acme_config_t *cfg,
                        const char *const *domains, size_t ndomains,
                        const char *cert_key_path, char **cert_pem) {
    if (!cfg || !cfg->directory_url || !cfg->account_key_path || !domains ||
        ndomains == 0 || ndomains > ACME_MAX_DOMAINS || !cert_key_path || !cert_pem)
        return -1;
    *cert_pem = NULL;

    portico_acme_key_t *akey = portico_acme_key_load_or_create(cfg->account_key_path);
    if (!akey) return -1;
    portico_acme_session_t *s = portico_acme_session_new(akey, cfg->directory_url, cfg->ca_file);
    if (!s) { portico_acme_key_free(akey); return -1; }

    int rc = -1;
    char order_url[2048] = "", finalize_url[2048] = "";
    char authz[ACME_MAX_DOMAINS][512];
    size_t nauthz = 0;
    char tokens[ACME_MAX_DOMAINS][256];
    size_t nprov = 0;
    char *order_body = NULL;

    if (portico_acme_connect(s, cfg->email) != 0) goto cleanup;
    if (portico_acme_order(s, domains, ndomains, order_url, sizeof order_url,
                           finalize_url, sizeof finalize_url, authz, ACME_MAX_DOMAINS, &nauthz) != 0)
        goto cleanup;

    /* Provision + trigger validation for every still-pending authorization. */
    for (size_t i = 0; i < nauthz; i++) {
        char status[32], token[256], chal[2048];
        if (portico_acme_http01(s, authz[i], status, sizeof status,
                                token, sizeof token, chal, sizeof chal) != 0)
            goto cleanup;
        if (strcmp(status, "valid") == 0) continue;   /* already authorized (cached) */
        char keyauth[512];
        if (portico_acme_key_authz(akey, token, keyauth, sizeof keyauth) < 0) goto cleanup;
        if (cfg->provision) cfg->provision(token, keyauth, cfg->ud);
        snprintf(tokens[nprov++], 256, "%s", token);
        if (challenge_ready(s, chal) != 0) goto cleanup;
    }

    /* Wait for the CA to validate every authorization. */
    for (size_t i = 0; i < nauthz; i++)
        if (poll_status(s, authz[i], "valid", 120, NULL) != 0) goto cleanup;

    /* Finalize with the CSR, wait for issuance, fetch the chain. */
    {
        char csr[8192];
        if (portico_acme_make_csr(cert_key_path, domains, ndomains, csr, sizeof csr) < 0) goto cleanup;
        if (do_finalize(s, finalize_url, csr) != 0) goto cleanup;
        if (poll_status(s, order_url, "valid", 120, &order_body) != 0) goto cleanup;

        char st[32], fin[2048], cert_url[2048];
        size_t dummy;
        if (acme_parse_order(order_body, st, sizeof st, fin, sizeof fin,
                             cert_url, sizeof cert_url, authz, ACME_MAX_DOMAINS, &dummy) != 0 ||
            !cert_url[0])
            goto cleanup;
        if (download_cert(s, cert_url, cert_pem) != 0) goto cleanup;
    }
    rc = 0;

cleanup:
    for (size_t i = 0; i < nprov; i++)
        if (cfg->unprovision) cfg->unprovision(tokens[i], cfg->ud);
    free(order_body);
    portico_acme_session_free(s);
    portico_acme_key_free(akey);
    return rc;
}

#else  /* portico built without OpenSSL — the flow needs the verifying HTTPS client */

portico_acme_session_t *portico_acme_session_new(portico_acme_key_t *akey,
                                                 const char *directory_url, const char *ca_file) {
    (void)akey; (void)directory_url; (void)ca_file; return NULL;
}
void portico_acme_session_free(portico_acme_session_t *s) { (void)s; }
int portico_acme_connect(portico_acme_session_t *s, const char *email) { (void)s; (void)email; return -1; }
int portico_acme_order(portico_acme_session_t *s, const char *const *d, size_t n,
                       char *ou, size_t oc, char *fu, size_t fc,
                       char au[][512], size_t ma, size_t *na) {
    (void)s;(void)d;(void)n;(void)ou;(void)oc;(void)fu;(void)fc;(void)au;(void)ma;(void)na; return -1;
}
int portico_acme_http01(portico_acme_session_t *s, const char *au, char *st, size_t sc,
                        char *tk, size_t tc, char *cu, size_t uc) {
    (void)s;(void)au;(void)st;(void)sc;(void)tk;(void)tc;(void)cu;(void)uc; return -1;
}
int portico_acme_obtain(const portico_acme_config_t *cfg, const char *const *domains,
                        size_t ndomains, const char *cert_key_path, char **cert_pem) {
    (void)cfg;(void)domains;(void)ndomains;(void)cert_key_path;
    if (cert_pem) *cert_pem = NULL;
    return -1;
}

#endif /* PORTICO_TLS */
