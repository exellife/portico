/* JSON config-file loader — see include/portico_config.h and
 * docs/portico-config-design.md. Parses + validates a deployment config into
 * owned ws_config_t + portico_vhost_t[] structures. cJSON-backed; no other module
 * touches a config file. */
#include "portico_config.h"

#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define ACME_DEFAULT_DIRECTORY "https://acme-v02.api.letsencrypt.org/directory"

struct portico_config {
    ws_config_t             ws;
    portico_vhost_t        *vhosts;     size_t nvhosts;
    ws_tls_sni_cert_t      *sni;        size_t nsni;     /* ws.tls_sni_certs points here */
    const char            **domains;    size_t ndomains; /* site hosts (SAN set) */
    portico_tls_mode_t      tls_mode;
    portico_acme_settings_t acme;

    /* Ownership: every string exposed above is registered here and freed en masse. */
    char  **owned;  size_t nowned, cap_owned;
};

/* ---- string ownership -------------------------------------------------------- */

/* strdup `s` into the config's owned set and return the copy (NULL-safe → NULL).
 * Returns NULL on OOM too; callers treat that as "absent". */
static const char *own(portico_config_t *c, const char *s) {
    if (!s) return NULL;
    if (c->nowned == c->cap_owned) {
        size_t ncap = c->cap_owned ? c->cap_owned * 2 : 16;
        char **n = realloc(c->owned, ncap * sizeof *n);
        if (!n) return NULL;
        c->owned = n; c->cap_owned = ncap;
    }
    char *dup = strdup(s);
    if (!dup) return NULL;
    c->owned[c->nowned++] = dup;
    return dup;
}

/* ---- small cJSON helpers ----------------------------------------------------- */

static const char *jstr(const cJSON *o, const char *k) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}
static int jint(const cJSON *o, const char *k, int def) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(v) ? v->valueint : def;
}
static int jbool(const cJSON *o, const char *k, int def) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsBool(v)) return cJSON_IsTrue(v) ? 1 : 0;
    return def;
}

/* ---- validation helpers ------------------------------------------------------ */

static int is_dir(const char *p) {
    struct stat st;
    return p && stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}
static int is_readable(const char *p) { return p && access(p, R_OK) == 0; }

#define FAIL(...) do { if (err) snprintf(err, errcap, __VA_ARGS__); goto fail; } while (0)

/* ---- file slurp -------------------------------------------------------------- */

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

/* ---- the load ---------------------------------------------------------------- */

portico_config_t *portico_config_load(const char *path, char *err, size_t errcap) {
    cJSON *root = NULL;
    portico_config_t *c = NULL;

    char *text = read_file(path);
    if (!text) { if (err) snprintf(err, errcap, "cannot read config file '%s'", path ? path : "(null)"); return NULL; }

    root = cJSON_Parse(text);
    free(text);
    if (!root) { if (err) snprintf(err, errcap, "invalid JSON in config"); return NULL; }

    c = calloc(1, sizeof *c);
    if (!c) FAIL("out of memory");
    ws_get_default_config(&c->ws);

    /* listen */
    const cJSON *listen = cJSON_GetObjectItemCaseSensitive(root, "listen");
    if (listen) {
        int port = jint(listen, "port", c->ws.port);
        if (port < 1 || port > 65535) FAIL("listen.port out of range (1-65535): %d", port);
        c->ws.port = (uint16_t)port;
        int threads = jint(listen, "threads", (int)c->ws.thread_count);
        if (threads < 0) FAIL("listen.threads must be >= 0");
        c->ws.thread_count = (uint32_t)threads;
        const char *bind = jstr(listen, "bind");
        if (bind) c->ws.bind_address = own(c, bind);
    }

    c->ws.trust_proxy = jbool(root, "trust_proxy", c->ws.trust_proxy);

    /* tls */
    c->tls_mode = PORTICO_TLS_OFF;
    const cJSON *tls = cJSON_GetObjectItemCaseSensitive(root, "tls");
    if (tls) {
        const char *mode = jstr(tls, "mode");
        if (!mode || strcmp(mode, "off") == 0)        c->tls_mode = PORTICO_TLS_OFF;
        else if (strcmp(mode, "files") == 0)          c->tls_mode = PORTICO_TLS_FILES;
        else if (strcmp(mode, "acme") == 0)           c->tls_mode = PORTICO_TLS_ACME;
        else FAIL("tls.mode must be one of off|files|acme (got '%s')", mode);

        if (c->tls_mode == PORTICO_TLS_FILES) {
            const char *cert = jstr(tls, "cert"), *key = jstr(tls, "key");
            if (!cert || !key) FAIL("tls.mode=files requires tls.cert and tls.key");
            if (!is_readable(cert)) FAIL("tls.cert not readable: %s", cert);
            if (!is_readable(key))  FAIL("tls.key not readable: %s", key);
            c->ws.tls_cert_file = own(c, cert);
            c->ws.tls_key_file  = own(c, key);
        } else if (c->tls_mode == PORTICO_TLS_ACME) {
            const cJSON *a = cJSON_GetObjectItemCaseSensitive(tls, "acme");
            if (!a) FAIL("tls.mode=acme requires a tls.acme object");
            const char *dir = jstr(a, "directory");
            c->acme.directory_url    = own(c, dir ? dir : ACME_DEFAULT_DIRECTORY);
            c->acme.email            = own(c, jstr(a, "email"));
            c->acme.account_key_path = own(c, jstr(a, "account_key"));
            c->acme.cert_dir         = own(c, jstr(a, "cert_dir"));
            c->acme.ca_file          = own(c, jstr(a, "ca_file"));
            c->acme.renew_days       = jint(a, "renew_days", 0);
            c->acme.challenge_port   = jint(a, "challenge_port", 0);
            if (!c->acme.cert_dir)         FAIL("tls.acme.cert_dir is required");
            if (!c->acme.account_key_path) FAIL("tls.acme.account_key is required");
        }
    }

    /* sites */
    const cJSON *sites = cJSON_GetObjectItemCaseSensitive(root, "sites");
    if (sites && !cJSON_IsArray(sites)) FAIL("'sites' must be an array");
    size_t nsites = sites ? (size_t)cJSON_GetArraySize(sites) : 0;
    if (nsites == 0) FAIL("config has no sites");

    c->vhosts  = calloc(nsites, sizeof *c->vhosts);
    c->sni     = calloc(nsites, sizeof *c->sni);
    c->domains = calloc(nsites, sizeof *c->domains);
    if (!c->vhosts || !c->sni || !c->domains) FAIL("out of memory");

    int seen_fallback = 0;
    const cJSON *site;
    cJSON_ArrayForEach(site, sites) {
        if (!cJSON_IsObject(site)) FAIL("each site must be an object");
        const char *host = jstr(site, "host");   /* NULL/absent → fallback vhost */
        const cJSON *hostitem = cJSON_GetObjectItemCaseSensitive(site, "host");
        int is_fallback = (host == NULL);
        /* explicit null is a fallback; a non-string non-null host is an error */
        if (hostitem && !cJSON_IsString(hostitem) && !cJSON_IsNull(hostitem))
            FAIL("site.host must be a string or null");

        if (is_fallback) {
            if (seen_fallback) FAIL("more than one fallback site (host: null)");
            seen_fallback = 1;
        } else {
            for (size_t i = 0; i < c->nvhosts; i++)
                if (c->vhosts[i].host && strcasecmp(c->vhosts[i].host, host) == 0)
                    FAIL("duplicate site host '%s'", host);
        }

        const char *docroot = jstr(site, "docroot");
        if (!docroot)        FAIL("site '%s' missing docroot", is_fallback ? "(fallback)" : host);
        if (!is_dir(docroot)) FAIL("docroot is not a directory: %s", docroot);

        portico_vhost_t *v = &c->vhosts[c->nvhosts];
        v->host = is_fallback ? NULL : own(c, host);
        v->static_opts.docroot = own(c, docroot);

        const cJSON *s = cJSON_GetObjectItemCaseSensitive(site, "static");
        if (s) {
            v->static_opts.url_prefix    = own(c, jstr(s, "url_prefix"));
            v->static_opts.index         = own(c, jstr(s, "index"));
            v->static_opts.cache_control = own(c, jstr(s, "cache_control"));
            v->static_opts.spa_fallback  = own(c, jstr(s, "spa_fallback"));
            v->static_opts.precompressed = jbool(s, "precompressed", 0);
            v->static_opts.dir_redirect  = jbool(s, "dir_redirect", 0);
        }
        c->nvhosts++;

        /* per-site TLS override → an SNI cert entry (only for named hosts) */
        const cJSON *stls = cJSON_GetObjectItemCaseSensitive(site, "tls");
        if (stls) {
            if (is_fallback) FAIL("a fallback site cannot carry a per-site tls cert");
            const char *cert = jstr(stls, "cert"), *key = jstr(stls, "key");
            if (!cert || !key) FAIL("site '%s' tls override needs cert and key", host);
            if (!is_readable(cert)) FAIL("site '%s' tls.cert not readable: %s", host, cert);
            if (!is_readable(key))  FAIL("site '%s' tls.key not readable: %s", host, key);
            c->sni[c->nsni].hostname  = own(c, host);
            c->sni[c->nsni].cert_file = own(c, cert);
            c->sni[c->nsni].key_file  = own(c, key);
            c->nsni++;
        }

        if (!is_fallback) c->domains[c->ndomains++] = own(c, host);
    }

    if (c->nsni) {
        c->ws.tls_sni_certs      = c->sni;
        c->ws.tls_sni_cert_count = c->nsni;
    }

    cJSON_Delete(root);
    return c;

fail:
    cJSON_Delete(root);
    portico_config_free(c);
    return NULL;
}

void portico_config_free(portico_config_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->nowned; i++) free(c->owned[i]);
    free(c->owned);
    free(c->vhosts);
    free(c->sni);
    free(c->domains);
    free(c);
}

/* ---- views ------------------------------------------------------------------- */

const ws_config_t *portico_config_ws(const portico_config_t *c) { return c ? &c->ws : NULL; }

const portico_vhost_t *portico_config_vhosts(const portico_config_t *c, size_t *n) {
    if (n) *n = c ? c->nvhosts : 0;
    return c ? c->vhosts : NULL;
}

portico_tls_mode_t portico_config_tls_mode(const portico_config_t *c) {
    return c ? c->tls_mode : PORTICO_TLS_OFF;
}
const portico_acme_settings_t *portico_config_acme(const portico_config_t *c) {
    return c ? &c->acme : NULL;
}
const char *const *portico_config_acme_domains(const portico_config_t *c, size_t *n) {
    if (n) *n = c ? c->ndomains : 0;
    return c ? c->domains : NULL;
}
