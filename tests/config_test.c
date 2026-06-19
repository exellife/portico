/* portico_config loader — parse + validation tests. Pure/offline: fixtures are
 * written to temp files (real docroots/certs created on the fly so the directory /
 * readable-file validation runs for real), no network, no server. */
#include "portico_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-46s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* ---- temp fixtures ---- */

static char *mk_dir(void) {
    static char tmpl[] = "/tmp/portico_cfg_dir_XXXXXX";
    char *t = malloc(sizeof tmpl);
    memcpy(t, tmpl, sizeof tmpl);
    return mkdtemp(t);   /* leaks on exit; fine for a test process */
}

static char *mk_file(const char *content) {
    static int seq = 0;
    char *p = malloc(64);
    snprintf(p, 64, "/tmp/portico_cfg_f_%d_%d", (int)getpid(), seq++);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(content, f); fclose(f); }
    return p;
}

/* Write `json` to a temp file and load it. err (if non-NULL) receives the reason. */
static portico_config_t *load_json(const char *json, char *err, size_t errcap) {
    char *path = mk_file(json);
    portico_config_t *c = portico_config_load(path, err, errcap);
    unlink(path);
    free(path);
    return c;
}

int main(void) {
    char *DR1 = mk_dir();   /* two real docroots */
    char *DR2 = mk_dir();
    char *CERT = mk_file("---cert---");   /* readable, content irrelevant to the loader */
    char *KEY  = mk_file("---key---");
    char buf[8192], err[256];

    printf("portico_config loader tests\n");

    /* 1. valid: named site + fallback, listen + static opts */
    snprintf(buf, sizeof buf,
        "{\"listen\":{\"port\":8443,\"threads\":3},\"trust_proxy\":true,"
        "\"sites\":["
        "{\"host\":\"a.com\",\"docroot\":\"%s\",\"static\":{"
            "\"precompressed\":true,\"cache_control\":\"no-cache\","
            "\"spa_fallback\":\"index.html\",\"dir_redirect\":true}},"
        "{\"host\":null,\"docroot\":\"%s\"}]}", DR1, DR2);
    err[0] = 0;
    portico_config_t *c = load_json(buf, err, sizeof err);
    chk("valid config loads", c != NULL, err);
    if (c) {
        const ws_config_t *ws = portico_config_ws(c);
        chk("port parsed",     ws->port == 8443, NULL);
        chk("threads parsed",  ws->thread_count == 3, NULL);
        chk("trust_proxy",     ws->trust_proxy == true, NULL);
        size_t n = 0;
        const portico_vhost_t *vh = portico_config_vhosts(c, &n);
        chk("two vhosts",      n == 2, NULL);
        chk("named host",      vh[0].host && strcmp(vh[0].host, "a.com") == 0, NULL);
        chk("docroot set",     vh[0].static_opts.docroot && strcmp(vh[0].static_opts.docroot, DR1) == 0, NULL);
        chk("precompressed",   vh[0].static_opts.precompressed == 1, NULL);
        chk("cache_control",   vh[0].static_opts.cache_control && strcmp(vh[0].static_opts.cache_control, "no-cache") == 0, NULL);
        chk("spa_fallback",    vh[0].static_opts.spa_fallback && strcmp(vh[0].static_opts.spa_fallback, "index.html") == 0, NULL);
        chk("dir_redirect",    vh[0].static_opts.dir_redirect == 1, NULL);
        chk("fallback host NULL", vh[1].host == NULL, NULL);
        size_t nd = 0;
        portico_config_acme_domains(c, &nd);
        chk("one acme domain (fallback excluded)", nd == 1, NULL);
        chk("tls mode off by default", portico_config_tls_mode(c) == PORTICO_TLS_OFF, NULL);
        portico_config_free(c);
    }

    /* 2. missing docroot */
    snprintf(buf, sizeof buf, "{\"sites\":[{\"host\":\"a.com\"}]}");
    chk("missing docroot rejected", load_json(buf, NULL, 0) == NULL, NULL);

    /* 3. docroot not a directory */
    snprintf(buf, sizeof buf, "{\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"}]}", CERT);
    chk("non-dir docroot rejected", load_json(buf, NULL, 0) == NULL, NULL);

    /* 4. duplicate host */
    snprintf(buf, sizeof buf,
        "{\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"},"
        "{\"host\":\"A.COM\",\"docroot\":\"%s\"}]}", DR1, DR2);
    chk("duplicate host rejected (case-insensitive)", load_json(buf, NULL, 0) == NULL, NULL);

    /* 5. two fallbacks */
    snprintf(buf, sizeof buf,
        "{\"sites\":[{\"host\":null,\"docroot\":\"%s\"},"
        "{\"host\":null,\"docroot\":\"%s\"}]}", DR1, DR2);
    chk("two fallbacks rejected", load_json(buf, NULL, 0) == NULL, NULL);

    /* 6. invalid JSON */
    chk("invalid JSON rejected", load_json("{ not json", NULL, 0) == NULL, NULL);

    /* 7. no sites */
    chk("empty sites rejected", load_json("{\"sites\":[]}", NULL, 0) == NULL, NULL);
    chk("missing sites rejected", load_json("{}", NULL, 0) == NULL, NULL);

    /* 8. tls files mode */
    snprintf(buf, sizeof buf,
        "{\"tls\":{\"mode\":\"files\",\"cert\":\"%s\",\"key\":\"%s\"},"
        "\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"}]}", CERT, KEY, DR1);
    err[0] = 0;
    c = load_json(buf, err, sizeof err);
    chk("tls files mode loads", c != NULL, err);
    if (c) {
        chk("mode is FILES", portico_config_tls_mode(c) == PORTICO_TLS_FILES, NULL);
        chk("default cert wired", portico_config_ws(c)->tls_cert_file != NULL, NULL);
        portico_config_free(c);
    }
    snprintf(buf, sizeof buf,
        "{\"tls\":{\"mode\":\"files\"},\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"}]}", DR1);
    chk("files mode without cert/key rejected", load_json(buf, NULL, 0) == NULL, NULL);

    /* 9. tls acme mode */
    snprintf(buf, sizeof buf,
        "{\"tls\":{\"mode\":\"acme\",\"acme\":{\"cert_dir\":\"%s\",\"account_key\":\"%s\"}},"
        "\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"}]}", DR2, KEY, DR1);
    err[0] = 0;
    c = load_json(buf, err, sizeof err);
    chk("tls acme mode loads", c != NULL, err);
    if (c) {
        chk("mode is ACME", portico_config_tls_mode(c) == PORTICO_TLS_ACME, NULL);
        const portico_acme_settings_t *a = portico_config_acme(c);
        chk("acme directory defaulted", a->directory_url && strstr(a->directory_url, "acme-v02") != NULL, NULL);
        portico_config_free(c);
    }
    snprintf(buf, sizeof buf,
        "{\"tls\":{\"mode\":\"acme\"},\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\"}]}", DR1);
    chk("acme mode without acme object rejected", load_json(buf, NULL, 0) == NULL, NULL);

    /* 10. per-site SNI override */
    snprintf(buf, sizeof buf,
        "{\"sites\":[{\"host\":\"a.com\",\"docroot\":\"%s\","
        "\"tls\":{\"cert\":\"%s\",\"key\":\"%s\"}}]}", DR1, CERT, KEY);
    err[0] = 0;
    c = load_json(buf, err, sizeof err);
    chk("per-site tls override loads", c != NULL, err);
    if (c) {
        const ws_config_t *ws = portico_config_ws(c);
        chk("one SNI cert wired", ws->tls_sni_cert_count == 1, NULL);
        chk("SNI hostname", ws->tls_sni_certs && ws->tls_sni_certs[0].hostname
                            && strcmp(ws->tls_sni_certs[0].hostname, "a.com") == 0, NULL);
        portico_config_free(c);
    }

    /* fixture cleanup (so the test itself is leak/tmp clean under LSan) */
    unlink(CERT); unlink(KEY); rmdir(DR1); rmdir(DR2);
    free(DR1); free(DR2); free(CERT); free(KEY);

    printf("\n%d ok, %d failed\n", ok, fail);
    return fail ? 1 : 0;
}
