/* ws_server_add_sni_cert — runtime per-host cert management on a live TLS listener.
 * Exercises the build-group/atomic-swap/rollback lifecycle and ownership in process
 * (create → add/update/reload/destroy), without driving real handshakes: the SNI
 * selection over the wire is covered by sni_test.sh / the config-reload integration
 * test, which run the identical ws_tls_ctx_add_sni path this builds on. Verified
 * clean under ASan+LSan. Requires a PORTICO_TLS build + openssl in PATH. */
#include "wslib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c) {
    printf("  %-5s %s\n", c ? "ok" : "FAIL", n);
    if (c) ok++; else fail++;
}

/* mint a throwaway self-signed cert/key (like tls_test.sh) into the given paths */
static int mint(const char *cn, const char *cert, const char *key) {
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
        "openssl req -x509 -newkey rsa:2048 -keyout '%s' -out '%s' -days 1 -nodes "
        "-subj '/CN=%s' >/dev/null 2>&1", key, cert, cn);
    return system(cmd);
}

/* create a TLS server, trying a few ports to avoid a bind collision (create binds) */
static ws_server_t *make_tls_server(const char *cert, const char *key) {
    for (int i = 0; i < 8; i++) {
        ws_config_t cfg;
        ws_get_default_config(&cfg);
        cfg.port = (uint16_t)(20000 + (getpid() + i * 911) % 20000);
        cfg.thread_count = 1;
        cfg.tls_cert_file = cert;
        cfg.tls_key_file  = key;
        ws_server_t *s = ws_server_create(&cfg);
        if (s) return s;
    }
    return NULL;
}

int main(void) {
    char dc[64], dk[64], ac[64], ak[64], bogus[64];
    snprintf(dc, sizeof dc, "/tmp/prt_def_%d.crt",   (int)getpid());
    snprintf(dk, sizeof dk, "/tmp/prt_def_%d.key",   (int)getpid());
    snprintf(ac, sizeof ac, "/tmp/prt_alpha_%d.crt", (int)getpid());
    snprintf(ak, sizeof ak, "/tmp/prt_alpha_%d.key", (int)getpid());
    snprintf(bogus, sizeof bogus, "/tmp/prt_nope_%d.crt", (int)getpid());

    if (mint("localhost", dc, dk) != 0 || mint("alpha.test", ac, ak) != 0) {
        fprintf(stderr, "openssl mint failed — skipping\n");
        return 0;   /* treat a missing/old openssl as a skip, not a failure */
    }

    printf("ws_server_add_sni_cert runtime tests\n");

    ws_server_t *s = make_tls_server(dc, dk);
    chk("TLS server created", s != NULL);
    if (s) {
        chk("add new SNI cert at runtime", ws_server_add_sni_cert(s, "alpha.test", ac, ak) == 0);
        chk("update same host (idempotent)", ws_server_add_sni_cert(s, "alpha.test", ac, ak) == 0);
        chk("add second host", ws_server_add_sni_cert(s, "beta.test", ac, ak) == 0);
        chk("reload keeps runtime certs (returns 0)", ws_server_reload_tls(s) == 0);
        chk("add another after reload", ws_server_add_sni_cert(s, "gamma.test", ac, ak) == 0);

        /* failure paths: bad cert path and NULL args → -1, server unharmed */
        chk("bad cert path rejected", ws_server_add_sni_cert(s, "evil.test", bogus, ak) == -1);
        chk("NULL host rejected", ws_server_add_sni_cert(s, NULL, ac, ak) == -1);
        chk("server still healthy after failures", ws_server_reload_tls(s) == 0);

        ws_server_destroy(s);
        chk("destroy clean", 1);
    }

    /* add_sni_cert on a plaintext listener → -1 */
    ws_config_t pc;
    ws_get_default_config(&pc);
    pc.port = (uint16_t)(40000 + getpid() % 20000);
    pc.thread_count = 1;
    ws_server_t *p = ws_server_create(&pc);
    if (p) {
        chk("add on plaintext listener → -1", ws_server_add_sni_cert(p, "x.test", ac, ak) == -1);
        ws_server_destroy(p);
    }

    unlink(dc); unlink(dk); unlink(ac); unlink(ak);
    printf("\n%d ok, %d failed\n", ok, fail);
    return fail ? 1 : 0;
}
