/* HTTP-01 responder: the token→keyauth store, the well-known-path matcher portico's
 * dispatch calls, and the standalone :80 listener exercised over a real loopback HTTP
 * GET (the bytes the CA would fetch). All in-process — no curl, no external server. */
#include "acme_internal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-46s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* Minimal loopback HTTP GET; returns the raw response in `resp`. */
static int http_get(int port, const char *path, char *resp, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }

    char req[2200];
    int rn = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    send(fd, req, (size_t)rn, 0);

    size_t len = 0; ssize_t k;
    while (len < cap - 1 && (k = recv(fd, resp + len, cap - 1 - len, 0)) > 0) len += (size_t)k;
    resp[len] = '\0';
    close(fd);
    return (int)len;
}

int main(void) {
    printf("== ACME HTTP-01 responder ==\n");

    portico_acme_responder_t *r = portico_acme_responder_new();
    chk("responder created", r != NULL, NULL);

    const char *TOKEN = "tok-AbC123_xyz";
    const char *KEYAUTH = "tok-AbC123_xyz.JWK-thumbprint-here";
    char out[512];

    /* Store + matcher, before/after provisioning. */
    chk("unknown token => -1",
        portico_acme_responder_lookup(r, "/.well-known/acme-challenge/tok-AbC123_xyz", out, sizeof out) == -1, NULL);

    portico_acme_responder_provision(TOKEN, KEYAUTH, r);
    int n = portico_acme_responder_lookup(r, "/.well-known/acme-challenge/tok-AbC123_xyz", out, sizeof out);
    chk("provisioned token => keyauth", n == (int)strlen(KEYAUTH) && strcmp(out, KEYAUTH) == 0, NULL);

    chk("non-challenge path => -1",
        portico_acme_responder_lookup(r, "/index.html", out, sizeof out) == -1, NULL);
    chk("challenge path, wrong token => -1",
        portico_acme_responder_lookup(r, "/.well-known/acme-challenge/nope", out, sizeof out) == -1, NULL);
    chk("empty token => -1",
        portico_acme_responder_lookup(r, "/.well-known/acme-challenge/", out, sizeof out) == -1, NULL);

    portico_acme_responder_unprovision(TOKEN, r);
    chk("after unprovision => -1",
        portico_acme_responder_lookup(r, "/.well-known/acme-challenge/tok-AbC123_xyz", out, sizeof out) == -1, NULL);

    /* Standalone listener over real loopback HTTP — the bytes the CA fetches. */
    portico_acme_responder_provision(TOKEN, KEYAUTH, r);
    int port = portico_acme_responder_listen(r, 0);   /* ephemeral */
    chk("standalone listener bound", port > 0, NULL);

    if (port > 0) {
        char resp[2048];
        int got = http_get(port, "/.well-known/acme-challenge/tok-AbC123_xyz", resp, sizeof resp);
        chk("GET challenge => 200", got > 0 && strstr(resp, "HTTP/1.1 200") != NULL, NULL);
        const char *body = strstr(resp, "\r\n\r\n");
        chk("response body is the keyauth", body && strcmp(body + 4, KEYAUTH) == 0, NULL);
        chk("served octet-stream type", strstr(resp, "Content-Type: application/octet-stream") != NULL, NULL);

        got = http_get(port, "/.well-known/acme-challenge/wrong", resp, sizeof resp);
        chk("GET unknown token => 404", got > 0 && strstr(resp, "HTTP/1.1 404") != NULL, NULL);

        got = http_get(port, "/robots.txt", resp, sizeof resp);
        chk("GET non-challenge => 404", got > 0 && strstr(resp, "HTTP/1.1 404") != NULL, NULL);
    }

    portico_acme_responder_stop(r);
    /* free() must also be safe after an explicit stop, and on a never-listened one. */
    portico_acme_responder_free(r);
    portico_acme_responder_free(portico_acme_responder_new());

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
