/* Test helper: do one HTTPS request with portico's verifying client and print the
 * outcome. Exit 0 if the HTTP exchange completed (cert verified), 2 if it failed
 * (transport / TLS verify). Used by https_client_test.sh.
 *   https_probe METHOD URL [ca_file]    (empty ca_file => system roots) */
#include "acme_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: https_probe METHOD URL [ca_file]\n"); return 64; }
    const char *ca = (argc > 3 && argv[3][0]) ? argv[3] : NULL;

    portico_http_response_t r;
    int rc = portico_https_request(argv[1], argv[2], ca, NULL, NULL, 0, &r);
    printf("rc=%d status=%d ct=%s bodylen=%zu\n",
           rc, r.status, r.content_type[0] ? r.content_type : "-", r.body_len);
    if (r.body && r.body_len) {
        char *nl = strchr(r.body, '\n'); if (nl) *nl = '\0';
        printf("body1=%.100s\n", r.body);
    }
    free(r.body);
    return rc == 0 ? 0 : 2;
}
