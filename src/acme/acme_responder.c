/* HTTP-01 challenge responder. The CA validates control by fetching, in plaintext
 * over :80, http://<domain>/.well-known/acme-challenge/<token>, expecting the key
 * authorization back. This module is NOT a second web server: at its core it is a
 * thread-safe token→keyauth store plus a one-line matcher that portico's own :80
 * request dispatch calls (the integration point). The optional standalone listener
 * wrapping it covers the "nothing else on :80" case (à la certbot --standalone) and
 * lets the route be tested in isolation. Plaintext only — no TLS, no JSON. */
#include "acme_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <netinet/in.h>

#define RESP_MAX_SLOTS 64
#define CHALLENGE_PREFIX "/.well-known/acme-challenge/"

struct resp_slot { int used; char token[256]; char keyauth[512]; };

struct portico_acme_responder {
    pthread_mutex_t mu;
    struct resp_slot slots[RESP_MAX_SLOTS];
    /* standalone listener (optional) */
    int       listen_fd;
    int       stop_fd;    /* eventfd to unblock the accept loop on stop */
    pthread_t thread;
    int       running;
};

portico_acme_responder_t *portico_acme_responder_new(void) {
    portico_acme_responder_t *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    pthread_mutex_init(&r->mu, NULL);
    r->listen_fd = r->stop_fd = -1;
    return r;
}

/* ---- token store ---------------------------------------------------------- */

void portico_acme_responder_provision(const char *token, const char *keyauth, void *ud) {
    portico_acme_responder_t *r = ud;
    if (!r || !token || !keyauth) return;
    pthread_mutex_lock(&r->mu);
    int slot = -1;
    for (int i = 0; i < RESP_MAX_SLOTS; i++) {
        if (r->slots[i].used && strcmp(r->slots[i].token, token) == 0) { slot = i; break; }
        if (!r->slots[i].used && slot < 0) slot = i;   /* first free, as a fallback */
    }
    if (slot >= 0) {
        r->slots[slot].used = 1;
        snprintf(r->slots[slot].token,   sizeof r->slots[slot].token,   "%s", token);
        snprintf(r->slots[slot].keyauth, sizeof r->slots[slot].keyauth, "%s", keyauth);
    }
    pthread_mutex_unlock(&r->mu);
}

void portico_acme_responder_unprovision(const char *token, void *ud) {
    portico_acme_responder_t *r = ud;
    if (!r || !token) return;
    pthread_mutex_lock(&r->mu);
    for (int i = 0; i < RESP_MAX_SLOTS; i++)
        if (r->slots[i].used && strcmp(r->slots[i].token, token) == 0) r->slots[i].used = 0;
    pthread_mutex_unlock(&r->mu);
}

int portico_acme_responder_lookup(portico_acme_responder_t *r, const char *path,
                                  char *out, size_t cap) {
    if (!r || !path) return -1;
    if (strncmp(path, CHALLENGE_PREFIX, sizeof CHALLENGE_PREFIX - 1) != 0) return -1;
    const char *token = path + (sizeof CHALLENGE_PREFIX - 1);
    if (*token == '\0') return -1;

    int n = -1;
    pthread_mutex_lock(&r->mu);
    for (int i = 0; i < RESP_MAX_SLOTS; i++) {
        if (r->slots[i].used && strcmp(r->slots[i].token, token) == 0) {
            int w = snprintf(out, cap, "%s", r->slots[i].keyauth);
            if (w > 0 && (size_t)w < cap) n = w;
            break;
        }
    }
    pthread_mutex_unlock(&r->mu);
    return n;
}

/* ---- standalone listener -------------------------------------------------- */

static void send_all(int fd, const char *buf, size_t len) {
    for (size_t off = 0; off < len; ) {
        ssize_t k = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (k <= 0) return;
        off += (size_t)k;
    }
}

/* Read one request, answer the challenge path with the keyauth (200), else 404. */
static void handle_conn(portico_acme_responder_t *r, int c) {
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    char buf[4096]; size_t len = 0;
    while (len < sizeof buf - 1) {
        ssize_t k = recv(c, buf + len, sizeof buf - 1 - len, 0);
        if (k <= 0) break;
        len += (size_t)k; buf[len] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;   /* end of request headers */
    }
    buf[len] = '\0';

    char path[2048];
    if (sscanf(buf, "GET %2047s", path) != 1) {
        const char *bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(c, bad, strlen(bad));
        return;
    }
    char *q = strchr(path, '?'); if (q) *q = '\0';   /* drop any query string */

    char keyauth[512];
    int n = portico_acme_responder_lookup(r, path, keyauth, sizeof keyauth);
    if (n < 0) {
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(c, nf, strlen(nf));
        return;
    }
    char head[256];
    int hn = snprintf(head, sizeof head,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n", n);
    send_all(c, head, (size_t)hn);
    send_all(c, keyauth, (size_t)n);
}

static void *serve_thread(void *arg) {
    portico_acme_responder_t *r = arg;
    for (;;) {
        struct pollfd p[2] = {
            { .fd = r->listen_fd, .events = POLLIN },
            { .fd = r->stop_fd,   .events = POLLIN },
        };
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (p[1].revents & POLLIN) break;            /* stop requested */
        if (p[0].revents & POLLIN) {
            int c = accept(r->listen_fd, NULL, NULL);
            if (c < 0) continue;
            handle_conn(r, c);
            close(c);
        }
    }
    return NULL;
}

int portico_acme_responder_listen(portico_acme_responder_t *r, int port) {
    if (!r || r->running) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0) { close(fd); return -1; }

    socklen_t al = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &al) != 0) { close(fd); return -1; }
    int bound = ntohs(a.sin_port);

    int ev = eventfd(0, EFD_NONBLOCK);
    if (ev < 0) { close(fd); return -1; }

    r->listen_fd = fd; r->stop_fd = ev; r->running = 1;
    if (pthread_create(&r->thread, NULL, serve_thread, r) != 0) {
        close(fd); close(ev);
        r->listen_fd = r->stop_fd = -1; r->running = 0;
        return -1;
    }
    return bound;
}

void portico_acme_responder_stop(portico_acme_responder_t *r) {
    if (!r || !r->running) return;
    uint64_t one = 1;
    if (write(r->stop_fd, &one, sizeof one) < 0) { /* thread will still exit on close */ }
    pthread_join(r->thread, NULL);
    close(r->listen_fd); close(r->stop_fd);
    r->listen_fd = r->stop_fd = -1; r->running = 0;
}

void portico_acme_responder_free(portico_acme_responder_t *r) {
    if (!r) return;
    if (r->running) portico_acme_responder_stop(r);
    pthread_mutex_destroy(&r->mu);
    free(r);
}
