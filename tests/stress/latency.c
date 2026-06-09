/* portico latency benchmark — open-loop, coordinated-omission-corrected.
 *
 * Why a separate C tool (vs the Go loadtest): latency tails are destroyed by two
 * things a throughput test ignores —
 *   1. Coordinated omission: a closed-loop client (send, await reply, repeat)
 *      stops sending whenever the server stalls, so the backlog is never sampled
 *      and the tail looks far better than reality. We send at a FIXED rate on a
 *      schedule and measure each request from its INTENDED send time, so a stall
 *      shows up as elevated latency on every request queued behind it.
 *   2. GC jitter: a managed-runtime client injects pauses into the measurement.
 *      This is plain C with no allocation in the steady-state loop.
 *
 * Design: N connections, each with a writer thread (paces sends at rate/N and
 * records the intended send time in a per-connection SPSC ring) and a reader
 * thread (reads replies in order, pops the matching send time, records latency).
 * HTTP/1.1 and WS echo both preserve order, so FIFO matching is exact.
 *
 * Pin client and server to DISJOINT cores, e.g.:
 *   taskset -c 0-11  ./stress_server &
 *   taskset -c 12-27 ./latency -mode ws -conns 16 -rate 200000 -dur 20s
 *
 * Build: gcc -O2 -o /tmp/latency tests/stress/latency.c -lpthread
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- timing ---------------------------------------------------------------- */

static inline int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Sleep coarsely to ~60us before the deadline, then busy-spin to it. Keeps
 * pacing precise without burning a full core per writer. */
static void pace_until(int64_t deadline_ns) {
    int64_t t = now_ns();
    if (t >= deadline_ns) return;             /* already behind schedule */
    int64_t gap = deadline_ns - t;
    if (gap > 60000) {
        struct timespec req;
        int64_t wake = deadline_ns - 60000;
        req.tv_sec = wake / 1000000000LL;
        req.tv_nsec = wake % 1000000000LL;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
    }
    while (now_ns() < deadline_ns) { /* spin */ }
}

/* ---- latency histogram (1us buckets to 131ms + exact max) ------------------ */

#define HBUCKETS 131072            /* 0..131ms at 1us resolution */
typedef struct {
    uint64_t *b;
    uint64_t count, sum, max, overflow;
} hist_t;

static void hist_init(hist_t *h) {
    h->b = calloc(HBUCKETS, sizeof(uint64_t));
    h->count = h->sum = h->max = h->overflow = 0;
}
static void hist_add(hist_t *h, int64_t ns) {
    int64_t us = ns / 1000;
    if (us < 0) us = 0;
    h->count++;
    h->sum += (uint64_t)us;
    if ((uint64_t)us > h->max) h->max = (uint64_t)us;
    if (us >= HBUCKETS) { h->overflow++; h->b[HBUCKETS - 1]++; }
    else h->b[us]++;
}
static void hist_merge(hist_t *d, const hist_t *s) {
    d->count += s->count; d->sum += s->sum; d->overflow += s->overflow;
    if (s->max > d->max) d->max = s->max;
    for (int i = 0; i < HBUCKETS; i++) d->b[i] += s->b[i];
}
static uint64_t hist_pct(const hist_t *h, double p) {
    if (!h->count) return 0;
    uint64_t target = (uint64_t)(p / 100.0 * (double)h->count + 0.5);
    if (target == 0) target = 1;
    uint64_t cum = 0;
    for (int i = 0; i < HBUCKETS; i++) {
        cum += h->b[i];
        if (cum >= target) return (uint64_t)i;
    }
    return h->max;
}

/* ---- SPSC ring of intended send timestamps --------------------------------- */

#define RING_BITS 18               /* 262144 in-flight headroom */
#define RING_SIZE (1u << RING_BITS)
#define RING_MASK (RING_SIZE - 1)
typedef struct {
    int64_t *slot;
    _Atomic uint64_t head;         /* writer pushes */
    _Atomic uint64_t tail;         /* reader pops */
} ring_t;

static void ring_init(ring_t *r) {
    r->slot = malloc(sizeof(int64_t) * RING_SIZE);
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
}
static void ring_push(ring_t *r, int64_t v) {
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    /* The reader is always behind the writer by the in-flight count, which is
     * rate*latency — far below RING_SIZE. If it ever fills, spin (test invalid
     * rather than corrupt the FIFO match). */
    while (h - atomic_load_explicit(&r->tail, memory_order_acquire) >= RING_SIZE) { }
    r->slot[h & RING_MASK] = v;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
}
static int64_t ring_pop(ring_t *r) {
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    while (t == atomic_load_explicit(&r->head, memory_order_acquire)) { /* wait */ }
    int64_t v = r->slot[t & RING_MASK];
    atomic_store_explicit(&r->tail, t + 1, memory_order_release);
    return v;
}

/* ---- shared config / per-connection context -------------------------------- */

typedef struct {
    const char *host;
    int port;
    int mode_ws;                   /* 0=http, 1=ws */
    int payload;                   /* ws payload bytes */
    double rate_per_conn;          /* requests/sec on this connection */
    int64_t start_ns, end_ns, warmup_end_ns;

    int fd;
    ring_t ring;
    hist_t hist;
    _Atomic uint64_t sent, recv;
    _Atomic int writer_done;
    int connect_failed;

    /* Persistent receive buffer so pipelined responses aren't lost between
     * http_recv() calls (open-loop sends many before any reply arrives). */
    char rbuf[65536];
    size_t rlen;
} conn_t;

/* ---- socket / protocol helpers --------------------------------------------- */

static int dial(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    /* periodic read wakeups so the reader can notice the writer is done */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        off += (size_t)n;
    }
    return 0;
}

/* read exactly len bytes, retrying on the 1s recv timeout while not done */
static int read_all(conn_t *c, void *buf, size_t len) {
    char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(c->fd, p + off, len - off, 0);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (atomic_load(&c->writer_done) &&
                atomic_load(&c->recv) >= atomic_load(&c->sent)) return -1; /* done */
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;                  /* closed / error */
    }
    return 0;
}

/* WebSocket handshake (client side). */
static int ws_handshake(conn_t *c) {
    static const char *req =
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    if (write_all(c->fd, req, strlen(req)) < 0) return -1;
    /* read until \r\n\r\n */
    char buf[1024];
    size_t used = 0;
    while (used < sizeof(buf) - 1) {
        ssize_t n = recv(c->fd, buf + used, sizeof(buf) - 1 - used, 0);
        if (n <= 0) { if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue; return -1; }
        used += (size_t)n;
        buf[used] = 0;
        if (strstr(buf, "\r\n\r\n")) return 0;
    }
    return -1;
}

/* one masked client frame */
static int ws_send(conn_t *c, const uint8_t *payload, int n) {
    uint8_t h[14];
    int hl;
    h[0] = 0x82;                    /* FIN + binary */
    if (n < 126) { h[1] = 0x80 | (uint8_t)n; hl = 2; }
    else { h[1] = 0x80 | 126; h[2] = (uint8_t)(n >> 8); h[3] = (uint8_t)n; hl = 4; }
    uint8_t mask[4] = { 0x12, 0x34, 0x56, 0x78 };
    memcpy(h + hl, mask, 4); hl += 4;
    if (write_all(c->fd, h, (size_t)hl) < 0) return -1;
    /* mask payload into a small stack buffer (payload is bounded by caller) */
    static __thread uint8_t mbuf[65536];
    for (int i = 0; i < n; i++) mbuf[i] = payload[i] ^ mask[i & 3];
    return write_all(c->fd, mbuf, (size_t)n);
}

/* read one server frame, discard payload */
static int ws_recv(conn_t *c) {
    uint8_t h2[2];
    if (read_all(c, h2, 2) < 0) return -1;
    uint64_t n = h2[1] & 0x7f;
    if (n == 126) { uint8_t e[2]; if (read_all(c, e, 2) < 0) return -1; n = ((uint64_t)e[0] << 8) | e[1]; }
    else if (n == 127) { uint8_t e[8]; if (read_all(c, e, 8) < 0) return -1; n = 0; for (int i = 0; i < 8; i++) n = (n << 8) | e[i]; }
    if (h2[1] & 0x80) { uint8_t m[4]; if (read_all(c, m, 4) < 0) return -1; }
    uint8_t tmp[4096];
    while (n > 0) {
        size_t chunk = n < sizeof(tmp) ? (size_t)n : sizeof(tmp);
        if (read_all(c, tmp, chunk) < 0) return -1;
        n -= chunk;
    }
    return 0;
}

/* Fill more bytes into the persistent buffer. Returns 1 on progress, 0 if the
 * test is finished, -1 on close/error. */
static int rbuf_fill(conn_t *c) {
    if (c->rlen >= sizeof(c->rbuf)) return -1;  /* full without a complete msg */
    ssize_t n = recv(c->fd, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen, 0);
    if (n > 0) { c->rlen += (size_t)n; return 1; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (atomic_load(&c->writer_done) && atomic_load(&c->recv) >= atomic_load(&c->sent)) return 0;
        return 1;   /* timeout, keep waiting */
    }
    if (n < 0 && errno == EINTR) return 1;
    return -1;
}

/* Consume exactly one complete HTTP/1.1 response from the persistent buffer,
 * leaving any pipelined bytes for the next call. */
static int http_recv(conn_t *c) {
    for (;;) {
        /* find end of headers */
        char *term = NULL;
        if (c->rlen >= 4) {
            for (size_t i = 3; i < c->rlen; i++)
                if (c->rbuf[i-3]=='\r'&&c->rbuf[i-2]=='\n'&&c->rbuf[i-1]=='\r'&&c->rbuf[i]=='\n') {
                    term = c->rbuf + i + 1; break;
                }
        }
        if (term) {
            size_t hdr_len = (size_t)(term - c->rbuf);
            /* parse Content-Length within the header block */
            long clen = 0;
            char save = c->rbuf[hdr_len - 1]; c->rbuf[hdr_len - 1] = 0;
            char *cl = strcasestr(c->rbuf, "content-length:");
            if (cl) clen = strtol(cl + 15, NULL, 10);
            c->rbuf[hdr_len - 1] = save;
            size_t total = hdr_len + (clen > 0 ? (size_t)clen : 0);
            if (c->rlen >= total) {
                /* one full response present: drop it, keep the remainder */
                memmove(c->rbuf, c->rbuf + total, c->rlen - total);
                c->rlen -= total;
                return 0;
            }
        }
        int rc = rbuf_fill(c);
        if (rc <= 0) return -1;
    }
}

/* ---- threads --------------------------------------------------------------- */

static void *writer_thread(void *arg) {
    conn_t *c = arg;
    double interval_ns = 1e9 / c->rate_per_conn;
    int64_t next = c->start_ns;
    uint8_t payload[65536];
    memset(payload, 0xAB, sizeof(payload));
    uint64_t i = 0;
    while (1) {
        int64_t sched = c->start_ns + (int64_t)(i * interval_ns);
        if (sched >= c->end_ns) break;
        pace_until(sched);
        int64_t intended = sched;          /* schedule-based, NOT now() */
        ring_push(&c->ring, intended);
        int rc = c->mode_ws ? ws_send(c, payload, c->payload)
                            : write_all(c->fd, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 33);
        if (rc < 0) { /* pop our own push so reader doesn't wait forever */
            atomic_fetch_add(&c->sent, 1);
            break;
        }
        atomic_fetch_add(&c->sent, 1);
        i++;
        (void)next;
    }
    atomic_store(&c->writer_done, 1);
    return NULL;
}

static void *reader_thread(void *arg) {
    conn_t *c = arg;
    while (1) {
        if (atomic_load(&c->writer_done) &&
            atomic_load(&c->recv) >= atomic_load(&c->sent)) break;
        int rc = c->mode_ws ? ws_recv(c) : http_recv(c);
        if (rc < 0) break;
        int64_t intended = ring_pop(&c->ring);
        int64_t lat = now_ns() - intended;
        if (now_ns() >= c->warmup_end_ns) hist_add(&c->hist, lat);
        atomic_fetch_add(&c->recv, 1);
    }
    return NULL;
}

/* ---- main ------------------------------------------------------------------ */

static int64_t parse_dur(const char *s) {
    char *e; double v = strtod(s, &e);
    if (*e == 's') return (int64_t)(v * 1e9);
    if (*e == 'm') return (int64_t)(v * 60e9);
    if (*e == 0)   return (int64_t)(v * 1e9);
    return (int64_t)(v * 1e9);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8090, conns = 8, mode_ws = 0, payload = 64;
    double rate = 100000;          /* total req/s */
    int64_t dur = 20LL * 1000000000LL, warmup = 2LL * 1000000000LL;

    for (int i = 1; i < argc - 1; i++) {
        if (!strcmp(argv[i], "-addr")) { static char hb[64]; strncpy(hb, argv[++i], 63); char *col = strchr(hb, ':'); if (col){*col=0; port=atoi(col+1);} host = hb; }
        else if (!strcmp(argv[i], "-mode")) mode_ws = !strcmp(argv[++i], "ws");
        else if (!strcmp(argv[i], "-conns")) conns = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-rate")) rate = atof(argv[++i]);
        else if (!strcmp(argv[i], "-size")) payload = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-dur")) dur = parse_dur(argv[++i]);
        else if (!strcmp(argv[i], "-warmup")) warmup = parse_dur(argv[++i]);
    }
    if (payload > 60000) payload = 60000;

    conn_t *cs = calloc((size_t)conns, sizeof(conn_t));
    int64_t start = now_ns() + 200000000LL;  /* 200ms grace to spin up threads */
    int established = 0;
    for (int i = 0; i < conns; i++) {
        conn_t *c = &cs[i];
        c->host = host; c->port = port; c->mode_ws = mode_ws; c->payload = payload;
        c->rate_per_conn = rate / conns;
        c->start_ns = start; c->end_ns = start + dur; c->warmup_end_ns = start + warmup;
        ring_init(&c->ring); hist_init(&c->hist);
        atomic_store(&c->sent, 0); atomic_store(&c->recv, 0); atomic_store(&c->writer_done, 0);
        c->fd = dial(host, port);
        if (c->fd < 0 || (mode_ws && ws_handshake(c) < 0)) { c->connect_failed = 1; continue; }
        established++;
    }
    if (!established) { fprintf(stderr, "no connections established to %s:%d\n", host, port); return 1; }

    pthread_t *wt = calloc((size_t)conns, sizeof(pthread_t));
    pthread_t *rt = calloc((size_t)conns, sizeof(pthread_t));
    for (int i = 0; i < conns; i++) {
        if (cs[i].connect_failed) continue;
        pthread_create(&rt[i], NULL, reader_thread, &cs[i]);
        pthread_create(&wt[i], NULL, writer_thread, &cs[i]);
    }
    for (int i = 0; i < conns; i++) {
        if (cs[i].connect_failed) continue;
        pthread_join(wt[i], NULL);
        pthread_join(rt[i], NULL);
    }

    hist_t agg; hist_init(&agg);
    uint64_t total_sent = 0, total_recv = 0;
    for (int i = 0; i < conns; i++) {
        if (cs[i].connect_failed) continue;
        hist_merge(&agg, &cs[i].hist);
        total_sent += atomic_load(&cs[i].sent);
        total_recv += atomic_load(&cs[i].recv);
    }
    double secs = (double)dur / 1e9;
    double measured_secs = (double)(dur - warmup) / 1e9;

    printf("\n== latency: %s, %d conns, target %.0f req/s, %.0fs (%.0fs warmup) ==\n",
           mode_ws ? "ws" : "http", established, rate, secs, (double)warmup / 1e9);
    printf("  sent: %lu  recv: %lu  achieved: %.0f req/s\n",
           (unsigned long)total_sent, (unsigned long)total_recv,
           (double)total_recv / secs);
    printf("  measured samples (post-warmup): %lu over %.0fs\n", (unsigned long)agg.count, measured_secs);
    if (agg.count) {
        printf("  latency us:  mean=%.1f  p50=%lu  p90=%lu  p99=%lu  p99.9=%lu  p99.99=%lu  max=%lu\n",
               (double)agg.sum / (double)agg.count,
               (unsigned long)hist_pct(&agg, 50), (unsigned long)hist_pct(&agg, 90),
               (unsigned long)hist_pct(&agg, 99), (unsigned long)hist_pct(&agg, 99.9),
               (unsigned long)hist_pct(&agg, 99.99), (unsigned long)agg.max);
        if (agg.overflow) printf("  NOTE: %lu samples exceeded %dms (counted at cap)\n",
                                 (unsigned long)agg.overflow, HBUCKETS / 1000);
    }
    return 0;
}
