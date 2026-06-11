/*
 * portico async file I/O — isolation unit test.
 *
 * No sockets, no event loop, no portico server: drives portico_aio directly
 * against a real temp file. The core correctness suite runs against BOTH the
 * blocking backend (the oracle) and the threadpool backend and asserts identical
 * results — differential testing. Threadpool-only cases cover concurrency and
 * bounded-queue backpressure. Run under ThreadSanitizer to validate the worker /
 * completion-queue synchronisation.
 */
#include "portico_aio.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_ok = 0, g_fail = 0;
static void chk(const char *name, int cond, const char *detail) {
    printf("  %-5s %-46s %s\n", cond ? "ok" : "FAIL", name, detail ? detail : "");
    if (cond) g_ok++; else g_fail++;
}

/* Deterministic file content so any (offset, len) read is verifiable. */
#define FILE_SIZE 4096
static int  g_fd = -1;
static char g_path[] = "/tmp/portico_aio_XXXXXX";

static unsigned char pat(size_t i) { return (unsigned char)((i * 31u + 7u) & 0xff); }
static int verify(const unsigned char *buf, off_t off, ssize_t n) {
    for (ssize_t i = 0; i < n; i++)
        if (buf[i] != pat((size_t)off + (size_t)i)) return 0;
    return 1;
}

typedef struct { ssize_t res; int called; } cap_t;
static void cb_capture(void *user, ssize_t res) { cap_t *c = user; c->res = res; c->called++; }

static int g_order[8], g_norder;
static void cb_order(void *user, ssize_t res) { (void)res; g_order[g_norder++] = *(int *)user; }

static int fd_readable(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
}

/* Poll the wakeup_fd and drain until `want` completions have fired (or timeout).
 * Works for both backends: blocking has them ready immediately, threadpool
 * delivers them as workers finish. Returns how many fired. */
static int await_completions(portico_aio_t *a, int want, int timeout_ms) {
    int got = portico_aio_drain(a);
    while (got < want) {
        struct pollfd p = { .fd = portico_aio_wakeup_fd(a), .events = POLLIN };
        if (poll(&p, 1, timeout_ms) <= 0) break;   /* timeout / error */
        got += portico_aio_drain(a);
    }
    return got;
}

/* One submitted read, awaited; fills *out. Returns the submit rc (0 = accepted). */
static int do_read(portico_aio_t *a, void *buf, size_t len, off_t off, cap_t *out) {
    out->res = -999999; out->called = 0;
    int rc = portico_aio_pread(a, g_fd, buf, len, off, cb_capture, out);
    if (rc == 0) await_completions(a, 1, 5000);
    return rc;
}

/* The backend-agnostic correctness suite — must pass identically for every
 * backend. `optional` backends (io_uring) that the kernel rejects are skipped,
 * not failed. */
static void correctness_suite(portico_aio_backend_t backend, const char *label, int optional) {
    char nm[80];
    portico_aio_cfg_t cfg = { .backend = backend, .threads = 4 };
    errno = 0;
    portico_aio_t *a = portico_aio_create(&cfg);
    if (!a && optional && errno == ENOSYS) {
        printf("  %-5s [%s] unavailable on this kernel — skipped\n", "skip", label);
        return;
    }
    snprintf(nm, sizeof nm, "[%s] create", label);
    chk(nm, a != NULL, a ? "" : strerror(errno));
    if (!a) return;

    unsigned char buf[FILE_SIZE];
    cap_t c;

    do_read(a, buf, FILE_SIZE, 0, &c);
    snprintf(nm, sizeof nm, "[%s] full read", label);
    chk(nm, c.called == 1 && c.res == FILE_SIZE && verify(buf, 0, c.res), NULL);

    memset(buf, 0, sizeof buf);
    do_read(a, buf, 100, 1000, &c);
    snprintf(nm, sizeof nm, "[%s] offset read", label);
    chk(nm, c.called == 1 && c.res == 100 && verify(buf, 1000, c.res), NULL);

    memset(buf, 0, sizeof buf);
    do_read(a, buf, 100, FILE_SIZE - 3, &c);
    snprintf(nm, sizeof nm, "[%s] tail short read (3)", label);
    chk(nm, c.called == 1 && c.res == 3 && verify(buf, FILE_SIZE - 3, c.res), NULL);

    do_read(a, buf, 64, FILE_SIZE + 100, &c);
    snprintf(nm, sizeof nm, "[%s] read past EOF -> 0", label);
    chk(nm, c.called == 1 && c.res == 0, NULL);

    do_read(a, buf, 0, 0, &c);
    snprintf(nm, sizeof nm, "[%s] zero-length -> 0", label);
    chk(nm, c.called == 1 && c.res == 0, NULL);

    {
        int wfd = open(g_path, O_WRONLY);
        cap_t e; e.res = 0; e.called = 0;
        int rc = portico_aio_pread(a, wfd, buf, 16, 0, cb_capture, &e);
        if (rc == 0) await_completions(a, 1, 5000);
        snprintf(nm, sizeof nm, "[%s] write-only fd -> -EBADF", label);
        chk(nm, e.called == 1 && e.res == -EBADF, NULL);
        if (wfd >= 0) close(wfd);
    }

    portico_aio_destroy(a);
}

int main(void) {
    printf("== portico aio isolation test ==\n");

    g_fd = mkstemp(g_path);
    if (g_fd < 0) { perror("mkstemp"); return 2; }
    unsigned char src[FILE_SIZE];
    for (size_t i = 0; i < FILE_SIZE; i++) src[i] = pat(i);
    if (write(g_fd, src, FILE_SIZE) != FILE_SIZE) { perror("write"); return 2; }

    /* ---- differential: same suite, every backend ---- */
    correctness_suite(PORTICO_AIO_BLOCKING,   "blocking",   0);
    correctness_suite(PORTICO_AIO_THREADPOOL, "threadpool", 0);
    correctness_suite(PORTICO_AIO_IOURING,    "io_uring",   1);   /* skipped if kernel rejects */

    unsigned char buf[FILE_SIZE];

    /* ---- blocking-only invariants (ordering + immediate readiness) ---- */
    {
        portico_aio_t *a = portico_aio_create(NULL);   /* blocking */
        chk("[blocking] wakeup quiet before submit", !fd_readable(portico_aio_wakeup_fd(a)), NULL);
        cap_t c = { .res = 0, .called = 0 };
        portico_aio_pread(a, g_fd, buf, 32, 0, cb_capture, &c);
        chk("[blocking] wakeup readable after submit", fd_readable(portico_aio_wakeup_fd(a)), NULL);
        int fired = portico_aio_drain(a);
        chk("[blocking] drain fires + clears wakeup",
            fired == 1 && c.called == 1 && !fd_readable(portico_aio_wakeup_fd(a)), NULL);

        int ids[3] = { 10, 20, 30 };
        g_norder = 0;
        for (int i = 0; i < 3; i++) portico_aio_pread(a, g_fd, buf, 8, i * 8, cb_order, &ids[i]);
        portico_aio_drain(a);
        chk("[blocking] completions in submission order",
            g_norder == 3 && g_order[0] == 10 && g_order[1] == 20 && g_order[2] == 30, NULL);
        portico_aio_destroy(a);
    }

    /* ---- frontend argument validation (backend-agnostic; synchronous -errno) ---- */
    {
        portico_aio_t *a = portico_aio_create(NULL);
        chk("NULL buf + nonzero len -> -EFAULT",
            portico_aio_pread(a, g_fd, NULL, 16, 0, cb_capture, NULL) == -EFAULT, NULL);
        chk("negative offset -> -EINVAL",
            portico_aio_pread(a, g_fd, buf, 16, -1, cb_capture, NULL) == -EINVAL, NULL);
        chk("NULL callback -> -EINVAL",
            portico_aio_pread(a, g_fd, buf, 16, 0, NULL, NULL) == -EINVAL, NULL);
        chk("negative fd -> -EINVAL",
            portico_aio_pread(a, -1, buf, 16, 0, cb_capture, NULL) == -EINVAL, NULL);
        portico_aio_destroy(a);
    }

    /* ---- threadpool: many concurrent ops, all correct (order-independent) ---- */
    {
        enum { N = 1000, LEN = 64 };
        portico_aio_cfg_t cfg = { .backend = PORTICO_AIO_THREADPOOL, .threads = 8 };
        portico_aio_t *a = portico_aio_create(&cfg);
        static cap_t caps[N];
        static unsigned char bufs[N][LEN];
        for (int i = 0; i < N; i++) {
            caps[i].res = -1; caps[i].called = 0;
            off_t off = (off_t)((i % 60) * LEN);
            portico_aio_pread(a, g_fd, bufs[i], LEN, off, cb_capture, &caps[i]);
        }
        int fired = await_completions(a, N, 10000);
        int all = (fired == N);
        for (int i = 0; i < N && all; i++) {
            off_t off = (off_t)((i % 60) * LEN);
            ssize_t want = (off + LEN <= FILE_SIZE) ? LEN : (FILE_SIZE - off);
            if (caps[i].called != 1 || caps[i].res != want || !verify(bufs[i], off, caps[i].res))
                all = 0;
        }
        char d[40]; snprintf(d, sizeof d, "fired %d/%d", fired, (int)N);
        chk("[threadpool] 1000 concurrent ops correct", all, d);
        portico_aio_destroy(a);
    }

    /* ---- threadpool: bounded queue backpressures with -EAGAIN, retries complete ---- */
    {
        enum { N = 300, LEN = 64 };
        portico_aio_cfg_t cfg = { .backend = PORTICO_AIO_THREADPOOL, .threads = 2, .queue_depth = 8 };
        portico_aio_t *a = portico_aio_create(&cfg);
        static cap_t caps[N];
        static unsigned char bufs[N][LEN];
        int eagain = 0, fired_total = 0, submit_err = 0;
        for (int i = 0; i < N; i++) {
            caps[i].res = -1; caps[i].called = 0;
            off_t off = (off_t)((i % 60) * LEN);
            for (;;) {
                int rc = portico_aio_pread(a, g_fd, bufs[i], LEN, off, cb_capture, &caps[i]);
                if (rc == 0) break;
                if (rc == -EAGAIN) {                 /* queue full: drain some, retry */
                    eagain++;
                    struct pollfd p = { .fd = portico_aio_wakeup_fd(a), .events = POLLIN };
                    poll(&p, 1, 5000);
                    fired_total += portico_aio_drain(a);
                    continue;
                }
                submit_err = 1; break;               /* unexpected */
            }
        }
        while (fired_total < N) {
            struct pollfd p = { .fd = portico_aio_wakeup_fd(a), .events = POLLIN };
            if (poll(&p, 1, 10000) <= 0) break;
            fired_total += portico_aio_drain(a);
        }
        int all = (!submit_err && fired_total == N);
        for (int i = 0; i < N && all; i++) {
            off_t off = (off_t)((i % 60) * LEN);
            ssize_t want = (off + LEN <= FILE_SIZE) ? LEN : (FILE_SIZE - off);
            if (caps[i].called != 1 || caps[i].res != want || !verify(bufs[i], off, caps[i].res))
                all = 0;
        }
        char d[48]; snprintf(d, sizeof d, "fired %d, %d EAGAIN retries", fired_total, eagain);
        chk("[threadpool] backpressure: all complete via retry", all, d);
        portico_aio_destroy(a);
    }

    /* ---- io_uring: many concurrent ops, all correct (if available) ---- */
    {
        enum { N = 1000, LEN = 64 };
        portico_aio_cfg_t cfg = { .backend = PORTICO_AIO_IOURING, .queue_depth = 4096 };
        errno = 0;
        portico_aio_t *a = portico_aio_create(&cfg);
        if (!a && errno == ENOSYS) {
            printf("  skip  [io_uring] concurrency — unavailable on this kernel\n");
        } else if (a) {
            static cap_t caps[N];
            static unsigned char bufs[N][LEN];
            int submit_err = 0;
            for (int i = 0; i < N; i++) {
                caps[i].res = -1; caps[i].called = 0;
                off_t off = (off_t)((i % 60) * LEN);
                if (portico_aio_pread(a, g_fd, bufs[i], LEN, off, cb_capture, &caps[i]) != 0)
                    submit_err = 1;
            }
            int fired = await_completions(a, N, 10000);
            int all = (!submit_err && fired == N);
            for (int i = 0; i < N && all; i++) {
                off_t off = (off_t)((i % 60) * LEN);
                ssize_t want = (off + LEN <= FILE_SIZE) ? LEN : (FILE_SIZE - off);
                if (caps[i].called != 1 || caps[i].res != want || !verify(bufs[i], off, caps[i].res))
                    all = 0;
            }
            char d[40]; snprintf(d, sizeof d, "fired %d/%d", fired, (int)N);
            chk("[io_uring] 1000 concurrent ops correct", all, d);
            portico_aio_destroy(a);
        } else {
            chk("[io_uring] create", 0, strerror(errno));
        }
    }

    close(g_fd);
    unlink(g_path);

    printf("\n%s  (%d ok, %d failed)\n", g_fail ? "FAIL" : "PASS", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
