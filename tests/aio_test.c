/*
 * portico async file I/O — isolation unit test.
 *
 * No sockets, no event loop, no portico server: it drives portico_aio directly
 * against a real temp file and asserts (1) byte-correct reads incl. EOF / tail /
 * zero-length / error propagation, (2) the wakeup_fd actually signals and clears,
 * (3) completions fire in submission order, (4) argument validation, and
 * (5) the queue holds up under many submissions. This is the harness future
 * backends (threadpool, io_uring) get validated against — same asserts, same
 * oracle (the blocking backend).
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
    printf("  %-5s %-44s %s\n", cond ? "ok" : "FAIL", name, detail ? detail : "");
    if (cond) g_ok++; else g_fail++;
}

/* Deterministic file content so any (offset, len) read is verifiable. */
#define FILE_SIZE 4096
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

/* Submit one read and drain it; return the delivered result. */
static ssize_t read_one(portico_aio_t *a, int fd, void *buf, size_t len, off_t off) {
    cap_t c = { .res = -12345, .called = 0 };
    int rc = portico_aio_pread(a, fd, buf, len, off, cb_capture, &c);
    if (rc != 0) return rc;            /* synchronous rejection (-errno) */
    portico_aio_drain(a);
    return c.called == 1 ? c.res : -99999;
}

int main(void) {
    printf("== portico aio isolation test ==\n");

    /* ---- fixture: a temp file of known content ---- */
    char path[] = "/tmp/portico_aio_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return 2; }
    unsigned char src[FILE_SIZE];
    for (size_t i = 0; i < FILE_SIZE; i++) src[i] = pat(i);
    if (write(fd, src, FILE_SIZE) != FILE_SIZE) { perror("write"); return 2; }

    portico_aio_t *a = portico_aio_create(NULL);   /* defaults → blocking */
    chk("create (default backend)", a != NULL, a ? "" : strerror(errno));
    if (!a) return 2;
    chk("wakeup_fd is valid", portico_aio_wakeup_fd(a) >= 0, NULL);

    unsigned char buf[FILE_SIZE];

    /* full read */
    memset(buf, 0, sizeof buf);
    ssize_t n = read_one(a, fd, buf, FILE_SIZE, 0);
    chk("full read returns size", n == FILE_SIZE, NULL);
    chk("full read content correct", n == FILE_SIZE && verify(buf, 0, n), NULL);

    /* mid-file read */
    memset(buf, 0, sizeof buf);
    n = read_one(a, fd, buf, 100, 1000);
    chk("offset read length", n == 100, NULL);
    chk("offset read content correct", n == 100 && verify(buf, 1000, n), NULL);

    /* tail: requested length runs past EOF → short read */
    memset(buf, 0, sizeof buf);
    n = read_one(a, fd, buf, 100, FILE_SIZE - 3);
    chk("tail read is short (3 bytes)", n == 3, NULL);
    chk("tail read content correct", n == 3 && verify(buf, FILE_SIZE - 3, n), NULL);

    /* entirely past EOF → 0 bytes */
    n = read_one(a, fd, buf, 64, FILE_SIZE + 100);
    chk("read past EOF returns 0", n == 0, NULL);

    /* zero-length read → 0 bytes */
    n = read_one(a, fd, buf, 0, 0);
    chk("zero-length read returns 0", n == 0, NULL);

    /* error propagation: a write-only fd → pread EBADF, delivered as -errno */
    {
        int wfd = open(path, O_WRONLY);
        chk("open O_WRONLY", wfd >= 0, NULL);
        char d[32];
        n = read_one(a, wfd, buf, 16, 0);
        snprintf(d, sizeof d, "got %zd", n);
        chk("read on write-only fd -> -EBADF", n == -EBADF, d);
        if (wfd >= 0) close(wfd);
    }

    /* wakeup_fd: signalled by a submit, cleared by drain */
    {
        cap_t c = { .res = 0, .called = 0 };
        chk("wakeup_fd quiet before submit", !fd_readable(portico_aio_wakeup_fd(a)), NULL);
        portico_aio_pread(a, fd, buf, 32, 0, cb_capture, &c);
        chk("wakeup_fd readable after submit", fd_readable(portico_aio_wakeup_fd(a)), NULL);
        int fired = portico_aio_drain(a);
        chk("drain fired the completion", fired == 1 && c.called == 1, NULL);
        chk("wakeup_fd quiet after drain", !fd_readable(portico_aio_wakeup_fd(a)), NULL);
    }

    /* completions fire in submission order */
    {
        int ids[3] = { 10, 20, 30 };
        g_norder = 0;
        for (int i = 0; i < 3; i++)
            portico_aio_pread(a, fd, buf, 8, i * 8, cb_order, &ids[i]);
        int fired = portico_aio_drain(a);
        chk("3 submissions all fired", fired == 3, NULL);
        chk("completions in submission order",
            g_norder == 3 && g_order[0] == 10 && g_order[1] == 20 && g_order[2] == 30, NULL);
    }

    /* argument validation (synchronous -errno, no completion) */
    chk("NULL buf + nonzero len -> -EFAULT",
        portico_aio_pread(a, fd, NULL, 16, 0, cb_capture, NULL) == -EFAULT, NULL);
    chk("negative offset -> -EINVAL",
        portico_aio_pread(a, fd, buf, 16, -1, cb_capture, NULL) == -EINVAL, NULL);
    chk("NULL callback -> -EINVAL",
        portico_aio_pread(a, fd, buf, 16, 0, NULL, NULL) == -EINVAL, NULL);
    chk("negative fd -> -EINVAL",
        portico_aio_pread(a, -1, buf, 16, 0, cb_capture, NULL) == -EINVAL, NULL);

    /* many submissions before a single drain: queue integrity under volume */
    {
        enum { N = 1000, LEN = 64 };
        static cap_t caps[N];
        static unsigned char bufs[N][LEN];
        for (int i = 0; i < N; i++) {
            caps[i].res = -1; caps[i].called = 0;
            off_t off = (off_t)((i % 60) * LEN);
            portico_aio_pread(a, fd, bufs[i], LEN, off, cb_capture, &caps[i]);
        }
        int fired = portico_aio_drain(a);
        int all = (fired == N);
        for (int i = 0; i < N && all; i++) {
            off_t off = (off_t)((i % 60) * LEN);
            ssize_t want = (off + LEN <= FILE_SIZE) ? LEN : (FILE_SIZE - off);
            if (caps[i].called != 1 || caps[i].res != want || !verify(bufs[i], off, caps[i].res))
                all = 0;
        }
        char d[32]; snprintf(d, sizeof d, "fired %d", fired);
        chk("1000 submissions all correct", all, d);
    }

    /* reserved backend reports ENOSYS rather than misbehaving */
    {
        portico_aio_cfg_t cfg = { .backend = PORTICO_AIO_IOURING };
        portico_aio_t *b = portico_aio_create(&cfg);
        chk("unimplemented backend -> NULL/ENOSYS", b == NULL && errno == ENOSYS, NULL);
        if (b) portico_aio_destroy(b);
    }

    portico_aio_destroy(a);
    close(fd);
    unlink(path);

    printf("\n%s  (%d ok, %d failed)\n", g_fail ? "FAIL" : "PASS", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
