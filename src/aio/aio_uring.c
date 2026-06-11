/**
 * @file aio_uring.c
 * @brief io_uring backend — the Linux fast path. True async file I/O: reads are
 *        submitted to the kernel's submission ring and reaped from the completion
 *        ring, with no worker thread parked per in-flight op. Slots into the same
 *        completion contract as the other backends by registering the frontend's
 *        wakeup_fd with the ring, so the kernel signals it on every CQE and the
 *        existing drain() path reaps + fires callbacks.
 *
 * Built against raw io_uring syscalls (no liburing dependency — portico stays
 * self-contained). Ring index publication/consumption uses C11 acquire/release
 * atomics, so the ordering is correct on weakly-ordered targets (ARM/Ampere), not
 * merely on x86's strong model.
 *
 * Compiled with real behaviour only when <linux/io_uring.h> is present
 * (PORTICO_AIO_HAVE_IOURING); otherwise portico_aio_uring_init() is a stub that
 * returns -ENOSYS so PORTICO_AIO_IOURING cleanly falls back.
 *
 * Usage model: a single thread submits and drains (the event-loop thread). The
 * rings are therefore single-producer (submit) / single-consumer (reap) and need
 * no locking of their own; only the kernel is the other party.
 */
#include "aio_internal.h"

#include <errno.h>

#ifdef PORTICO_AIO_HAVE_IOURING

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

/* C11 acquire/release on a kernel-shared 32-bit ring index. The cast is the
 * standard idiom for raw io_uring: the field is a plain __u32 the kernel updates,
 * and we need the matching barrier on our side. */
static inline unsigned load_acquire(unsigned *p) {
    return atomic_load_explicit((_Atomic unsigned *)p, memory_order_acquire);
}
static inline void store_release(unsigned *p, unsigned v) {
    atomic_store_explicit((_Atomic unsigned *)p, v, memory_order_release);
}

static int sys_io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(SYS_io_uring_setup, entries, p);
}
static int sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
    return (int)syscall(SYS_io_uring_enter, fd, to_submit, min_complete, flags,
                        (void *)0, (size_t)0);
}
static int sys_io_uring_register(int fd, unsigned opcode, void *arg, unsigned nr) {
    return (int)syscall(SYS_io_uring_register, fd, opcode, arg, nr);
}

/* Per-op context: the CQE's user_data points here so reap can recover cb/user. */
typedef struct { portico_aio_cb_t cb; void *user; } uring_op_t;

typedef struct {
    portico_aio_t *a;
    int    ring_fd;

    void  *sq_ring;  size_t sq_ring_sz;     /* single mmap (also backs the CQ ring) */
    void  *sqes;     size_t sqes_sz;

    unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
    struct io_uring_sqe *sqe;
    unsigned  sq_entries;

    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqe;

    unsigned  inflight;                     /* submitted, not yet reaped */
} uring_state_t;

static int uring_submit(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                        portico_aio_cb_t cb, void *user) {
    uring_state_t *u = a->backend;

    /* Bound in-flight by the ring so the CQ can never overflow, and apply SQ
     * backpressure. Both report -EAGAIN, same contract as the threadpool. */
    if (u->inflight >= u->sq_entries) return -EAGAIN;
    unsigned tail = *u->sq_tail;                 /* we are the sole producer */
    if (tail - load_acquire(u->sq_head) >= u->sq_entries) return -EAGAIN;

    uring_op_t *op = malloc(sizeof *op);
    if (!op) return -ENOMEM;
    op->cb = cb; op->user = user;

    unsigned idx = tail & *u->sq_mask;
    struct io_uring_sqe *s = &u->sqe[idx];
    memset(s, 0, sizeof *s);
    s->opcode    = IORING_OP_READ;
    s->fd        = fd;
    s->addr      = (uint64_t)(uintptr_t)buf;
    s->len       = (unsigned)len;
    s->off       = (uint64_t)off;
    s->user_data = (uint64_t)(uintptr_t)op;
    u->sq_array[idx] = idx;

    store_release(u->sq_tail, tail + 1);         /* publish the SQE to the kernel */

    int r = sys_io_uring_enter(u->ring_fd, 1, 0, 0);
    if (r < 0) {
        store_release(u->sq_tail, tail);         /* un-publish: kernel didn't consume */
        free(op);
        return -errno;
    }
    u->inflight++;
    return 0;
}

static void uring_reap(portico_aio_t *a) {
    uring_state_t *u = a->backend;
    unsigned head = *u->cq_head;                 /* we are the sole consumer */
    unsigned tail = load_acquire(u->cq_tail);    /* kernel published up to here */

    while (head != tail) {
        struct io_uring_cqe *c = &u->cqe[head & *u->cq_mask];
        uring_op_t *op = (uring_op_t *)(uintptr_t)c->user_data;
        ssize_t res = c->res;                    /* >= 0 bytes, or -errno */
        if (op) {
            /* We already run inside drain() on the consumer thread → quiet enqueue;
             * the pop loop right after reap will fire these callbacks. */
            portico_aio_enqueue(a, op->cb, op->user, res);
            free(op);
        }
        u->inflight--;
        head++;
    }
    store_release(u->cq_head, head);             /* release consumed CQEs to kernel */
}

static void uring_destroy(portico_aio_t *a) {
    uring_state_t *u = a->backend;
    if (!u) return;

    /* Wait for and discard every in-flight completion so no op context leaks.
     * Callbacks are intentionally NOT fired (matches the frontend's destroy). */
    while (u->inflight > 0) {
        unsigned head = *u->cq_head, tail = load_acquire(u->cq_tail);
        if (head == tail) {
            sys_io_uring_enter(u->ring_fd, 0, 1, IORING_ENTER_GETEVENTS);
            continue;
        }
        while (head != tail) {
            struct io_uring_cqe *c = &u->cqe[head & *u->cq_mask];
            free((void *)(uintptr_t)c->user_data);
            u->inflight--;
            head++;
        }
        store_release(u->cq_head, head);
    }

    if (u->sqes && u->sqes != MAP_FAILED)       munmap(u->sqes, u->sqes_sz);
    if (u->sq_ring && u->sq_ring != MAP_FAILED) munmap(u->sq_ring, u->sq_ring_sz);
    close(u->ring_fd);                          /* also unregisters the eventfd */
    free(u);
    a->backend = NULL;
}

static const portico_aio_ops_t URING_OPS = {
    .submit  = uring_submit,
    .reap    = uring_reap,
    .destroy = uring_destroy,
};

int portico_aio_uring_init(portico_aio_t *a) {
    unsigned entries = a->cfg.queue_depth > 0 ? (unsigned)a->cfg.queue_depth : 256;

    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    int fd = sys_io_uring_setup(entries, &p);
    if (fd < 0) return -errno;                  /* ENOSYS (old kernel) / EPERM (seccomp) */

    /* Require the single-mmap layout (kernels >= 5.4); keeps setup simple. */
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) { close(fd); return -ENOSYS; }

    uring_state_t *u = calloc(1, sizeof *u);
    if (!u) { close(fd); return -ENOMEM; }
    u->a = a;
    u->ring_fd = fd;
    u->sq_entries = p.sq_entries;

    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_sz = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    u->sq_ring_sz = sq_sz > cq_sz ? sq_sz : cq_sz;

    u->sq_ring = mmap(NULL, u->sq_ring_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (u->sq_ring == MAP_FAILED) { int e = errno; close(fd); free(u); return -e; }

    u->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    u->sqes = mmap(NULL, u->sqes_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (u->sqes == MAP_FAILED) {
        int e = errno; munmap(u->sq_ring, u->sq_ring_sz); close(fd); free(u); return -e;
    }

    char *sr = u->sq_ring;
    u->sq_head  = (unsigned *)(sr + p.sq_off.head);
    u->sq_tail  = (unsigned *)(sr + p.sq_off.tail);
    u->sq_mask  = (unsigned *)(sr + p.sq_off.ring_mask);
    u->sq_array = (unsigned *)(sr + p.sq_off.array);
    u->sqe      = (struct io_uring_sqe *)u->sqes;
    u->cq_head  = (unsigned *)(sr + p.cq_off.head);
    u->cq_tail  = (unsigned *)(sr + p.cq_off.tail);
    u->cq_mask  = (unsigned *)(sr + p.cq_off.ring_mask);
    u->cqe      = (struct io_uring_cqe *)(sr + p.cq_off.cqes);

    /* Register the frontend's wakeup_fd so the kernel signals it per CQE — this is
     * what makes io_uring fit the same epoll-add-then-drain() contract. */
    int efd = a->wakeup_fd;
    if (sys_io_uring_register(fd, IORING_REGISTER_EVENTFD, &efd, 1) < 0) {
        int e = errno;
        munmap(u->sqes, u->sqes_sz);
        munmap(u->sq_ring, u->sq_ring_sz);
        close(fd); free(u);
        return -e;
    }

    a->ops = &URING_OPS;
    a->backend = u;
    return 0;
}

#else  /* !PORTICO_AIO_HAVE_IOURING */

int portico_aio_uring_init(portico_aio_t *a) { (void)a; return -ENOSYS; }

#endif
