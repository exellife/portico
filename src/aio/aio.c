/**
 * @file aio.c
 * @brief Frontend: lifecycle, the shared completion queue + eventfd wakeup, and
 *        dispatch to the selected backend. Backend-agnostic by construction.
 */
#include "aio_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/eventfd.h>

portico_aio_t *portico_aio_create(const portico_aio_cfg_t *cfg) {
    portico_aio_t *a = calloc(1, sizeof *a);
    if (!a) { errno = ENOMEM; return NULL; }

    a->cfg = cfg ? *cfg : (portico_aio_cfg_t){0};   /* defaults: blocking, 0, 0 */

    a->wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (a->wakeup_fd < 0) { int e = errno; free(a); errno = e; return NULL; }
    pthread_mutex_init(&a->lock, NULL);

    int rc;
    switch (a->cfg.backend) {
        case PORTICO_AIO_BLOCKING: rc = portico_aio_blocking_init(a); break;
        default:                   rc = -ENOSYS; break;   /* threadpool/iouring: not yet */
    }
    if (rc != 0) {
        pthread_mutex_destroy(&a->lock);
        close(a->wakeup_fd);
        free(a);
        errno = -rc;
        return NULL;
    }
    return a;
}

void portico_aio_destroy(portico_aio_t *a) {
    if (!a) return;
    if (a->ops && a->ops->destroy) a->ops->destroy(a);
    /* Free any undrained completions (callbacks intentionally not fired). */
    for (portico_aio_completion_t *c = a->head; c; ) {
        portico_aio_completion_t *n = c->next;
        free(c);
        c = n;
    }
    pthread_mutex_destroy(&a->lock);
    close(a->wakeup_fd);
    free(a);
}

int portico_aio_wakeup_fd(portico_aio_t *a) { return a->wakeup_fd; }

void portico_aio_post_completion(portico_aio_t *a, portico_aio_cb_t cb,
                                 void *user, ssize_t res) {
    portico_aio_completion_t *c = malloc(sizeof *c);
    if (!c) {
        /* Out of memory for bookkeeping: fire inline as a last resort so the op
         * is never silently lost. Rare; the threaded backends will document that
         * this can run the callback on a worker thread. */
        cb(user, res);
        return;
    }
    c->cb = cb; c->user = user; c->res = res; c->next = NULL;

    pthread_mutex_lock(&a->lock);
    if (a->tail) a->tail->next = c; else a->head = c;
    a->tail = c;
    pthread_mutex_unlock(&a->lock);

    uint64_t one = 1;
    ssize_t w = write(a->wakeup_fd, &one, sizeof one);
    (void)w;   /* level-triggered: a missed bump is recovered on the next signal */
}

int portico_aio_pread(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                      portico_aio_cb_t cb, void *user) {
    if (!a || !cb || fd < 0 || off < 0) return -EINVAL;
    if (len && !buf) return -EFAULT;
    return a->ops->submit(a, fd, buf, len, off, cb, user);
}

int portico_aio_drain(portico_aio_t *a) {
    if (!a) return 0;

    /* Clear the eventfd counter (EFD_NONBLOCK → EAGAIN once empty). */
    uint64_t cnt;
    while (read(a->wakeup_fd, &cnt, sizeof cnt) == (ssize_t)sizeof cnt) { }

    if (a->ops->reap) a->ops->reap(a);

    int fired = 0;
    for (;;) {
        pthread_mutex_lock(&a->lock);
        portico_aio_completion_t *c = a->head;
        if (c) { a->head = c->next; if (!a->head) a->tail = NULL; }
        pthread_mutex_unlock(&a->lock);
        if (!c) break;
        c->cb(c->user, c->res);   /* fire outside the lock */
        free(c);
        fired++;
    }
    return fired;
}
