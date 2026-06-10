/**
 * @file aio_blocking.c
 * @brief Blocking backend: pread() inline on the submitting thread, then post the
 *        completion. It does NOT make file I/O non-blocking — it is the portable
 *        fallback and, because it shares the frontend's completion flow exactly,
 *        the correctness oracle the threaded / io_uring backends are tested against.
 */
#include "aio_internal.h"

#include <errno.h>
#include <unistd.h>

static int blocking_submit(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                           portico_aio_cb_t cb, void *user) {
    ssize_t n;
    do {
        n = pread(fd, buf, len, off);
    } while (n < 0 && errno == EINTR);

    portico_aio_post_completion(a, cb, user, n < 0 ? -errno : n);
    return 0;
}

static const portico_aio_ops_t BLOCKING_OPS = {
    .submit  = blocking_submit,
    .reap    = NULL,        /* completions are posted directly at submit time */
    .destroy = NULL,        /* no backend-private state */
};

int portico_aio_blocking_init(portico_aio_t *a) {
    a->ops = &BLOCKING_OPS;
    a->backend = NULL;
    return 0;
}
