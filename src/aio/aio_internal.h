/**
 * @file aio_internal.h
 * @brief Shared internals: the completion queue the frontend owns and the backend
 *        vtable each backend implements. Not a public header.
 */
#ifndef PORTICO_AIO_INTERNAL_H
#define PORTICO_AIO_INTERNAL_H

#include "portico_aio.h"
#include <pthread.h>
#include <stdatomic.h>

/* One finished op, waiting for its callback to fire on the consumer thread. */
typedef struct portico_aio_completion {
    portico_aio_cb_t cb;
    void            *user;
    ssize_t          res;
    struct portico_aio_completion *next;
} portico_aio_completion_t;

/* A backend turns a submitted read into a completion that the frontend delivers.
 * Backends that compute results on other threads (blocking inline, threadpool)
 * push via portico_aio_post_completion(); a ring backend instead reaps in reap(). */
typedef struct {
    /* Perform or queue a read. Return 0 if accepted (a completion WILL be
     * produced for it), or -errno if rejected synchronously (none produced). */
    int  (*submit)(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                   portico_aio_cb_t cb, void *user);
    /* Pull any backend-held completions into the frontend queue. May be NULL for
     * backends that post directly. Called at the start of drain(). */
    void (*reap)(portico_aio_t *a);
    /* Release backend-private state. May be NULL. */
    void (*destroy)(portico_aio_t *a);
} portico_aio_ops_t;

struct portico_aio {
    int                       wakeup_fd;   /* eventfd; consumer adds to its epoll */
    atomic_int                notified;    /* 1 = an unconsumed wakeup is pending (coalesces eventfd writes) */
    pthread_mutex_t           lock;        /* guards head/tail */
    portico_aio_completion_t *head, *tail; /* FIFO completion queue */
    const portico_aio_ops_t  *ops;         /* backend vtable */
    void                     *backend;     /* backend-private state */
    portico_aio_cfg_t         cfg;
};

/* Enqueue a finished op and signal wakeup_fd. Thread-safe; callable from any
 * backend worker thread. The callback fires later, in portico_aio_drain(). */
void portico_aio_post_completion(portico_aio_t *a, portico_aio_cb_t cb,
                                 void *user, ssize_t res);

/* Backend constructors: wire a->ops and a->backend, return 0 or -errno. */
int  portico_aio_blocking_init(portico_aio_t *a);
int  portico_aio_threadpool_init(portico_aio_t *a);

#endif /* PORTICO_AIO_INTERNAL_H */
