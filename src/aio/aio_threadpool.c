/**
 * @file aio_threadpool.c
 * @brief Threadpool backend: N worker threads pull submitted reads off a bounded
 *        queue, run pread() (off the caller's event thread), and post completions
 *        through the frontend's coalesced wakeup. This is the portable backend
 *        that makes file I/O genuinely non-blocking for the loop — and the runtime
 *        fallback when io_uring is unavailable (old kernel / seccomp-blocked).
 *
 * Correctness is validated differentially against the blocking backend (same
 * inputs → identical results); concurrency is validated under ThreadSanitizer.
 */
#include "aio_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define TP_DEFAULT_THREADS 4

/* One queued read. Allocated at submit, freed by the worker that runs it. */
typedef struct tp_task {
    int               fd;
    void             *buf;
    size_t            len;
    off_t             off;
    portico_aio_cb_t  cb;
    void             *user;
    struct tp_task   *next;
} tp_task_t;

typedef struct {
    portico_aio_t  *a;            /* back-ref, for posting completions */
    pthread_t      *threads;
    int             nthreads;
    pthread_mutex_t lock;         /* guards the task queue + stop */
    pthread_cond_t  cond;         /* workers wait here for work / stop */
    tp_task_t      *head, *tail;
    int             depth;        /* tasks currently queued */
    int             max_depth;    /* 0 = unbounded; else submit backpressures */
    int             stop;
} tp_state_t;

static void *tp_worker(void *arg) {
    tp_state_t *tp = arg;
    for (;;) {
        pthread_mutex_lock(&tp->lock);
        while (!tp->head && !tp->stop)
            pthread_cond_wait(&tp->cond, &tp->lock);
        if (!tp->head && tp->stop) { pthread_mutex_unlock(&tp->lock); break; }

        tp_task_t *t = tp->head;
        tp->head = t->next;
        if (!tp->head) tp->tail = NULL;
        tp->depth--;
        pthread_mutex_unlock(&tp->lock);

        ssize_t n;
        do { n = pread(t->fd, t->buf, t->len, t->off); } while (n < 0 && errno == EINTR);
        portico_aio_post_completion(tp->a, t->cb, t->user, n < 0 ? -errno : n);
        free(t);
    }
    return NULL;
}

static int tp_submit(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                     portico_aio_cb_t cb, void *user) {
    tp_state_t *tp = a->backend;

    tp_task_t *t = malloc(sizeof *t);
    if (!t) return -ENOMEM;
    t->fd = fd; t->buf = buf; t->len = len; t->off = off;
    t->cb = cb; t->user = user; t->next = NULL;

    pthread_mutex_lock(&tp->lock);
    if (tp->max_depth && tp->depth >= tp->max_depth) {
        pthread_mutex_unlock(&tp->lock);
        free(t);
        return -EAGAIN;                 /* bounded queue full → caller backpressures */
    }
    if (tp->tail) tp->tail->next = t; else tp->head = t;
    tp->tail = t;
    tp->depth++;
    pthread_cond_signal(&tp->cond);     /* wake one worker */
    pthread_mutex_unlock(&tp->lock);
    return 0;
}

static void tp_destroy(portico_aio_t *a) {
    tp_state_t *tp = a->backend;
    if (!tp) return;

    pthread_mutex_lock(&tp->lock);
    tp->stop = 1;
    pthread_cond_broadcast(&tp->cond);
    pthread_mutex_unlock(&tp->lock);

    /* Workers drain the queue before exiting (loop breaks only when empty AND
     * stopped), so every accepted task still runs and posts its completion. */
    for (int i = 0; i < tp->nthreads; i++)
        pthread_join(tp->threads[i], NULL);

    free(tp->threads);
    pthread_mutex_destroy(&tp->lock);
    pthread_cond_destroy(&tp->cond);
    free(tp);
    a->backend = NULL;
}

static const portico_aio_ops_t TP_OPS = {
    .submit  = tp_submit,
    .reap    = NULL,            /* workers post completions directly */
    .destroy = tp_destroy,
};

int portico_aio_threadpool_init(portico_aio_t *a) {
    int n = a->cfg.threads > 0 ? a->cfg.threads : TP_DEFAULT_THREADS;

    tp_state_t *tp = calloc(1, sizeof *tp);
    if (!tp) return -ENOMEM;
    tp->a = a;
    tp->nthreads = n;
    tp->max_depth = a->cfg.queue_depth > 0 ? a->cfg.queue_depth : 0;
    pthread_mutex_init(&tp->lock, NULL);
    pthread_cond_init(&tp->cond, NULL);
    tp->threads = calloc((size_t)n, sizeof(pthread_t));
    if (!tp->threads) {
        pthread_mutex_destroy(&tp->lock);
        pthread_cond_destroy(&tp->cond);
        free(tp);
        return -ENOMEM;
    }

    a->ops = &TP_OPS;
    a->backend = tp;            /* set before workers start (they deref a->backend) */

    for (int i = 0; i < n; i++) {
        if (pthread_create(&tp->threads[i], NULL, tp_worker, tp) != 0) {
            tp->nthreads = i;   /* only i threads exist; tp_destroy joins those */
            tp_destroy(a);      /* sets a->backend = NULL */
            a->ops = NULL;
            return -EAGAIN;
        }
    }
    return 0;
}
