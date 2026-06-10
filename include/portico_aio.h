/**
 * @file portico_aio.h
 * @brief Async file I/O for an event loop — loop-agnostic, testable in isolation.
 *
 * The problem this solves: epoll/kqueue readiness models do not work for regular
 * files (a regular fd is always "ready"), yet read()/pread() on one can block on
 * disk. Doing that on the event thread stalls every connection it owns. This
 * library moves the blocking work off the caller's thread and delivers the result
 * back through a single completion mechanism the caller integrates with its loop.
 *
 * Design boundary (what keeps it standalone):
 *   - It speaks ONLY fds, offsets, lengths and completions. It knows nothing of
 *     HTTP, TLS, sockets, or any connection type. Path validation (traversal,
 *     symlinks) is the caller's job; hand this library an already-opened fd.
 *   - Completion delivery is injectable: every completion is queued and the
 *     `wakeup_fd` (an eventfd) is signalled. The caller adds `wakeup_fd` to its
 *     epoll set and calls portico_aio_drain() when it fires. In a unit test there
 *     is no loop — you read the fd / call drain() directly. Same library, no loop.
 *
 * Backends share this exact completion flow, so the blocking backend is a faithful
 * correctness oracle for the threaded / io_uring backends (differential testing).
 *
 * Thread-safety: portico_aio_pread() may be called from the loop thread; the
 * completion queue and wakeup are internally synchronised so worker backends can
 * post from other threads. portico_aio_drain() must be called from a single
 * consumer thread (typically the loop thread that owns wakeup_fd).
 */
#ifndef PORTICO_AIO_H
#define PORTICO_AIO_H

#include <stddef.h>
#include <sys/types.h>   /* ssize_t, off_t */

#ifdef __cplusplus
extern "C" {
#endif

/** Selects how blocking work is performed. Only BLOCKING is implemented today;
 *  THREADPOOL and IOURING are reserved so callers can opt in without an API
 *  change once those backends land. */
typedef enum {
    PORTICO_AIO_BLOCKING = 0,   /**< pread() inline on the submitting thread (oracle/fallback). */
    PORTICO_AIO_THREADPOOL,     /**< (reserved) N worker threads. */
    PORTICO_AIO_IOURING         /**< (reserved) Linux io_uring. */
} portico_aio_backend_t;

typedef struct {
    portico_aio_backend_t backend;   /**< default PORTICO_AIO_BLOCKING. */
    int threads;                     /**< worker count (threaded backends; ignored otherwise). */
    int queue_depth;                 /**< max in-flight ops (threaded/ring backends; 0 = default). */
} portico_aio_cfg_t;

/** Opaque instance. */
typedef struct portico_aio portico_aio_t;

/** Completion callback. @p res is the byte count read (>= 0) or -errno (< 0).
 *  Fired by portico_aio_drain() on the consumer thread, never inline at submit. */
typedef void (*portico_aio_cb_t)(void *user, ssize_t res);

/**
 * Create an instance. Returns NULL on failure (errno set: ENOSYS for a backend
 * that is not yet implemented, else the underlying failure). @p cfg may be NULL
 * for all-defaults (blocking backend).
 */
portico_aio_t *portico_aio_create(const portico_aio_cfg_t *cfg);

/** Destroy an instance, releasing backend resources and any undrained
 *  completions (their callbacks are NOT fired). Drain first if you need them. */
void portico_aio_destroy(portico_aio_t *a);

/**
 * The completion-notification fd (an eventfd). Add it to your epoll set with
 * EPOLLIN; when it becomes readable, call portico_aio_drain(). Always valid for
 * the life of the instance. Do not read/write it yourself.
 */
int portico_aio_wakeup_fd(portico_aio_t *a);

/**
 * Submit a positional read: read up to @p len bytes from @p fd at @p off into
 * @p buf (caller-owned; must outlive the completion). On completion @p cb is
 * invoked with the byte count or -errno.
 *
 * @return 0 if accepted (a completion WILL be delivered via drain), or -errno if
 *         rejected synchronously (e.g. -EINVAL, -EAGAIN when a bounded queue is
 *         full); in that case no completion is produced.
 */
int portico_aio_pread(portico_aio_t *a, int fd, void *buf, size_t len, off_t off,
                      portico_aio_cb_t cb, void *user);

/**
 * Deliver all ready completions: clears wakeup_fd, reaps any backend-side results,
 * and fires each queued callback (in submission order, outside internal locks).
 * Safe to call at any time; returns the number of callbacks fired.
 */
int portico_aio_drain(portico_aio_t *a);

#ifdef __cplusplus
}
#endif

#endif /* PORTICO_AIO_H */
