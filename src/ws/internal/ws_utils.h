#ifndef WS_UTILS_H
#define WS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdatomic.h>
#include <pthread.h>

/* ============================================================================
 * WSLib Essential Utilities
 * 
 * Self-contained utility functions needed for scalable WebSocket implementation
 * ============================================================================ */

/* WebSocket constants */
#define WS_WEBSOCKET_KEY_LENGTH     24      /* Sec-WebSocket-Key length (base64) */
#define WS_WEBSOCKET_ACCEPT_LENGTH  28      /* Sec-WebSocket-Accept length (base64) */
#define WS_WEBSOCKET_MAGIC_STRING   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_SHA1_DIGEST_LENGTH       20      /* SHA-1 digest length */
#define WS_BASE64_ENCODED_SIZE(n)   (((n) + 2) / 3 * 4)

/* Alignment and memory utilities */
#define WS_ALIGN_UP(x, align)       (((x) + (align) - 1) & ~((align) - 1))
#define WS_ALIGN_DOWN(x, align)     ((x) & ~((align) - 1))
#define WS_IS_ALIGNED(x, align)     (((x) & ((align) - 1)) == 0)

/* ============================================================================
 * WebSocket Cryptography
 * ============================================================================ */

/* Generate WebSocket accept key from client key */
int ws_generate_accept_key(const char *client_key, char *accept_key);

/* Validate WebSocket key format */
bool ws_validate_websocket_key(const char *key);

/* SHA-1 hash function */
int ws_sha1(const uint8_t *data, size_t len, uint8_t *hash);

/* Base64 encoding/decoding */
int ws_base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_size);
int ws_base64_decode(const char *input, uint8_t *output, size_t output_size);
bool ws_is_valid_base64(const char *input, size_t len);

/* ============================================================================
 * String Utilities
 * ============================================================================ */

/* Case-insensitive string comparison */
int ws_strcasecmp(const char *s1, const char *s2);
int ws_strncasecmp(const char *s1, const char *s2, size_t n);

/* String trimming */
char* ws_trim_whitespace(char *str);

/* Safe string copy */
int ws_strlcpy(char *dst, const char *src, size_t size);

/* Check if string contains token (case-insensitive) */
bool ws_string_contains_token(const char *str, const char *token);

/* ============================================================================
 * Network Utilities
 * ============================================================================ */

/* Socket operations */
int ws_set_socket_nonblocking(int fd);
int ws_set_socket_reuseaddr(int fd, bool enable);
int ws_set_socket_reuseport(int fd, bool enable);
int ws_get_socket_error(int fd);
int ws_set_socket_nodelay(int fd, bool enable);
int ws_set_socket_keepalive(int fd, bool enable);

/* Address utilities */
int ws_sockaddr_to_string(const struct sockaddr *addr, char *buffer, size_t buffer_size);

/* ============================================================================
 * Atomic Stack (Lock-free)
 * ============================================================================ */

typedef struct {
    atomic_uintptr_t head;
    uint32_t *data;
    size_t capacity;
} ws_atomic_stack_t;

/* Atomic stack operations */
int ws_atomic_stack_init(ws_atomic_stack_t *stack, size_t capacity);
void ws_atomic_stack_destroy(ws_atomic_stack_t *stack);
bool ws_atomic_stack_push(ws_atomic_stack_t *stack, uint32_t value);
bool ws_atomic_stack_pop(ws_atomic_stack_t *stack, uint32_t *value);

/* ============================================================================
 * Hash Functions (for use with hierarchical hash table)
 * ============================================================================ */

/* FNV-1a hash function */
uint64_t ws_fnv1a_hash(const void *data, size_t len);
uint64_t ws_fnv1a_hash_uint32(uint32_t value);

/* ============================================================================
 * Performance Monitoring
 * ============================================================================ */

/* Atomic performance counters */
typedef struct {
    atomic_uint_fast64_t operations;
    atomic_uint_fast64_t bytes_processed;
    atomic_uint_fast32_t active_count;
    atomic_uint_fast32_t peak_count;
} ws_perf_counters_t;

/* Performance counter operations */
void ws_perf_counters_init(ws_perf_counters_t *counters);
void ws_perf_counters_increment_ops(ws_perf_counters_t *counters);
void ws_perf_counters_add_bytes(ws_perf_counters_t *counters, uint64_t bytes);
void ws_perf_counters_increment_active(ws_perf_counters_t *counters);
void ws_perf_counters_decrement_active(ws_perf_counters_t *counters);

/* ============================================================================
 * Thread Utilities
 * ============================================================================ */

/* CPU affinity */
int ws_set_thread_affinity(pthread_t thread, int cpu_id);

/* Eventfd operations */
int ws_create_eventfd(void);
int ws_eventfd_notify(int eventfd);
int ws_eventfd_wait(int eventfd);

/* ============================================================================
 * Memory Utilities
 * ============================================================================ */

/* Aligned memory allocation */
void* ws_aligned_alloc(size_t alignment, size_t size);
void ws_aligned_free(void *ptr);

/* Memory barriers */
#define WS_MEMORY_BARRIER() atomic_thread_fence(memory_order_seq_cst)
#define WS_COMPILER_BARRIER() atomic_signal_fence(memory_order_seq_cst)

#endif /* WS_UTILS_H */
