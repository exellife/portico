/* ============================================================================
 * WSLib - Essential Utilities Implementation
 * 
 * Self-contained utility functions for scalable WebSocket implementation
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sched.h>

/* ============================================================================
 * WebSocket Cryptography Implementation
 * ============================================================================ */

int ws_generate_accept_key(const char *client_key, char *accept_key) {
    if (!client_key || !accept_key) {
        return -1;
    }
    
    /* Concatenate client key with WebSocket magic string */
    char combined[WS_WEBSOCKET_KEY_LENGTH + strlen(WS_WEBSOCKET_MAGIC_STRING) + 1];
    snprintf(combined, sizeof(combined), "%s%s", client_key, WS_WEBSOCKET_MAGIC_STRING);
    
    /* Compute SHA-1 hash */
    uint8_t hash[WS_SHA1_DIGEST_LENGTH];
    if (ws_sha1((const uint8_t*)combined, strlen(combined), hash) != 0) {
        return -1;
    }
    
    /* Encode as base64 */
    if (ws_base64_encode(hash, WS_SHA1_DIGEST_LENGTH, accept_key, WS_WEBSOCKET_ACCEPT_LENGTH + 1) != WS_WEBSOCKET_ACCEPT_LENGTH) {
        return -1;
    }
    
    return 0;
}

bool ws_validate_websocket_key(const char *key) {
    if (!key) return false;
    
    /* Key should be exactly 24 characters */
    if (strlen(key) != WS_WEBSOCKET_KEY_LENGTH) {
        return false;
    }
    
    /* Validate base64 format */
    return ws_is_valid_base64(key, WS_WEBSOCKET_KEY_LENGTH);
}

/* SHA-1 implementation (minimal, secure enough for WebSocket accept keys) */
int ws_sha1(const uint8_t *data, size_t len, uint8_t *hash) {
    /* Input validation */
    if (!data || !hash) {
        return -1;
    }
    
    /* This is a simplified SHA-1 implementation for WebSocket keys */
    /* In production, you might want to use a proper crypto library */
    
    uint32_t h[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    
    uint64_t bit_len = len * 8;
    uint8_t *msg = malloc(len + 72); /* Space for padding */
    if (!msg) return -1;
    
    memcpy(msg, data, len);
    msg[len] = 0x80;
    
    /* Calculate padding */
    size_t new_len = len + 1;
    while (new_len % 64 != 56) {
        msg[new_len++] = 0;
    }
    
    /* Append length */
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }
    new_len += 8;
    
    /* Process in 512-bit chunks */
    for (size_t chunk = 0; chunk < new_len; chunk += 64) {
        uint32_t w[80];
        
        /* Break chunk into words */
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[chunk + i * 4] << 24) |
                   (msg[chunk + i * 4 + 1] << 16) |
                   (msg[chunk + i * 4 + 2] << 8) |
                   (msg[chunk + i * 4 + 3]);
        }
        
        /* Extend words */
        for (int i = 16; i < 80; i++) {
            uint32_t tmp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w[i] = (tmp << 1) | (tmp >> 31);
        }
        
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    
    /* Output hash */
    for (int i = 0; i < 5; i++) {
        hash[i * 4] = (h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = h[i] & 0xFF;
    }
    
    free(msg);
    return 0;
}

/* Base64 encoding */
int ws_base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_size) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    size_t encoded_len = WS_BASE64_ENCODED_SIZE(input_len);
    if (output_size < encoded_len + 1) {
        return -1;
    }
    
    size_t i = 0, j = 0;
    
    while (i < input_len) {
        uint32_t a = i < input_len ? input[i++] : 0;
        uint32_t b = i < input_len ? input[i++] : 0;
        uint32_t c = i < input_len ? input[i++] : 0;
        
        uint32_t triple = (a << 16) | (b << 8) | c;
        
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >> 6) & 0x3F];
        output[j++] = base64_chars[triple & 0x3F];
    }
    
    /* Add padding */
    for (size_t pad = 0; pad < (3 - input_len % 3) % 3; pad++) {
        output[encoded_len - 1 - pad] = '=';
    }
    
    output[encoded_len] = '\0';
    return (int)encoded_len;
}

bool ws_is_valid_base64(const char *input, size_t len) {
    if (!input) return false;
    
    /* Base64 strings must be multiples of 4 in length */
    if (len % 4 != 0) return false;
    
    bool padding_found = false;
    /* Check each character */
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
            return false;
        }
        
        /* Once padding is found, all remaining chars must be padding */
        if (c == '=') {
            padding_found = true;
        } else if (padding_found) {
            return false; /* Non-padding character after padding */
        }
    }
    
    return true;
}

/* ============================================================================
 * String Utilities Implementation
 * ============================================================================ */

int ws_strcasecmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int diff = tolower(*s1) - tolower(*s2);
        if (diff != 0) return diff;
        s1++; s2++;
    }
    return tolower(*s1) - tolower(*s2);
}

int ws_strncasecmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    
    for (size_t i = 0; i < n; i++) {
        int diff = tolower(*s1) - tolower(*s2);
        if (diff != 0 || *s1 == '\0' || *s2 == '\0') {
            return diff;
        }
        s1++; s2++;
    }
    return 0;  /* All n characters matched */
}

char* ws_trim_whitespace(char *str) {
    if (!str) return NULL;
    
    /* Trim leading whitespace */
    while (isspace(*str)) str++;
    
    if (*str == '\0') return str;
    
    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    end[1] = '\0';
    
    return str;
}

bool ws_string_contains_token(const char *str, const char *token) {
    if (!str || !token) return false;
    
    char *str_copy = strdup(str);
    if (!str_copy) return false;
    
    char *saveptr;
    char *current = strtok_r(str_copy, " \t,", &saveptr);
    
    while (current) {
        if (ws_strcasecmp(ws_trim_whitespace(current), token) == 0) {
            free(str_copy);
            return true;
        }
        current = strtok_r(NULL, " \t,", &saveptr);
    }
    
    free(str_copy);
    return false;
}

/* ============================================================================
 * Network Utilities Implementation
 * ============================================================================ */

int ws_set_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int ws_set_socket_reuseaddr(int fd, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

int ws_set_socket_reuseport(int fd, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

int ws_get_socket_error(int fd) {
    if (fd < 0) return -1;  /* Invalid socket */
    
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return -1;  /* Error getting socket error */
    }
    return error;
}

int ws_set_socket_nodelay(int fd, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

int ws_set_socket_keepalive(int fd, bool enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
}

int ws_sockaddr_to_string(const struct sockaddr *addr, char *buffer, size_t buffer_size) {
    if (!addr || !buffer || buffer_size == 0) return -1;
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) {
            snprintf(buffer, buffer_size, "%s:%d", ip_str, ntohs(sin->sin_port));
            return 0;
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
        char ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str))) {
            snprintf(buffer, buffer_size, "[%s]:%d", ip_str, ntohs(sin6->sin6_port));
            return 0;
        }
    }
    
    return -1;
}

/* ============================================================================
 * Hash Functions Implementation
 * ============================================================================ */

uint64_t ws_fnv1a_hash(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t*)data;
    uint64_t hash = 14695981039346656037ULL; /* FNV offset basis */
    
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL; /* FNV prime */
    }
    
    return hash;
}

uint64_t ws_fnv1a_hash_uint32(uint32_t value) {
    return ws_fnv1a_hash(&value, sizeof(value));
}

/* ============================================================================
 * Atomic Stack Implementation
 * ============================================================================ */

int ws_atomic_stack_init(ws_atomic_stack_t *stack, size_t capacity) {
    if (!stack || capacity == 0) return -1;
    
    stack->data = malloc(capacity * sizeof(uint32_t));
    if (!stack->data) return -1;
    
    /* Initialize with all indices available */
    for (size_t i = 0; i < capacity; i++) {
        stack->data[i] = (i + 1 < capacity) ? (uint32_t)(i + 1) : UINT32_MAX;
    }
    
    stack->capacity = capacity;
    atomic_store(&stack->head, 0); /* Start with index 0 at head */
    
    return 0;
}

void ws_atomic_stack_destroy(ws_atomic_stack_t *stack) {
    if (stack && stack->data) {
        free(stack->data);
        stack->data = NULL;
        stack->capacity = 0;
        atomic_store(&stack->head, UINTPTR_MAX);
    }
}

bool ws_atomic_stack_push(ws_atomic_stack_t *stack, uint32_t value) {
    if (!stack || !stack->data || value >= stack->capacity) return false;
    
    uintptr_t head = atomic_load(&stack->head);
    
    do {
        stack->data[value] = (head == UINTPTR_MAX) ? UINT32_MAX : (uint32_t)head;
    } while (!atomic_compare_exchange_weak(&stack->head, &head, value));
    
    return true;
}

bool ws_atomic_stack_pop(ws_atomic_stack_t *stack, uint32_t *value) {
    if (!stack || !stack->data || !value) return false;
    
    uintptr_t head = atomic_load(&stack->head);
    
    while (head != UINTPTR_MAX) {
        uint32_t next = stack->data[head];
        if (atomic_compare_exchange_weak(&stack->head, &head, 
                                        (next == UINT32_MAX) ? UINTPTR_MAX : next)) {
            *value = (uint32_t)head;
            return true;
        }
    }
    
    return false;
}

/* ============================================================================
 * Performance Counters Implementation
 * ============================================================================ */

void ws_perf_counters_init(ws_perf_counters_t *counters) {
    if (!counters) return;
    
    atomic_store(&counters->operations, 0);
    atomic_store(&counters->bytes_processed, 0);
    atomic_store(&counters->active_count, 0);
    atomic_store(&counters->peak_count, 0);
}

void ws_perf_counters_increment_ops(ws_perf_counters_t *counters) {
    if (counters) {
        atomic_fetch_add(&counters->operations, 1);
    }
}

void ws_perf_counters_add_bytes(ws_perf_counters_t *counters, uint64_t bytes) {
    if (counters) {
        atomic_fetch_add(&counters->bytes_processed, bytes);
    }
}

void ws_perf_counters_increment_active(ws_perf_counters_t *counters) {
    if (!counters) return;
    
    uint32_t new_count = atomic_fetch_add(&counters->active_count, 1) + 1;
    
    /* Update peak if necessary */
    uint_fast32_t current_peak = atomic_load(&counters->peak_count);
    uint_fast32_t new_peak = new_count;
    while (new_peak > current_peak) {
        if (atomic_compare_exchange_weak(&counters->peak_count, &current_peak, new_peak)) {
            break;
        }
    }
}

void ws_perf_counters_decrement_active(ws_perf_counters_t *counters) {
    if (counters) {
        atomic_fetch_sub(&counters->active_count, 1);
    }
}

/* ============================================================================
 * Thread Utilities Implementation
 * ============================================================================ */

int ws_set_thread_affinity(pthread_t thread, int cpu_id) {
    if (cpu_id < 0) return 0; /* No affinity */
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    return pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}

int ws_create_eventfd(void) {
    return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

int ws_eventfd_notify(int eventfd) {
    uint64_t value = 1;
    return write(eventfd, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
}

int ws_eventfd_wait(int eventfd) {
    uint64_t value;
    return read(eventfd, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
}

/* ============================================================================
 * Memory Utilities Implementation
 * ============================================================================ */

void* ws_aligned_alloc(size_t alignment, size_t size) {
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) == 0) {
        return ptr;
    }
    return NULL;
}

void ws_aligned_free(void *ptr) {
    free(ptr);
}
