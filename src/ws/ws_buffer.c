/* ============================================================================
 * WSLib - High-Performance Buffer Pool Management
 * 
 * Lock-free buffer allocation system optimized for WebSocket message handling
 * Supports small (1KB), medium (4KB), and large (16KB) buffer pools
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdatomic.h>

/* ============================================================================
 * Buffer Pool Constants and Configuration
 * ============================================================================ */

/* Cache line size for alignment optimization */
#define CACHE_LINE_SIZE 64

/* Buffer pool magic numbers for corruption detection */
#define WS_BUFFER_POOL_MAGIC    0xBEEFCAFE
#define WS_BUFFER_FREE_MAGIC    0xDEADBEEF

/* ============================================================================
 * Buffer Pool Internal Structures
 * ============================================================================ */

/* Header for each buffer (stored at beginning of buffer) */
typedef struct __attribute__((packed)) {
    uint32_t magic;                /* Magic number for corruption detection */
    uint32_t pool_id;              /* Which pool this buffer belongs to */
    uint32_t buffer_index;         /* Index of this buffer in the pool */
    uint32_t next_free;            /* Next free buffer (when in free list) */
} ws_buffer_header_t;

/* ============================================================================
 * Buffer Pool Initialization and Cleanup
 * ============================================================================ */

int ws_buffer_pool_init(ws_buffer_pool_t *pool, uint32_t buffer_size, uint32_t buffer_count) {
    if (!pool || buffer_size == 0 || buffer_count == 0) {
        WS_ERROR_LOG("Invalid buffer pool parameters");
        return -1;
    }

    /* Clear the pool structure */
    memset(pool, 0, sizeof(ws_buffer_pool_t));

    /* Ensure buffer size includes header and is cache-aligned */
    uint32_t header_size = sizeof(ws_buffer_header_t);
    uint32_t aligned_buffer_size = WS_ALIGN_UP(buffer_size + header_size, CACHE_LINE_SIZE);
    
    pool->buffer_size = aligned_buffer_size;
    pool->buffer_count = buffer_count;

    /* Calculate total memory needed */
    size_t total_memory = (size_t)aligned_buffer_size * buffer_count;
    
    /* Add space for the free list indices */
    size_t free_list_size = buffer_count * sizeof(uint32_t);
    total_memory += free_list_size;

    WS_DEBUG_LOG("Initializing buffer pool: %u buffers of %u bytes each (total: %zu bytes)",
                 buffer_count, aligned_buffer_size, total_memory);

    /* Allocate aligned memory using mmap for better performance */
    pool->memory_block = mmap(NULL, total_memory, 
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS,
                             -1, 0);
    
    if (pool->memory_block == MAP_FAILED) {
        WS_ERROR_LOG("Failed to allocate buffer pool memory: %s", strerror(errno));
        return -1;
    }

    /* Advise kernel about memory usage patterns */
    if (madvise(pool->memory_block, total_memory, MADV_WILLNEED) != 0) {
        WS_DEBUG_LOG("madvise failed (non-critical): %s", strerror(errno));
    }

    /* Set up free list array at the end of the memory block */
    pool->free_next = (uint32_t *)((char *)pool->memory_block + 
                                  (size_t)aligned_buffer_size * buffer_count);

    /* Initialize all buffers and build free list */
    for (uint32_t i = 0; i < buffer_count; i++) {
        char *buffer_ptr = (char *)pool->memory_block + (size_t)i * aligned_buffer_size;
        ws_buffer_header_t *header = (ws_buffer_header_t *)buffer_ptr;
        
        /* Initialize buffer header */
        header->magic = WS_BUFFER_FREE_MAGIC;
        header->pool_id = 0; /* Will be set when pool is assigned to thread */
        header->buffer_index = i;
        header->next_free = (i == buffer_count - 1) ? WS_BUFFER_INVALID_INDEX : i + 1;
        
        /* Set up free list pointers */
        pool->free_next[i] = header->next_free;
    }

    /* Initialize atomic free list head (starts with buffer 0) */
    atomic_store(&pool->free_head, 0);
    
    /* Initialize statistics */
    atomic_store(&pool->allocated_count, 0);
    atomic_store(&pool->peak_usage, 0);

    WS_DEBUG_LOG("Buffer pool initialized successfully: %u buffers ready", buffer_count);
    return 0;
}

void ws_buffer_pool_cleanup(ws_buffer_pool_t *pool) {
    if (!pool || !pool->memory_block) {
        return;
    }

    /* Calculate total memory size for munmap */
    size_t total_memory = (size_t)pool->buffer_size * pool->buffer_count + 
                         pool->buffer_count * sizeof(uint32_t);

    /* Unmap the memory */
    if (munmap(pool->memory_block, total_memory) != 0) {
        WS_ERROR_LOG("Failed to unmap buffer pool memory: %s", strerror(errno));
    }

    /* Clear the structure */
    memset(pool, 0, sizeof(ws_buffer_pool_t));
    
    WS_DEBUG_LOG("Buffer pool cleaned up");
}

/* ============================================================================
 * Adaptive Buffer Pool Management
 * ============================================================================ */

int ws_buffer_pool_init_adaptive(ws_buffer_pool_t *pool, uint32_t buffer_size, 
                                uint32_t initial_count, uint32_t max_count) {
    if (!pool || buffer_size == 0 || initial_count == 0 || max_count < initial_count) {
        WS_ERROR_LOG("Invalid adaptive buffer pool parameters");
        return -1;
    }

    /* Initialize regular pool with smart sizing (4x initial for headroom) */
    uint32_t actual_initial = initial_count * 4;
    if (actual_initial > max_count) {
        actual_initial = max_count;
    }

    int result = ws_buffer_pool_init(pool, buffer_size, actual_initial);
    if (result != 0) {
        return result;
    }

    /* Initialize adaptive fields */
    pool->initial_buffer_count = initial_count;
    pool->max_buffer_count = max_count;
    atomic_store(&pool->exhaustion_count, 0);
    atomic_store(&pool->expanding, false);
    pool->last_expansion_time = 0;
    pool->expansion_cooldown_sec = 5; /* 5 second cooldown between expansions */

    WS_DEBUG_LOG("Created adaptive buffer pool: requested=%u, actual=%u, max=%u", 
                 initial_count, actual_initial, max_count);

    return 0;
}

int ws_buffer_pool_expand_safe(ws_buffer_pool_t *pool, uint32_t additional_buffers) {
    if (!pool || additional_buffers == 0) {
        return -1;
    }

    /* Check if we can expand */
    if (pool->buffer_count + additional_buffers > pool->max_buffer_count) {
        WS_DEBUG_LOG("Cannot expand buffer pool: would exceed maximum (%u + %u > %u)",
                     pool->buffer_count, additional_buffers, pool->max_buffer_count);
        return -1;
    }

    /* Conservative approach: For now, we don't support runtime expansion of buffer pools
     * This is because buffer pool expansion requires complex memory reallocation and
     * pointer fixup that could interfere with lock-free operations.
     * 
     * Instead, we use smart pre-sizing (4x initial) to prevent exhaustion.
     */
    WS_DEBUG_LOG("Buffer pool expansion requested but not implemented for safety");
    return -1;
}

bool ws_buffer_pool_should_expand(ws_buffer_pool_t *pool) {
    if (!pool) {
        return false;
    }

    /* Conservative approach: Disable automatic expansion for production safety */
    return false;

    /* Future implementation could check:
     * - Current utilization > 90%
     * - Exhaustion events > threshold
     * - Time since last expansion
     * - Maximum pool size not reached
     */
}

void ws_buffer_pool_reset_exhaustion_counter(ws_buffer_pool_t *pool) {
    if (pool) {
        atomic_store(&pool->exhaustion_count, 0);
    }
}

/* ============================================================================
 * Buffer Allocation and Deallocation (Lock-Free)
 * ============================================================================ */

uint32_t ws_buffer_pool_allocate(ws_buffer_pool_t *pool) {
    if (!pool) {
        WS_ERROR_LOG("Invalid buffer pool");
        return WS_BUFFER_INVALID_INDEX;
    }

    uint_fast32_t current_head, next_head;
    ws_buffer_header_t *header;
    
    /* Lock-free allocation using compare-and-swap */
    do {
        current_head = atomic_load(&pool->free_head);
        
        /* Check if pool is empty */
        if (current_head == WS_BUFFER_INVALID_INDEX) {
            /* Track exhaustion event for adaptive sizing */
            atomic_fetch_add(&pool->exhaustion_count, 1);
            WS_DEBUG_LOG("Buffer pool exhausted (event #%u)", 
                        (uint32_t)atomic_load(&pool->exhaustion_count));
            return WS_BUFFER_INVALID_INDEX;
        }
        
        /* Get the header of the current head buffer */
        char *buffer_ptr = (char *)pool->memory_block + 
                          (size_t)current_head * pool->buffer_size;
        header = (ws_buffer_header_t *)buffer_ptr;
        
        /* Verify buffer integrity */
        if (header->magic != WS_BUFFER_FREE_MAGIC || 
            header->buffer_index != current_head) {
            WS_ERROR_LOG("Buffer pool corruption detected at index %u", (uint32_t)current_head);
            return WS_BUFFER_INVALID_INDEX;
        }
        
        next_head = pool->free_next[current_head];
        
    } while (!atomic_compare_exchange_weak(&pool->free_head, &current_head, next_head));

    /* Mark buffer as allocated */
    header->magic = WS_BUFFER_POOL_MAGIC;
    
    /* Update statistics */
    uint_fast32_t current_allocated = atomic_fetch_add(&pool->allocated_count, 1) + 1;
    
    /* Update peak usage (relaxed ordering for performance) */
    uint_fast32_t current_peak = atomic_load_explicit(&pool->peak_usage, memory_order_relaxed);
    while (current_allocated > current_peak) {
        if (atomic_compare_exchange_weak_explicit(&pool->peak_usage, &current_peak, 
                                                 current_allocated,
                                                 memory_order_relaxed, 
                                                 memory_order_relaxed)) {
            break;
        }
    }

    WS_DEBUG_LOG("Allocated buffer %u (allocated count: %u)", (uint32_t)current_head, (uint32_t)current_allocated);
    return (uint32_t)current_head;
}

void ws_buffer_pool_deallocate(ws_buffer_pool_t *pool, uint32_t buffer_idx) {
    if (!pool || buffer_idx >= pool->buffer_count) {
        WS_ERROR_LOG("Invalid buffer pool or buffer index %u", buffer_idx);
        return;
    }

    /* Get buffer pointer and header */
    char *buffer_ptr = (char *)pool->memory_block + (size_t)buffer_idx * pool->buffer_size;
    ws_buffer_header_t *header = (ws_buffer_header_t *)buffer_ptr;
    
    /* Verify buffer was allocated and not corrupted */
    if (header->magic != WS_BUFFER_POOL_MAGIC || 
        header->buffer_index != buffer_idx) {
        WS_ERROR_LOG("Attempting to free invalid or corrupted buffer %u", buffer_idx);
        return;
    }

    /* Clear the buffer data (security measure) */
    char *data_ptr = buffer_ptr + sizeof(ws_buffer_header_t);
    size_t data_size = pool->buffer_size - sizeof(ws_buffer_header_t);
    memset(data_ptr, 0, data_size);

    /* Mark buffer as free and update free list atomically */
    header->magic = WS_BUFFER_FREE_MAGIC;
    
    uint_fast32_t current_head;
    do {
        current_head = atomic_load(&pool->free_head);
        pool->free_next[buffer_idx] = (uint32_t)current_head;
        header->next_free = (uint32_t)current_head;
        
    } while (!atomic_compare_exchange_weak(&pool->free_head, &current_head, (uint_fast32_t)buffer_idx));

    /* Update statistics */
    uint_fast32_t current_allocated = atomic_fetch_sub(&pool->allocated_count, 1) - 1;
    
    WS_DEBUG_LOG("Deallocated buffer %u (allocated count: %u)", buffer_idx, (uint32_t)current_allocated);
}

/* ============================================================================
 * Buffer Access and Utilities
 * ============================================================================ */

void* ws_buffer_pool_get_buffer(ws_buffer_pool_t *pool, uint32_t buffer_idx) {
    if (!pool || buffer_idx >= pool->buffer_count) {
        WS_ERROR_LOG("Invalid buffer pool or buffer index %u", buffer_idx);
        return NULL;
    }

    char *buffer_ptr = (char *)pool->memory_block + (size_t)buffer_idx * pool->buffer_size;
    ws_buffer_header_t *header = (ws_buffer_header_t *)buffer_ptr;
    
    /* Verify buffer is allocated */
    if (header->magic != WS_BUFFER_POOL_MAGIC || 
        header->buffer_index != buffer_idx) {
        WS_ERROR_LOG("Attempting to access invalid buffer %u", buffer_idx);
        return NULL;
    }

    /* Return pointer to data area (after header) */
    return buffer_ptr + sizeof(ws_buffer_header_t);
}

size_t ws_buffer_pool_get_data_size(ws_buffer_pool_t *pool) {
    if (!pool) {
        return 0;
    }
    return pool->buffer_size - sizeof(ws_buffer_header_t);
}

uint32_t ws_buffer_pool_get_buffer_index(ws_buffer_pool_t *pool, void *buffer_data) {
    if (!pool || !buffer_data) {
        return WS_BUFFER_INVALID_INDEX;
    }

    /* Calculate buffer index from pointer arithmetic */
    char *data_ptr = (char *)buffer_data;
    char *header_ptr = data_ptr - sizeof(ws_buffer_header_t);
    
    /* Verify pointer is within pool bounds */
    if (header_ptr < (char *)pool->memory_block) {
        return WS_BUFFER_INVALID_INDEX;
    }
    
    size_t offset = header_ptr - (char *)pool->memory_block;
    if (offset % pool->buffer_size != 0) {
        return WS_BUFFER_INVALID_INDEX;
    }
    
    uint32_t buffer_idx = offset / pool->buffer_size;
    if (buffer_idx >= pool->buffer_count) {
        return WS_BUFFER_INVALID_INDEX;
    }

    /* Verify header integrity */
    ws_buffer_header_t *header = (ws_buffer_header_t *)header_ptr;
    if (header->magic != WS_BUFFER_POOL_MAGIC || 
        header->buffer_index != buffer_idx) {
        return WS_BUFFER_INVALID_INDEX;
    }

    return buffer_idx;
}

/* ============================================================================
 * Buffer Pool Statistics and Monitoring
 * ============================================================================ */

void ws_buffer_pool_get_stats(ws_buffer_pool_t *pool, ws_buffer_pool_stats_t *stats) {
    if (!pool || !stats) {
        return;
    }

    memset(stats, 0, sizeof(ws_buffer_pool_stats_t));
    
    stats->total_buffers = pool->buffer_count;
    stats->allocated_buffers = (uint32_t)atomic_load(&pool->allocated_count);
    stats->peak_allocated = (uint32_t)atomic_load(&pool->peak_usage);
    stats->total_allocations = 0; /* Allocation counters not implemented */
    stats->total_deallocations = 0; /* Deallocation counters not implemented */
    stats->allocation_failures = 0; /* Failure counters not implemented */
    
    /* Adaptive pool statistics */
    stats->initial_buffer_count = pool->initial_buffer_count;
    stats->max_buffer_count = pool->max_buffer_count;
    stats->exhaustion_events = (uint32_t)atomic_load(&pool->exhaustion_count);
    stats->is_adaptive = (pool->max_buffer_count > 0);
}

void ws_buffer_pool_print_stats(ws_buffer_pool_t *pool, const char *pool_name) {
    if (!pool) {
        return;
    }

    ws_buffer_pool_stats_t stats;
    ws_buffer_pool_get_stats(pool, &stats);
    
    printf("=== Buffer Pool Stats: %s ===\n", pool_name ? pool_name : "Unknown");
    printf("Total buffers:     %u\n", stats.total_buffers);
    printf("Allocated buffers: %u\n", stats.allocated_buffers);
    printf("Free buffers:      %u\n", stats.total_buffers - stats.allocated_buffers);
    printf("Peak usage:        %u buffers\n", stats.peak_allocated);
    printf("Utilization:       %u%%\n", (stats.allocated_buffers * 100) / stats.total_buffers);
    printf("Total allocations: %lu\n", stats.total_allocations);
    printf("Total failures:    %lu\n", stats.allocation_failures);
    
    /* Show adaptive statistics if available */
    if (stats.is_adaptive) {
        printf("--- Adaptive Pool Info ---\n");
        printf("Initial size:      %u buffers\n", stats.initial_buffer_count);
        printf("Maximum size:      %u buffers\n", stats.max_buffer_count);
        printf("Exhaustion events: %u\n", stats.exhaustion_events);
        printf("Growth potential:  %u buffers (%.1fx)\n", 
               stats.max_buffer_count - stats.total_buffers,
               (float)stats.max_buffer_count / stats.total_buffers);
    }
    printf("\n");
}

/* ============================================================================
 * High-Level Buffer Management API
 * ============================================================================ */

/* Allocate from appropriate pool based on size */
ws_buffer_allocation_t ws_allocate_buffer_for_size(ws_event_thread_t *thread, size_t needed_size) {
    ws_buffer_allocation_t result = {0};
    
    if (!thread) {
        return result;
    }

    ws_buffer_pool_t *pool = NULL;
    
    /* Select appropriate pool based on size */
    size_t small_data_size = ws_buffer_pool_get_data_size(&thread->small_buffers);
    size_t medium_data_size = ws_buffer_pool_get_data_size(&thread->medium_buffers);
    size_t large_data_size = ws_buffer_pool_get_data_size(&thread->large_buffers);
    
    if (needed_size <= small_data_size) {
        pool = &thread->small_buffers;
    } else if (needed_size <= medium_data_size) {
        pool = &thread->medium_buffers;
    } else if (needed_size <= large_data_size) {
        pool = &thread->large_buffers;
    } else {
        WS_ERROR_LOG("Requested buffer size %zu exceeds maximum buffer size %zu", 
                     needed_size, large_data_size);
        return result;
    }

    /* Allocate from selected pool */
    uint32_t buffer_idx = ws_buffer_pool_allocate(pool);
    if (buffer_idx == WS_BUFFER_INVALID_INDEX) {
        WS_DEBUG_LOG("Failed to allocate buffer of size %zu", needed_size);
        return result;
    }

    void *data = ws_buffer_pool_get_buffer(pool, buffer_idx);
    if (!data) {
        ws_buffer_pool_deallocate(pool, buffer_idx);
        return result;
    }

    result.buffer_idx = buffer_idx;
    result.pool = pool;
    result.data = data;
    result.data_size = ws_buffer_pool_get_data_size(pool);
    
    return result;
}

void ws_deallocate_buffer(ws_buffer_allocation_t *allocation) {
    if (!allocation || !allocation->pool || allocation->buffer_idx == WS_BUFFER_INVALID_INDEX) {
        return;
    }

    ws_buffer_pool_deallocate(allocation->pool, allocation->buffer_idx);
    
    /* Clear allocation structure */
    memset(allocation, 0, sizeof(ws_buffer_allocation_t));
}

/* ============================================================================
 * Buffer Pool Stress Testing and Validation
 * ============================================================================ */

#ifdef WS_DEBUG
int ws_buffer_pool_validate(ws_buffer_pool_t *pool) {
    if (!pool || !pool->memory_block) {
        WS_ERROR_LOG("Invalid buffer pool");
        return -1;
    }

    uint32_t free_count = 0;
    uint32_t allocated_count = 0;
    
    /* Walk through all buffers and verify integrity */
    for (uint32_t i = 0; i < pool->buffer_count; i++) {
        char *buffer_ptr = (char *)pool->memory_block + (size_t)i * pool->buffer_size;
        ws_buffer_header_t *header = (ws_buffer_header_t *)buffer_ptr;
        
        if (header->buffer_index != i) {
            WS_ERROR_LOG("Buffer %u has incorrect index %u in header", i, header->buffer_index);
            return -1;
        }
        
        if (header->magic == WS_BUFFER_FREE_MAGIC) {
            free_count++;
        } else if (header->magic == WS_BUFFER_POOL_MAGIC) {
            allocated_count++;
        } else {
            WS_ERROR_LOG("Buffer %u has invalid magic number 0x%x", i, header->magic);
            return -1;
        }
    }

    uint32_t reported_allocated = atomic_load(&pool->allocated_count);
    if (allocated_count != reported_allocated) {
        WS_ERROR_LOG("Allocated count mismatch: counted %u, reported %u", 
                     allocated_count, reported_allocated);
        return -1;
    }

    if (free_count + allocated_count != pool->buffer_count) {
        WS_ERROR_LOG("Buffer count mismatch: free %u + allocated %u != total %u",
                     free_count, allocated_count, pool->buffer_count);
        return -1;
    }

    WS_DEBUG_LOG("Buffer pool validation passed: %u free, %u allocated", 
                 free_count, allocated_count);
    return 0;
}
#endif /* WS_DEBUG */
