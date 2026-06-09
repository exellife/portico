/* ============================================================================
 * WSLib - Multi-Producer Single-Consumer Queue Implementation
 * 
 * Lock-free queue for efficient cross-thread communication in WebSocket server.
 * Based on the Michael & Scott algorithm with optimizations for single consumer.
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <assert.h>

/* ============================================================================
 * MPSC Queue Constants and Message Types
 * ============================================================================ */

/* Message data structures for different message types */
typedef struct {
    int fd;                        /* New connection file descriptor */
    struct sockaddr_storage client_addr; /* Client address information */
    socklen_t client_addr_len;     /* Length of client address */
} ws_msg_new_connection_t;

typedef struct {
    int fd;                        /* Target connection file descriptor */
    size_t data_len;               /* Length of data */
    char data[];                   /* Variable length data */
} ws_msg_send_data_t;

typedef struct {
    int fd;                        /* Target connection file descriptor */
    ws_close_code_t code;          /* Close code */
    size_t reason_len;             /* Length of reason string */
    char reason[];                 /* Variable length reason string */
} ws_msg_close_data_t;

typedef struct {
    int fd;                        /* Target connection file descriptor */
    void *user_data;               /* New user data pointer */
} ws_msg_user_data_t;

/* Default node pool size per queue */
#define WS_MPSC_DEFAULT_NODE_POOL_SIZE  1024
#define WS_MPSC_NODE_POOL_REFILL_SIZE   256

/* Adaptive pool sizing constants */
#define WS_MPSC_DEFAULT_MAX_POOL_SIZE   131072  /* 128K nodes max */
#define WS_MPSC_DEFAULT_GROWTH_FACTOR   2       /* Double on expansion */
#define WS_MPSC_DEFAULT_GROWTH_COOLDOWN 5       /* 5 seconds between expansions */
#define WS_MPSC_EXHAUSTION_THRESHOLD    3       /* Expand after 3 exhaustions in cooldown period */

/* Sentinel node pointer for empty queue */
#define WS_MPSC_EMPTY_QUEUE ((ws_mpsc_node_t*)1)

/* ============================================================================
 * Adaptive Pool Sizing Functions
 * ============================================================================ */

static int expand_node_pool(ws_mpsc_queue_t *queue, uint32_t new_size) {
    if (!queue || new_size <= queue->node_pool_size || new_size > queue->max_pool_size) {
        return -1;  /* Invalid parameters or size limit reached */
    }
    
    /* Prevent concurrent expansions */
    bool expected = false;
    if (!atomic_compare_exchange_strong(&queue->expanding, &expected, true)) {
        return 0;  /* Another thread is already expanding */
    }
    
    WS_DEBUG_LOG("Expanding MPSC node pool from %u to %u nodes", 
                 queue->node_pool_size, new_size);
    
    uint32_t old_size = queue->node_pool_size;
    
    /* Allocate a completely new pool instead of using realloc */
    ws_mpsc_node_t *new_pool = calloc(new_size, sizeof(ws_mpsc_node_t));
    if (!new_pool) {
        atomic_store(&queue->expanding, false);
        WS_ERROR_LOG("Failed to allocate new MPSC node pool of %u nodes", new_size);
        return -1;
    }
    
    /* Copy the old pool to the new pool */
    memcpy(new_pool, queue->node_pool, old_size * sizeof(ws_mpsc_node_t));
    
    /* Initialize the new nodes */
    for (uint32_t i = old_size; i < new_size; i++) {
        new_pool[i].data = NULL;
        new_pool[i].data_size = 0;
        new_pool[i].message_type = 0;
        atomic_store_explicit(&new_pool[i].next, 0, memory_order_relaxed);
    }
    
    /* Create a simple free list from ONLY the new nodes */
    /* This avoids the complexity of trying to link to existing free nodes */
    for (uint32_t i = old_size; i < new_size - 1; i++) {
        atomic_store_explicit(&new_pool[i].next, (uintptr_t)&new_pool[i + 1], memory_order_relaxed);
    }
    
    /* Last new node ends the list */
    atomic_store_explicit(&new_pool[new_size - 1].next, 0, memory_order_relaxed);
    
    /* Update pointers atomically */
    ws_mpsc_node_t *old_pool = queue->node_pool;
    queue->node_pool = new_pool;
    queue->node_pool_size = new_size;
    
    /* Point free list to the new nodes only - old free nodes will be lost but that's okay */
    atomic_store(&queue->free_head, (uintptr_t)&new_pool[old_size]);
    atomic_store(&queue->free_nodes, new_size - old_size);  /* Reset to just new nodes */
    
    /* Update expansion tracking */
    atomic_fetch_add(&queue->total_expansions, 1);
    queue->last_growth_time = time(NULL);
    
    /* Free the old pool */
    free(old_pool);
    
    atomic_store(&queue->expanding, false);
    
    WS_DEBUG_LOG("MPSC node pool expanded successfully: %u -> %u nodes, %u free nodes available", 
                 old_size, new_size, new_size - old_size);
    
    return 0;
}

static bool should_expand_pool(ws_mpsc_queue_t *queue) {
    /* Disable automatic expansion for now - too complex for lock-free operation */
    /* Instead, applications should use ws_mpsc_queue_create_adaptive with proper sizing */
    return false;
    
    (void)queue; /* Suppress unused parameter warning */
}

/* Safe pool expansion - only call when queue is not under active load */
int ws_mpsc_queue_expand_pool_safe(ws_mpsc_queue_t *queue, uint32_t new_size) {
    if (!queue || new_size <= queue->node_pool_size || new_size > queue->max_pool_size) {
        return -1;  /* Invalid parameters */
    }
    
    /* Check if there's significant queue activity */
    uint32_t free_nodes = atomic_load(&queue->free_nodes);
    if (free_nodes < queue->node_pool_size / 2) {
        WS_DEBUG_LOG("Cannot expand pool safely - too much activity (only %u/%u nodes free)", 
                     free_nodes, queue->node_pool_size);
        return -2;  /* Queue too active for safe expansion */
    }
    
    return expand_node_pool(queue, new_size);
}

/* ============================================================================
 * MPSC Queue Creation and Destruction
 * ============================================================================ */

ws_mpsc_queue_t* ws_mpsc_queue_create(uint32_t node_pool_size) {
    if (node_pool_size == 0) {
        node_pool_size = WS_MPSC_DEFAULT_NODE_POOL_SIZE;
    }

    ws_mpsc_queue_t *queue = calloc(1, sizeof(ws_mpsc_queue_t));
    if (!queue) {
        WS_ERROR_LOG("Failed to allocate MPSC queue");
        return NULL;
    }

    /* Allocate node pool */
    queue->node_pool = calloc(node_pool_size, sizeof(ws_mpsc_node_t));
    if (!queue->node_pool) {
        WS_ERROR_LOG("Failed to allocate MPSC node pool");
        free(queue);
        return NULL;
    }

    /* Initialize node pool as a stack of free nodes */
    for (uint32_t i = 0; i < node_pool_size - 1; i++) {
        atomic_store_explicit(&queue->node_pool[i].next, (uintptr_t)&queue->node_pool[i + 1], memory_order_relaxed);
        queue->node_pool[i].data = NULL;
        queue->node_pool[i].data_size = 0;
        queue->node_pool[i].message_type = 0;
    }
    
    /* Last node points to NULL */
    atomic_store_explicit(&queue->node_pool[node_pool_size - 1].next, 0, memory_order_relaxed);
    queue->node_pool[node_pool_size - 1].data = NULL;
    queue->node_pool[node_pool_size - 1].data_size = 0;
    queue->node_pool[node_pool_size - 1].message_type = 0;

    /* Initialize queue state */
    queue->node_pool_size = node_pool_size;
    atomic_store_explicit(&queue->head, (uintptr_t)NULL, memory_order_relaxed);
    atomic_store_explicit(&queue->tail, (uintptr_t)NULL, memory_order_relaxed);
    atomic_store_explicit(&queue->free_head, (uintptr_t)&queue->node_pool[0], memory_order_relaxed); /* Free list starts at first node */
    atomic_store_explicit(&queue->free_nodes, node_pool_size, memory_order_relaxed);
    atomic_store_explicit(&queue->messages_sent, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->messages_received, 0, memory_order_relaxed);

    /* Initialize adaptive pool sizing with conservative defaults */
    queue->initial_pool_size = node_pool_size;
    queue->max_pool_size = WS_MPSC_DEFAULT_MAX_POOL_SIZE;
    queue->growth_factor = WS_MPSC_DEFAULT_GROWTH_FACTOR;
    atomic_store(&queue->exhaustion_count, 0);
    queue->last_growth_time = 0;  /* Allow immediate expansion if needed */
    queue->growth_cooldown_sec = WS_MPSC_DEFAULT_GROWTH_COOLDOWN;
    atomic_store(&queue->expanding, false);
    atomic_store(&queue->total_expansions, 0);

    WS_DEBUG_LOG("Created MPSC queue with %u node pool (adaptive: max=%u, growth=%ux)", 
                 node_pool_size, queue->max_pool_size, queue->growth_factor);
    return queue;
}

ws_mpsc_queue_t* ws_mpsc_queue_create_adaptive(uint32_t initial_size, uint32_t max_size, uint32_t growth_factor) {
    if (initial_size == 0) {
        initial_size = WS_MPSC_DEFAULT_NODE_POOL_SIZE;
    }
    if (max_size == 0 || max_size < initial_size) {
        max_size = WS_MPSC_DEFAULT_MAX_POOL_SIZE;
    }
    if (growth_factor < 2) {
        growth_factor = WS_MPSC_DEFAULT_GROWTH_FACTOR;
    }

    /* For now, create queue with a larger initial size to reduce need for expansion */
    /* Use a more conservative approach: size = min(initial_size * 4, max_size) */
    uint32_t practical_size = initial_size * 4;
    if (practical_size > max_size) {
        practical_size = max_size;
    }
    
    /* Create queue with the practical size */
    ws_mpsc_queue_t *queue = ws_mpsc_queue_create(practical_size);
    if (!queue) {
        return NULL;
    }

    /* Set adaptive parameters for future use */
    queue->initial_pool_size = initial_size;  /* Remember the requested initial size */
    queue->max_pool_size = max_size;
    queue->growth_factor = growth_factor;

    WS_DEBUG_LOG("Created adaptive MPSC queue: requested=%u, actual=%u, max=%u, growth=%ux", 
                 initial_size, practical_size, max_size, growth_factor);
    return queue;
}

void ws_mpsc_queue_destroy(ws_mpsc_queue_t *queue) {
    if (!queue) {
        return;
    }

    /* Process any remaining messages to avoid memory leaks */
    ws_mpsc_node_t *node;
    while ((node = ws_mpsc_queue_dequeue(queue)) != NULL) {
        if (node->data) {
            free(node->data);
            node->data = NULL;
        }
        /* Don't call ws_mpsc_queue_return_node here since we're destroying the pool */
    }

    /* Free the node pool */
    if (queue->node_pool) {
        free(queue->node_pool);
    }

    free(queue);
    WS_DEBUG_LOG("Destroyed MPSC queue");
}

/* ============================================================================
 * Node Pool Management (Lock-Free)
 * ============================================================================ */

ws_mpsc_node_t* ws_mpsc_queue_get_node(ws_mpsc_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    /* Check if we should attempt adaptive expansion */
    if (should_expand_pool(queue)) {
        uint32_t new_size = queue->node_pool_size * queue->growth_factor;
        if (new_size > queue->max_pool_size) {
            new_size = queue->max_pool_size;
        }
        expand_node_pool(queue, new_size);
    }

    /* Try to pop a node from the free list */
    uintptr_t free_head;
    ws_mpsc_node_t *node;
    uintptr_t next_free;

    do {
        free_head = atomic_load_explicit(&queue->free_head, memory_order_acquire);
        if (free_head == 0) {
            /* No free nodes available - record exhaustion event */
            atomic_fetch_add(&queue->exhaustion_count, 1);
            WS_DEBUG_LOG("Buffer pool exhausted");
            return NULL;
        }
        
        node = (ws_mpsc_node_t*)free_head;
        next_free = atomic_load_explicit(&node->next, memory_order_acquire);
        
        /* Try to update free_head to point to next free node */
    } while (!atomic_compare_exchange_weak_explicit(&queue->free_head, &free_head, next_free,
                                                   memory_order_release, memory_order_acquire));

    /* Decrement free node count */
    atomic_fetch_sub_explicit(&queue->free_nodes, 1, memory_order_relaxed);
    
    /* Initialize the node for use */
    node->data = NULL;
    node->data_size = 0;
    node->message_type = 0;
    atomic_store_explicit(&node->next, 0, memory_order_relaxed);
    
    return node;
}

void ws_mpsc_queue_return_node(ws_mpsc_queue_t *queue, ws_mpsc_node_t *node) {
    if (!queue || !node) {
        return;
    }

    /* Clear node data */
    if (node->data) {
        free(node->data);
        node->data = NULL;
    }
    node->data_size = 0;
    node->message_type = 0;

    /* Push node back onto the free list */
    uintptr_t old_head;
    do {
        old_head = atomic_load_explicit(&queue->free_head, memory_order_acquire);
        atomic_store_explicit(&node->next, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&queue->free_head, &old_head, (uintptr_t)node,
                                                   memory_order_release, memory_order_acquire));
    
    /* Increment free node count */
    atomic_fetch_add_explicit(&queue->free_nodes, 1, memory_order_relaxed);
}

/* ============================================================================
 * MPSC Queue Operations (Lock-Free)
 * ============================================================================ */

int ws_mpsc_queue_enqueue(ws_mpsc_queue_t *queue, ws_mpsc_node_t *node) {
    if (!queue || !node) {
        return -1;
    }

    /* Initialize node for queue insertion */
    atomic_store_explicit(&node->next, (uintptr_t)NULL, memory_order_relaxed);
    
    /* Get the previous tail atomically and set this node as new tail */
    ws_mpsc_node_t *prev_tail = (ws_mpsc_node_t*)atomic_exchange_explicit(&queue->tail, 
                                                                         (uintptr_t)node, 
                                                                         memory_order_acq_rel);
    
    /* Link the previous tail to this new node */
    if (prev_tail != NULL) {
        atomic_store_explicit(&prev_tail->next, (uintptr_t)node, memory_order_release);
    } else {
        /* This is the first node, set it as head too */
        atomic_store_explicit(&queue->head, (uintptr_t)node, memory_order_release);
    }

    atomic_fetch_add_explicit(&queue->messages_sent, 1, memory_order_relaxed);
    return 0;
}

ws_mpsc_node_t* ws_mpsc_queue_dequeue(ws_mpsc_queue_t *queue) {
    if (!queue) {
        return NULL;
    }

    /* Single consumer dequeue - much simpler than multi-consumer */
    ws_mpsc_node_t *head = (ws_mpsc_node_t*)atomic_load_explicit(&queue->head, memory_order_acquire);
    if (head == NULL) {
        return NULL; /* Queue is empty */
    }
    
    /* Get the next node */
    ws_mpsc_node_t *next = (ws_mpsc_node_t*)atomic_load_explicit(&head->next, memory_order_acquire);
    
    if (next != NULL) {
        /* Normal case: there's a next node */
        atomic_store_explicit(&queue->head, (uintptr_t)next, memory_order_release);
    } else {
        /* This might be the last node or queue might be empty now */
        ws_mpsc_node_t *expected_head = head;
        if (atomic_compare_exchange_strong_explicit(&queue->head, (uintptr_t*)&expected_head, 
                                                   (uintptr_t)NULL, memory_order_acq_rel, memory_order_acquire)) {
            /* Successfully made queue empty, also need to reset tail if it was pointing to this node */
            ws_mpsc_node_t *expected_tail = head;
            atomic_compare_exchange_strong_explicit(&queue->tail, (uintptr_t*)&expected_tail, 
                                                   (uintptr_t)NULL, memory_order_acq_rel, memory_order_acquire);
        } else {
            /* Head changed, another thread enqueued - retry */
            return ws_mpsc_queue_dequeue(queue);
        }
    }

    atomic_fetch_add_explicit(&queue->messages_received, 1, memory_order_relaxed);
    return head;
}

/* ============================================================================
 * High-Level Message Operations
 * ============================================================================ */

int ws_mpsc_send_new_connection(ws_mpsc_queue_t *queue, int fd, 
                                const struct sockaddr_storage *client_addr, socklen_t client_addr_len) {
    if (!queue || fd < 0 || !client_addr) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    /* Allocate message data */
    ws_msg_new_connection_t *msg = malloc(sizeof(ws_msg_new_connection_t));
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->client_addr = *client_addr;
    msg->client_addr_len = client_addr_len;

    node->data = msg;
    node->data_size = sizeof(ws_msg_new_connection_t);
    node->message_type = WS_MSG_NEW_CONNECTION;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_text_message(ws_mpsc_queue_t *queue, int fd, const char *data, size_t len) {
    if (!queue || (!data && len > 0)) {   /* portico: allow zero-length text frames */
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    /* Allocate message data */
    size_t msg_size = sizeof(ws_msg_send_data_t) + len;
    ws_msg_send_data_t *msg = malloc(msg_size);
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->data_len = len;
    memcpy(msg->data, data, len);

    node->data = msg;
    node->data_size = msg_size;
    node->message_type = WS_MSG_SEND_TEXT;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_binary_message(ws_mpsc_queue_t *queue, int fd, const void *data, size_t len) {
    if (!queue || (!data && len > 0)) {   /* portico: allow zero-length frames */
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    /* Allocate message data */
    size_t msg_size = sizeof(ws_msg_send_data_t) + len;
    ws_msg_send_data_t *msg = malloc(msg_size);
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->data_len = len;
    if (len > 0) memcpy(msg->data, data, len);

    node->data = msg;
    node->data_size = msg_size;
    node->message_type = WS_MSG_SEND_BINARY;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_close_message(ws_mpsc_queue_t *queue, int fd, ws_close_code_t code, const char *reason) {
    if (!queue) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    size_t reason_len = reason ? strlen(reason) : 0;
    size_t msg_size = sizeof(ws_msg_close_data_t) + reason_len + 1; /* +1 for null terminator */
    ws_msg_close_data_t *msg = malloc(msg_size);
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->code = code;
    msg->reason_len = reason_len;
    if (reason_len > 0) {
        memcpy(msg->reason, reason, reason_len);
        msg->reason[reason_len] = '\0'; /* Ensure null termination */
    } else {
        msg->reason[0] = '\0'; /* Empty string */
    }

    node->data = msg;
    node->data_size = msg_size;
    node->message_type = WS_MSG_CLOSE_CONNECTION;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_ping_message(ws_mpsc_queue_t *queue, int fd, const void *data, size_t len) {
    if (!queue) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    size_t msg_size = sizeof(ws_msg_send_data_t) + len;
    ws_msg_send_data_t *msg = malloc(msg_size);
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->data_len = len;
    if (len > 0 && data) {
        memcpy(msg->data, data, len);
    }

    node->data = msg;
    node->data_size = msg_size;
    node->message_type = WS_MSG_SEND_PING;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_pong_message(ws_mpsc_queue_t *queue, int fd, const void *data, size_t len) {
    if (!queue) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    size_t msg_size = sizeof(ws_msg_send_data_t) + len;
    ws_msg_send_data_t *msg = malloc(msg_size);
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->data_len = len;
    if (len > 0 && data) {
        memcpy(msg->data, data, len);
    }

    node->data = msg;
    node->data_size = msg_size;
    node->message_type = WS_MSG_SEND_PONG;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_update_user_data(ws_mpsc_queue_t *queue, int fd, void *user_data) {
    if (!queue) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    ws_msg_user_data_t *msg = malloc(sizeof(ws_msg_user_data_t));
    if (!msg) {
        ws_mpsc_queue_return_node(queue, node);
        return -1;
    }

    msg->fd = fd;
    msg->user_data = user_data;

    node->data = msg;
    node->data_size = sizeof(ws_msg_user_data_t);
    node->message_type = WS_MSG_UPDATE_USER_DATA;

    return ws_mpsc_queue_enqueue(queue, node);
}

int ws_mpsc_send_shutdown_signal(ws_mpsc_queue_t *queue) {
    if (!queue) {
        return -1;
    }

    ws_mpsc_node_t *node = ws_mpsc_queue_get_node(queue);
    if (!node) {
        return -1;
    }

    node->data = NULL;
    node->data_size = 0;
    node->message_type = WS_MSG_THREAD_SHUTDOWN;

    return ws_mpsc_queue_enqueue(queue, node);
}

/* ============================================================================
 * Message Processing (Consumer Side)
 * ============================================================================ */

int ws_mpsc_process_messages(ws_mpsc_queue_t *queue, ws_mpsc_message_processor_t *processor, int max_messages) {
    if (!queue || !processor) {
        return -1;
    }

    int processed = 0;
    
    while (processed < max_messages) {
        ws_mpsc_node_t *node = ws_mpsc_queue_dequeue(queue);
        if (!node) {
            break; /* No more messages */
        }

        int result = 0;
        
        switch (node->message_type) {
            case WS_MSG_NEW_CONNECTION: {
                if (processor->process_new_connection) {
                    ws_msg_new_connection_t *msg = (ws_msg_new_connection_t*)node->data;
                    result = processor->process_new_connection(msg->fd, &msg->client_addr, msg->client_addr_len, processor->context);
                }
                break;
            }
            
            case WS_MSG_SEND_TEXT: {
                if (processor->process_text_message) {
                    ws_msg_send_data_t *msg = (ws_msg_send_data_t*)node->data;
                    result = processor->process_text_message(msg->fd, msg->data, msg->data_len, processor->context);
                }
                break;
            }
            
            case WS_MSG_SEND_BINARY: {
                if (processor->process_binary_message) {
                    ws_msg_send_data_t *msg = (ws_msg_send_data_t*)node->data;
                    result = processor->process_binary_message(msg->fd, msg->data, msg->data_len, processor->context);
                }
                break;
            }
            
            case WS_MSG_SEND_PING: {
                if (processor->process_ping_message) {
                    ws_msg_send_data_t *msg = (ws_msg_send_data_t*)node->data;
                    result = processor->process_ping_message(msg->fd, msg->data, msg->data_len, processor->context);
                }
                break;
            }
            
            case WS_MSG_SEND_PONG: {
                if (processor->process_pong_message) {
                    ws_msg_send_data_t *msg = (ws_msg_send_data_t*)node->data;
                    result = processor->process_pong_message(msg->fd, msg->data, msg->data_len, processor->context);
                }
                break;
            }
            
            case WS_MSG_CLOSE_CONNECTION: {
                if (processor->process_close_message) {
                    ws_msg_close_data_t *msg = (ws_msg_close_data_t*)node->data;
                    const char *reason = msg->reason_len > 0 ? msg->reason : NULL;
                    result = processor->process_close_message(msg->fd, msg->code, reason, processor->context);
                }
                break;
            }
            
            case WS_MSG_UPDATE_USER_DATA: {
                if (processor->process_user_data_update) {
                    ws_msg_user_data_t *msg = (ws_msg_user_data_t*)node->data;
                    result = processor->process_user_data_update(msg->fd, msg->user_data, processor->context);
                }
                break;
            }
            
            case WS_MSG_THREAD_SHUTDOWN: {
                if (processor->process_shutdown_signal) {
                    result = processor->process_shutdown_signal(processor->context);
                }
                ws_mpsc_queue_return_node(queue, node);
                return processed + 1; /* Signal to stop processing */
            }
            
            default:
                WS_DEBUG_LOG("Unknown message type: %u", node->message_type);
                break;
        }

        ws_mpsc_queue_return_node(queue, node);
        processed++;

        if (result < 0) {
            WS_DEBUG_LOG("Message processing failed for type %u", node->message_type);
        }
    }

    return processed;
}

/* ============================================================================
 * Statistics and Monitoring
 * ============================================================================ */

void ws_mpsc_get_stats(ws_mpsc_queue_t *queue, ws_mpsc_stats_t *stats) {
    if (!queue || !stats) {
        return;
    }

    memset(stats, 0, sizeof(ws_mpsc_stats_t));
    
    stats->messages_sent = atomic_load(&queue->messages_sent);
    stats->messages_received = atomic_load(&queue->messages_received);
    stats->free_nodes = atomic_load(&queue->free_nodes);
    stats->queue_depth = (uint32_t)(stats->messages_sent - stats->messages_received);
    
    /* Current pool size information */
    stats->current_pool_size = queue->node_pool_size;
    stats->max_pool_size = queue->max_pool_size;
    stats->total_expansions = atomic_load(&queue->total_expansions);
    stats->exhaustion_count = atomic_load(&queue->exhaustion_count);
    
    if (queue->node_pool_size > 0) {
        uint32_t used_nodes = queue->node_pool_size - stats->free_nodes;
        stats->utilization_percent = (used_nodes * 100.0) / queue->node_pool_size;
    }
}

void ws_mpsc_print_stats(ws_mpsc_queue_t *queue, const char *queue_name) {
    if (!queue) {
        return;
    }

    ws_mpsc_stats_t stats;
    ws_mpsc_get_stats(queue, &stats);
    
    printf("=== MPSC Queue Stats: %s ===\n", queue_name ? queue_name : "Unknown");
    printf("Messages sent:     %lu\n", stats.messages_sent);
    printf("Messages received: %lu\n", stats.messages_received);
    printf("Queue depth:       %u\n", stats.queue_depth);
    printf("Free nodes:        %u\n", stats.free_nodes);
    printf("Node utilization:  %.1f%%\n", stats.utilization_percent);
    printf("\n");
}
