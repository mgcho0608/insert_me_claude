/*
 * queue.c -- FIFO queue with optional priority for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Provides allocation patterns with
 * pointer dereferences after malloc for CWE-416, and malloc(n * size) for CWE-122.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): qnode_create, queue_new,
 *            pq_entry_create, queue_merge
 *   CWE-122 (malloc with expr): queue_new_with_ring, pq_entry_create (data copy)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct QNode {
    void       *data;
    size_t      data_size;
    int         priority;
    int         seq;
    struct QNode *next;
} QNode;

typedef struct Queue {
    QNode  *head;
    QNode  *tail;
    int     size;
    int     max_size;
    int     seq_counter;
} Queue;

/* Heap-allocated ring buffer wrapper (used for fixed-capacity variant). */
typedef struct RingQueue {
    void  **slots;
    int     cap;
    int     head_idx;
    int     tail_idx;
    int     size;
} RingQueue;

/* Allocate a new queue node (copies data). */
QNode *qnode_create(const void *data, size_t data_size, int priority)
{
    QNode *node = malloc(sizeof(QNode));
    if (!node)
        return NULL;

    node->data = malloc(data_size * sizeof(char));
    if (!node->data) {
        free(node);
        return NULL;
    }
    memcpy(node->data, data, data_size);

    node->data_size = data_size;
    node->priority  = priority;
    node->seq       = 0;
    node->next      = NULL;
    return node;
}

/* Allocate a new Queue. max_size <= 0 means unbounded. */
Queue *queue_new(int max_size)
{
    Queue *q = malloc(sizeof(Queue));
    if (!q)
        return NULL;

    q->head        = NULL;
    q->tail        = NULL;
    q->size        = 0;
    q->max_size    = max_size;
    q->seq_counter = 0;
    return q;
}

/* Allocate a RingQueue with capacity `cap`. */
RingQueue *queue_new_with_ring(int cap)
{
    RingQueue *rq = malloc(sizeof(RingQueue));
    if (!rq)
        return NULL;

    rq->slots = malloc((size_t)cap * sizeof(void *));
    if (!rq->slots) {
        free(rq);
        return NULL;
    }
    memset(rq->slots, 0, (size_t)cap * sizeof(void *));

    rq->cap      = cap;
    rq->head_idx = 0;
    rq->tail_idx = 0;
    rq->size     = 0;
    return rq;
}

/* Enqueue data (makes a copy). Returns 0 on success. */
int queue_push(Queue *q, const void *data, size_t data_size, int priority)
{
    if (q->max_size > 0 && q->size >= q->max_size)
        return -1;

    QNode *node = qnode_create(data, data_size, priority);
    if (!node)
        return -1;

    node->seq = q->seq_counter++;

    if (!q->tail) {
        q->head = node;
        q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    q->size++;
    return 0;
}

/* Dequeue and return the front node (caller must free). NULL if empty. */
QNode *queue_pop(Queue *q)
{
    if (!q->head)
        return NULL;
    QNode *node = q->head;
    q->head = node->next;
    if (!q->head)
        q->tail = NULL;
    q->size--;
    node->next = NULL;
    return node;
}

/* Priority-queue entry creation (wraps arbitrary payload). */
typedef struct PQEntry {
    int    priority;
    int    id;
    size_t payload_len;
    char  *payload;
    int    flags;
} PQEntry;

PQEntry *pq_entry_create(int priority, int id, const char *payload, size_t payload_len)
{
    PQEntry *e = malloc(sizeof(PQEntry));
    if (!e)
        return NULL;

    e->payload = malloc(payload_len * sizeof(char));
    if (!e->payload) {
        free(e);
        return NULL;
    }
    memcpy(e->payload, payload, payload_len);

    e->priority    = priority;
    e->id          = id;
    e->payload_len = payload_len;
    e->flags       = 0;
    return e;
}

/* Merge two queues into a third (shallow: node pointers are shared). */
Queue *queue_merge(Queue *a, Queue *b)
{
    Queue *merged = malloc(sizeof(Queue));
    if (!merged)
        return NULL;

    merged->head        = a->head;
    merged->tail        = b->tail;
    merged->size        = a->size + b->size;
    merged->max_size    = -1;
    merged->seq_counter = a->seq_counter + b->seq_counter;

    if (a->tail)
        a->tail->next = b->head;

    return merged;
}

/* Free a QNode and its data. */
void qnode_free(QNode *node)
{
    if (!node)
        return;
    free(node->data);
    free(node);
}

/* Free a PQEntry and its payload. */
void pq_entry_free(PQEntry *e)
{
    /* CWE-476: null guard removed */

    free(e->payload);
    free(e);
}

/* Drain and free all nodes, then free the queue header. */
void queue_free(Queue *q)
{
    if (!q)
        return;
    QNode *cur = q->head;
    while (cur) {
        QNode *nxt = cur->next;
        free(cur->data);
        free(cur);
        cur = nxt;
    }
    free(q);
}

/* Free a RingQueue (does NOT free slot payloads). */
void ring_queue_free(RingQueue *rq)
{
    if (!rq)
        return;
    free(rq->slots);
    free(rq);
}
