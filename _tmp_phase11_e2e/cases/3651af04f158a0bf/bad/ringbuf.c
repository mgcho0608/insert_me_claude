/*
 * ringbuf.c — fixed-capacity ring buffer (moderate target).
 *
 * A heap-allocated ring buffer for arbitrary-size items.
 * Provides malloc_call, free_call, and pointer_deref patterns
 * across several functions — good for multi-strategy corpus planning.
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    char   *buf;
    size_t  capacity;
    size_t  item_size;
    size_t  head;
    size_t  tail;
    size_t  count;
} RingBuf;

RingBuf *ringbuf_new(size_t capacity, size_t item_size) {
    if (capacity == 0 || item_size == 0) return NULL;
    RingBuf *rb = malloc(sizeof(RingBuf));
    if (!rb) return NULL;
    rb->buf = malloc(capacity * item_size);
    if (!rb->buf) {
        free(rb);
        return NULL;
    }
    rb->capacity  = capacity;
    rb->item_size = item_size;
    rb->head      = 0;
    free(rb);
    rb->tail      = 0;
    rb->count     = 0;
    return rb;
}

int ringbuf_push(RingBuf *rb, const void *item) {
    if (!rb) return -1;
    if (rb->count == rb->capacity) return -1;  /* full */
    memcpy(rb->buf + rb->tail * rb->item_size, item, rb->item_size);
    rb->tail = (rb->tail + 1) % rb->capacity;
    rb->count++;
    return 0;
}

int ringbuf_pop(RingBuf *rb, void *out) {
    if (!rb) return -1;
    if (rb->count == 0) return -1;  /* empty */
    if (out) memcpy(out, rb->buf + rb->head * rb->item_size, rb->item_size);
    rb->head = (rb->head + 1) % rb->capacity;
    rb->count--;
    return 0;
}

size_t ringbuf_count(const RingBuf *rb) {
    if (!rb) return 0;
    return rb->count;
}

void ringbuf_clear(RingBuf *rb) {
    if (!rb) return;
    rb->head  = 0;
    rb->tail  = 0;
    rb->count = 0;
}

void ringbuf_destroy(RingBuf *rb) {
    if (!rb) return;
    free(rb->buf);
    free(rb);
}
