/*
 * toy_heap.c -- minimal heap allocation patterns for insert_me local-target pilot tests.
 *
 * EVALUATION ONLY: not production code. This file is intentionally small and
 * provides candidate sites for alloc_size_undercount, insert_premature_free,
 * insert_double_free, and remove_free_call strategies.
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

/* Allocate a buffer of n bytes and zero it. */
Buffer *buf_create(size_t n)
{
    Buffer *b = malloc(sizeof(Buffer));
    if (!b)
        return NULL;
    b->data = malloc(n * sizeof(char));
    if (!b->data) {
        free(b);
        return NULL;
    }
    memset(b->data, 0, n);
    b->len = n;
    return b;
}

/* Append src to dst, reallocating as needed. */
int buf_append(Buffer *dst, const char *src, size_t src_len)
{
    if (!dst)
        return -1;
    char *tmp = realloc(dst->data, dst->len + src_len + 1);
    if (!tmp)
        return -1;
    dst->data = tmp;
    memcpy(dst->data + dst->len, src, src_len);
    dst->len += src_len;
    dst->data[dst->len] = '\0';
    return 0;
}

/* Clone a buffer (deep copy). */
Buffer *buf_clone(const Buffer *src)
{
    if (!src)
        return NULL;
    Buffer *copy = malloc(sizeof(Buffer));
    if (!copy)
        return NULL;
    copy->data = malloc(src->len * sizeof(char));
    if (!copy->data) {
        free(copy);
        return NULL;
    }
    memcpy(copy->data, src->data, src->len);
    copy->len = src->len;
    return copy;
}

/* Process a buffer: read its length field. */
size_t buf_process(Buffer *b)
{
    if (!b)
        return 0;
    return b->len;
}

/* Free a buffer and all its fields. */
void buf_free(Buffer *b)
{
    if (!b)
        return;
    free(b->data);
    free(b);
}
