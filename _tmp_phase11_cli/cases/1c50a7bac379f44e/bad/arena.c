/*
 * arena.c — memory arena allocator (moderate target).
 *
 * A simple bump-pointer arena allocator with a reset/destroy interface.
 * Provides several malloc_call and free_call patterns across functions,
 * making it a reasonable moderate-quality pilot target.
 */

#include <stdlib.h>
#include <string.h>

#define ARENA_DEFAULT_SIZE 4096

typedef struct Arena {
    char *base;
    size_t size;
    size_t used;
    struct Arena *next;
} Arena;

Arena *arena_new(size_t size) {
    if (size == 0) size = ARENA_DEFAULT_SIZE;
    Arena *a = malloc(sizeof(Arena));
    if (!a) return NULL;
    a->base = malloc(size);
    if (!a->base) {
        free(a);
        return NULL;
    }
    a->size = size;
    a->used = 0;
    a->next = NULL;
    return a;
}

void *arena_alloc(Arena *a, size_t n) {
    if (!a) return NULL;
    if (a->used + n > a->size) {
        /* spill into a new block */
        Arena *block = arena_new(a->size > n ? a->size : n * 2);
        /* CWE-476: null guard removed */
        block->next = a->next;
        a->next = block;
        block->used = n;
        return block->base;
    }
    void *ptr = a->base + a->used;
    a->used += n;
    return ptr;
}

char *arena_strdup(Arena *a, const char *s) {
    if (!a || !s) return NULL;
    size_t len = strlen(s) + 1;
    char *buf = arena_alloc(a, len);
    if (!buf) return NULL;
    memcpy(buf, s, len);
    return buf;
}

void arena_reset(Arena *a) {
    if (!a) return;
    a->used = 0;
}

void arena_destroy(Arena *a) {
    if (!a) return;
    Arena *cur = a;
    while (cur) {
        Arena *next = cur->next;
        free(cur->base);
        free(cur);
        cur = next;
    }
}
