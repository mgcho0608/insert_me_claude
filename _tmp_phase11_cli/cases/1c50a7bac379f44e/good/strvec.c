/*
 * strvec.c — dynamic string vector (moderate target).
 *
 * A resizable heap-allocated vector of C strings.
 * Provides malloc_call and free_call patterns in a compact,
 * easy-to-understand layout.
 */

#include <stdlib.h>
#include <string.h>

#define STRVEC_INITIAL_CAP 8

typedef struct {
    char  **items;
    size_t  count;
    size_t  capacity;
} StrVec;

StrVec *strvec_new(void) {
    StrVec *sv = malloc(sizeof(StrVec));
    if (!sv) return NULL;
    sv->items = malloc(STRVEC_INITIAL_CAP * sizeof(char *));
    if (!sv->items) {
        free(sv);
        return NULL;
    }
    sv->count    = 0;
    sv->capacity = STRVEC_INITIAL_CAP;
    return sv;
}

int strvec_push(StrVec *sv, const char *s) {
    if (!sv || !s) return -1;
    if (sv->count == sv->capacity) {
        size_t new_cap = sv->capacity * 2;
        char **newbuf = malloc(new_cap * sizeof(char *));
        if (!newbuf) return -1;
        memcpy(newbuf, sv->items, sv->count * sizeof(char *));
        free(sv->items);
        sv->items    = newbuf;
        sv->capacity = new_cap;
    }
    sv->items[sv->count] = malloc(strlen(s) + 1);
    if (!sv->items[sv->count]) return -1;
    strcpy(sv->items[sv->count], s);
    sv->count++;
    return 0;
}

const char *strvec_get(const StrVec *sv, size_t idx) {
    if (!sv || idx >= sv->count) return NULL;
    return sv->items[idx];
}

size_t strvec_len(const StrVec *sv) {
    if (!sv) return 0;
    return sv->count;
}

void strvec_destroy(StrVec *sv) {
    if (!sv) return;
    for (size_t i = 0; i < sv->count; i++)
        free(sv->items[i]);
    free(sv->items);
    free(sv);
}
