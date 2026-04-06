/*
 * dynarray.c -- resizable dynamic array for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Pointer-to-pointer indirection
 * and element-size arithmetic provide rich CWE-122/CWE-416/CWE-415/CWE-401
 * mutation sites distinct from the list/graph patterns in sandbox_eval.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): da_new, da_push, da_copy, da_slice
 *   CWE-122 (malloc with expr): da_new (items array), da_reserve (realloc),
 *            da_copy (n * elem_size), da_slice (slice len)
 *   CWE-415 (free_call): da_pop, da_clear, da_free
 *   CWE-401 (free_call — remove): da_remove, da_clear, da_free
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct DynArray {
    void   **items;      /* array of opaque item pointers */
    size_t   size;       /* number of live items */
    size_t   cap;        /* allocated slot count */
    size_t   elem_size;  /* byte size of one element (informational) */
    int      flags;      /* reserved */
} DynArray;

/* Allocate a new DynArray with initial capacity. */
DynArray *da_new(size_t initial_cap, size_t elem_size)
{
    DynArray *da = malloc(sizeof(DynArray));
    if (!da)
        return NULL;

    da->items = malloc(initial_cap * sizeof(void *));
    if (!da->items) {
        free(da);
        return NULL;
    }
    memset(da->items, 0, initial_cap * sizeof(void *));

    da->size      = 0;
    da->cap       = initial_cap;
    da->elem_size = elem_size;
    da->flags     = 0;
    return da;
}

/* Ensure capacity for at least min_cap items; returns 0 on success. */
int da_reserve(DynArray *da, size_t min_cap)
{
    if (da->cap >= min_cap)
        return 0;

    size_t new_cap = da->cap * 2;
    if (new_cap < min_cap)
        new_cap = min_cap;

    void **new_items = realloc(da->items, new_cap * sizeof(void *));
    if (!new_items)
        return -1;

    /* Zero-initialise the newly allocated slots. */
    memset(new_items + da->cap, 0, (new_cap - da->cap) * sizeof(void *));
    da->items = new_items;
    da->cap   = new_cap;
    return 0;
}

/* Append item to the end. item pointer is stored as-is (no copy). */
int da_push(DynArray *da, void *item)
{
    if (da->size >= da->cap) {
        if (da_reserve(da, da->cap + 1) != 0)
            return -1;
    }
    da->items[da->size] = item;
    da->size++;
    return 0;
}

/* Remove and return the last item, or NULL if empty. */
void *da_pop(DynArray *da)
{
    if (da->size == 0)
        return NULL;
    void *item = da->items[da->size - 1];
    da->items[da->size - 1] = NULL;
    da->size--;
    return item;
}

/* Return item at index, or NULL if out of range. */
void *da_get(const DynArray *da, size_t idx)
{
    if (idx >= da->size)
        return NULL;
    return da->items[idx];
}

/* Replace item at index; returns old pointer or NULL on error. */
void *da_set(DynArray *da, size_t idx, void *item)
{
    if (idx >= da->size)
        return NULL;
    void *old = da->items[idx];
    da->items[idx] = item;
    return old;
}

/* Remove item at index; shifts remaining items down. Returns old pointer. */
void *da_remove(DynArray *da, size_t idx)
{
    if (idx >= da->size)
        return NULL;
    void *old = da->items[idx];
    memmove(da->items + idx, da->items + idx + 1,
            (da->size - idx - 1) * sizeof(void *));
    da->size--;
    da->items[da->size] = NULL;
    return old;
}

/* Deep-copy a DynArray (shallow copy of item pointers; separate items[] array). */
DynArray *da_copy(const DynArray *src)
{
    DynArray *dst = malloc(sizeof(DynArray));
    if (!dst)
        return NULL;

    size_t n = src->size;
    dst->items = malloc(n * sizeof(void *));
    if (!dst->items) {
        free(dst);
        return NULL;
    }
    memcpy(dst->items, src->items, n * sizeof(void *));

    dst->size      = src->size;
    dst->cap       = n;
    dst->elem_size = src->elem_size;
    dst->flags     = src->flags;
    return dst;
}

/* Return a new DynArray containing items [from, to). Caller owns result. */
DynArray *da_slice(const DynArray *da, size_t from, size_t to)
{
    if (from > to || to > da->size)
        return NULL;

    size_t slice_len = to - from;
    DynArray *sl = malloc(sizeof(DynArray));
    if (!sl)
        return NULL;

    sl->items = malloc(slice_len * sizeof(void *));
    if (!sl->items) {
        free(sl);
        return NULL;
    }
    memcpy(sl->items, da->items + from, slice_len * sizeof(void *));

    sl->size      = slice_len;
    sl->cap       = slice_len;
    sl->elem_size = da->elem_size;
    sl->flags     = da->flags;
    return sl;
}

/* Null all item slots without freeing da or its items[] array. */
void da_clear(DynArray *da)
{
    memset(da->items, 0, da->size * sizeof(void *));
    da->size = 0;
}

/* Free the items[] array and the DynArray header. Does NOT free item pointees. */
void da_free(DynArray *da)
{
    if (!da)
        return;
    free(da->items);
    free(da);
}
