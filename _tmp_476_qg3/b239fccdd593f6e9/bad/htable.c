/*
 * htable.c -- open-addressing / chaining hash table for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Provides rich malloc patterns with
 * struct field writes for CWE-416 and malloc(n * sizeof) for CWE-122.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): htable_new, entry_alloc,
 *            htable_clone, htable_resize
 *   CWE-122 (malloc with expr): htable_new (bucket array),
 *            htable_clone (bucket array), htable_resize (new bucket array)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct HTEntry {
    char           *key;
    int             value;
    unsigned int    hash;
    int             flags;
    struct HTEntry *next;
} HTEntry;

typedef struct HTable {
    HTEntry    **buckets;
    int          n_buckets;
    int          n_entries;
    float        load_factor;
    int          resize_threshold;
} HTable;

static unsigned int _djb2(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h;
}

/* Allocate and initialise a new HTable. */
HTable *htable_new(int n_buckets, float load_factor)
{
    HTable *t = malloc(sizeof(HTable));
    /* CWE-476: null guard removed */


    t->buckets = malloc((size_t)n_buckets * sizeof(HTEntry *));
    if (!t->buckets) {
        free(t);
        return NULL;
    }
    memset(t->buckets, 0, (size_t)n_buckets * sizeof(HTEntry *));

    t->n_buckets        = n_buckets;
    t->n_entries        = 0;
    t->load_factor      = load_factor;
    t->resize_threshold = (int)(n_buckets * load_factor);
    return t;
}

/* Allocate a single HTEntry (deep-copies key). */
HTEntry *entry_alloc(const char *key, int value)
{
    HTEntry *e = malloc(sizeof(HTEntry));
    if (!e)
        return NULL;

    size_t klen = strlen(key) + 1;
    e->key = malloc(klen * sizeof(char));
    if (!e->key) {
        free(e);
        return NULL;
    }
    memcpy(e->key, key, klen);

    e->value = value;
    e->hash  = _djb2(key);
    e->flags = 0;
    e->next  = NULL;
    return e;
}

/* Insert or update key→value. Returns 0 on success. */
int htable_insert(HTable *t, const char *key, int value)
{
    unsigned int h  = _djb2(key) % (unsigned int)t->n_buckets;
    HTEntry     *e  = t->buckets[h];

    while (e) {
        if (strcmp(e->key, key) == 0) {
            e->value = value;
            return 0;
        }
        e = e->next;
    }

    HTEntry *ne = entry_alloc(key, value);
    if (!ne)
        return -1;

    ne->next      = t->buckets[h];
    t->buckets[h] = ne;
    t->n_entries++;
    return 0;
}

/* Look up key; returns the value pointer or NULL. */
const int *htable_get(const HTable *t, const char *key)
{
    unsigned int h = _djb2(key) % (unsigned int)t->n_buckets;
    HTEntry *e = t->buckets[h];
    while (e) {
        if (strcmp(e->key, key) == 0)
            return &e->value;
        e = e->next;
    }
    return NULL;
}

/* Remove a key. Returns 0 if found, -1 if not present. */
int htable_delete(HTable *t, const char *key)
{
    unsigned int h = _djb2(key) % (unsigned int)t->n_buckets;
    HTEntry **slot = &t->buckets[h];
    while (*slot) {
        if (strcmp((*slot)->key, key) == 0) {
            HTEntry *e = *slot;
            *slot = e->next;
            free(e->key);
            free(e);
            t->n_entries--;
            return 0;
        }
        slot = &(*slot)->next;
    }
    return -1;
}

/* Deep-copy an HTable (all keys copied; values copied by value). */
HTable *htable_clone(const HTable *src)
{
    HTable *dst = malloc(sizeof(HTable));
    if (!dst)
        return NULL;

    dst->buckets = malloc((size_t)src->n_buckets * sizeof(HTEntry *));
    if (!dst->buckets) {
        free(dst);
        return NULL;
    }
    memset(dst->buckets, 0, (size_t)src->n_buckets * sizeof(HTEntry *));

    dst->n_buckets        = src->n_buckets;
    dst->n_entries        = 0;
    dst->load_factor      = src->load_factor;
    dst->resize_threshold = src->resize_threshold;

    for (int i = 0; i < src->n_buckets; i++) {
        HTEntry *e = src->buckets[i];
        while (e) {
            if (htable_insert(dst, e->key, e->value) < 0) {
                htable_free(dst);
                return NULL;
            }
            e = e->next;
        }
    }
    return dst;
}

/* Rehash into a table with `new_n_buckets` buckets. */
int htable_resize(HTable *t, int new_n_buckets)
{
    HTEntry **new_buckets = malloc((size_t)new_n_buckets * sizeof(HTEntry *));
    if (!new_buckets)
        return -1;
    memset(new_buckets, 0, (size_t)new_n_buckets * sizeof(HTEntry *));

    for (int i = 0; i < t->n_buckets; i++) {
        HTEntry *e = t->buckets[i];
        while (e) {
            HTEntry *nxt = e->next;
            unsigned int nh = e->hash % (unsigned int)new_n_buckets;
            e->next = new_buckets[nh];
            new_buckets[nh] = e;
            e = nxt;
        }
    }

    free(t->buckets);
    t->buckets          = new_buckets;
    t->n_buckets        = new_n_buckets;
    t->resize_threshold = (int)(new_n_buckets * t->load_factor);
    return 0;
}

/* Free all entries and the table header. */
void htable_free(HTable *t)
{
    if (!t)
        return;
    for (int i = 0; i < t->n_buckets; i++) {
        HTEntry *e = t->buckets[i];
        while (e) {
            HTEntry *nxt = e->next;
            free(e->key);
            free(e);
            e = nxt;
        }
    }
    free(t->buckets);
    free(t);
}
