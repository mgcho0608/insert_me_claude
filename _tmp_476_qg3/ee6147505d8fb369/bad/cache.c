/*
 * cache.c -- LRU entry cache for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Demonstrates struct allocation
 * patterns with multiple field writes after malloc — good CWE-416 targets.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): entry_create, cache_create,
 *            cache_evict_entry, cache_clone_entry
 *   CWE-122 (malloc with expr): cache_create (bucket array), entry_create (key copy)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CACHE_DEFAULT_BUCKETS 16

typedef struct CacheEntry {
    char            *key;
    void            *value;
    size_t           value_size;
    unsigned int     access_count;
    int              priority;
    struct CacheEntry *lru_prev;
    struct CacheEntry *lru_next;
    struct CacheEntry *bucket_next;
} CacheEntry;

typedef struct Cache {
    CacheEntry **buckets;
    CacheEntry  *lru_head;   /* most recently used */
    CacheEntry  *lru_tail;   /* least recently used */
    int          n_buckets;
    int          n_entries;
    int          max_entries;
} Cache;

static unsigned int _hash(const char *key, int n_buckets)
{
    unsigned int h = 5381;
    while (*key)
        h = ((h << 5) + h) ^ (unsigned char)*key++;
    return h % (unsigned int)n_buckets;
}

/* Allocate a new CacheEntry (deep-copies key; takes ownership of value). */
CacheEntry *entry_create(const char *key, void *value, size_t value_size, int priority)
{
    CacheEntry *e = malloc(sizeof(CacheEntry));
    if (!e)
        return NULL;

    size_t key_len = strlen(key) + 1;
    e->key = malloc(key_len * sizeof(char));
    if (!e->key) {
        free(e);
        return NULL;
    }
    memcpy(e->key, key, key_len);

    e->value        = value;
    e->value_size   = value_size;
    e->access_count = 0;
    e->priority     = priority;
    e->lru_prev     = NULL;
    e->lru_next     = NULL;
    e->bucket_next  = NULL;
    return e;
}

/* Allocate and initialise a Cache. */
Cache *cache_create(int max_entries, int n_buckets)
{
    Cache *c = malloc(sizeof(Cache));
    if (!c)
        return NULL;

    c->buckets = malloc((size_t)n_buckets * sizeof(CacheEntry *));
    if (!c->buckets) {
        free(c);
        return NULL;
    }
    memset(c->buckets, 0, (size_t)n_buckets * sizeof(CacheEntry *));

    c->lru_head   = NULL;
    c->lru_tail   = NULL;
    c->n_buckets  = n_buckets;
    c->n_entries  = 0;
    c->max_entries = max_entries;
    return c;
}

/* Promote entry to front of the LRU list (most recently used). */
static void _lru_promote(Cache *c, CacheEntry *e)
{
    if (e == c->lru_head)
        return;
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    if (c->lru_tail == e) c->lru_tail = e->lru_prev;
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

/* Look up a key; returns the entry or NULL. Updates access_count. */
CacheEntry *cache_lookup(Cache *c, const char *key)
{
    unsigned int h = _hash(key, c->n_buckets);
    CacheEntry *e = c->buckets[h];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            e->access_count++;
            _lru_promote(c, e);
            return e;
        }
        e = e->bucket_next;
    }
    return NULL;
}

/* Insert entry into cache. Evicts LRU entry if at capacity. */
int cache_insert(Cache *c, const char *key, void *value, size_t value_size, int priority)
{
    if (c->n_entries >= c->max_entries && c->lru_tail) {
        CacheEntry *victim = c->lru_tail;
        /* Unlink from bucket chain */
        unsigned int vh = _hash(victim->key, c->n_buckets);
        CacheEntry **slot = &c->buckets[vh];
        while (*slot && *slot != victim) slot = &(*slot)->bucket_next;
        if (*slot) *slot = victim->bucket_next;
        /* Unlink from LRU */
        if (victim->lru_prev) victim->lru_prev->lru_next = NULL;
        c->lru_tail = victim->lru_prev;
        if (c->lru_head == victim) c->lru_head = NULL;
        free(victim->key);
        free(victim);
        c->n_entries--;
    }

    CacheEntry *e = entry_create(key, value, value_size, priority);
    if (!e)
        return -1;

    unsigned int h = _hash(key, c->n_buckets);
    e->bucket_next = c->buckets[h];
    c->buckets[h] = e;
    _lru_promote(c, e);
    c->n_entries++;
    return 0;
}

/* Create a shallow copy of an entry (clones key; shares value pointer). */
CacheEntry *cache_clone_entry(const CacheEntry *src)
{
    CacheEntry *dst = malloc(sizeof(CacheEntry));
    if (!dst)
        return NULL;

    size_t key_len = strlen(src->key) + 1;
    dst->key = malloc(key_len * sizeof(char));
    if (!dst->key) {
        free(dst);
        return NULL;
    }
    memcpy(dst->key, src->key, key_len);

    dst->value        = src->value;
    dst->value_size   = src->value_size;
    dst->access_count = 0;
    dst->priority     = src->priority;
    dst->lru_prev     = NULL;
    dst->lru_next     = NULL;
    dst->bucket_next  = NULL;
    return dst;
}

/* Evict the entry with the given key. Returns 0 if found and removed. */
int cache_evict(Cache *c, const char *key)
{
    unsigned int h = _hash(key, c->n_buckets);
    CacheEntry **slot = &c->buckets[h];
    while (*slot) {
        if (strcmp((*slot)->key, key) == 0) {
            CacheEntry *e = *slot;
            *slot = e->bucket_next;
            if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
            if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
            if (c->lru_head == e) c->lru_head = e->lru_next;
            if (c->lru_tail == e) c->lru_tail = e->lru_prev;
            free(e->key);
            free(e);
            c->n_entries--;
            return 0;
        }
        slot = &(*slot)->bucket_next;
    }
    return -1;
}

/* Free all entries and the cache header. */
void cache_free(Cache *c)
{
    if (!c)
        return;
    CacheEntry *cur = c->lru_head;
    while (cur) {
        CacheEntry *nxt = cur->lru_next;
        free(cur->key);
        free(cur);
        cur = nxt;
    }
    free(c->buckets);
    free(c);
}
