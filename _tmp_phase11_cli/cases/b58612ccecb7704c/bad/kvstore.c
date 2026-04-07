/*
 * kvstore.c — simple open-addressing hash map (moderate target).
 *
 * A string-key → string-value hash map with heap-allocated entries.
 * Provides rich malloc_call, free_call, and pointer_deref patterns
 * across multiple functions with different scopes.
 */

#include <stdlib.h>
#include <string.h>

#define KV_INITIAL_BUCKETS 16
#define KV_LOAD_NUMERATOR  3
#define KV_LOAD_DENOMINATOR 4

typedef struct KVEntry {
    char *key;
    char *value;
    struct KVEntry *next;
} KVEntry;

typedef struct {
    KVEntry **buckets;
    size_t    num_buckets;
    size_t    count;
} KVStore;

static size_t _hash(const char *key, size_t num_buckets) {
    size_t h = 5381;
    for (const char *p = key; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;
    return h % num_buckets;
}

KVStore *kvstore_new(void) {
    KVStore *kv = malloc(sizeof(KVStore));
    if (!kv) return NULL;
    kv->buckets = malloc(KV_INITIAL_BUCKETS * sizeof(KVEntry *));
    if (!kv->buckets) {
        free(kv);
        return NULL;
    }
    memset(kv->buckets, 0, KV_INITIAL_BUCKETS * sizeof(KVEntry *));
    kv->num_buckets = KV_INITIAL_BUCKETS;
    kv->count = 0;
    return kv;
}

int kvstore_put(KVStore *kv, const char *key, const char *value) {
    if (!kv || !key || !value) return -1;
    size_t idx = _hash(key, kv->num_buckets);
    KVEntry *e = kv->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            char *newval = malloc(strlen(value) + 1);
            if (!newval) return -1;
            free(e->value);
            e->value = newval;
            strcpy(e->value, value);
            return 0;
        }
        e = e->next;
    }
    KVEntry *entry = malloc(sizeof(KVEntry));
    if (!entry) return -1;
    entry->key = malloc(strlen(key) + 1);
    if (!entry->key) { free(entry); return -1; }
    entry->value = malloc(strlen(value) + 1);
    if (!entry->value) { free(entry->key); free(entry); return -1; }
    strcpy(entry->key, key);
    strcpy(entry->value, value);
    entry->next = kv->buckets[idx];
    kv->buckets[idx] = entry;
    kv->count++;
    return 0;
}

const char *kvstore_get(KVStore *kv, const char *key) {
    if (!kv || !key) return NULL;
    size_t idx = _hash(key, kv->num_buckets);
    KVEntry *e = kv->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0)
            return e->value;
        e = e->next;
    }
    return NULL;
}

int kvstore_delete(KVStore *kv, const char *key) {
    if (!kv || !key) return -1;
    size_t idx = _hash(key, kv->num_buckets);
    KVEntry *prev = NULL;
    KVEntry *e = kv->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            if (prev) prev->next = e->next;
            else kv->buckets[idx] = e->next;
            free(e->key);
            free(e->value);
            free(e);
            kv->count--;
            return 0;
        }
        prev = e;
        e = e->next;
    }
    return -1;
}

void kvstore_destroy(KVStore *kv) {
    if (!kv) return;
    for (size_t i = 0; i < kv->num_buckets; i++) {
        KVEntry *e = kv->buckets[i];
        while (e) {
            KVEntry *next = e->next;
            free(e->key);
            free(e->value);
            free(e);
            e = next;
        }
    }
    free(kv->buckets);
    free(kv);
}
