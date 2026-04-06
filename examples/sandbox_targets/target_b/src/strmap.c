/*
 * strmap.c -- chained hash map (string -> string) for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Open-chain hash table with
 * per-bucket linked lists provides CWE-416/CWE-415/CWE-401/CWE-122
 * patterns distinct from tree and array patterns.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): sm_new, sm_set, sm_resize
 *   CWE-122 (malloc with expr): sm_new (buckets array), sm_resize (new_buckets),
 *            sm_set (key/value copies)
 *   CWE-415 (free_call): sm_delete, sm_clear, sm_free
 *   CWE-401 (free_call — remove): sm_delete, sm_clear, sm_free
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define STRMAP_DEFAULT_BUCKETS 16
#define STRMAP_LOAD_FACTOR     0.75

typedef struct SMEntry {
    char           *key;
    char           *value;
    struct SMEntry *next;
} SMEntry;

typedef struct StrMap {
    SMEntry **buckets;   /* array of bucket list heads */
    size_t    num_buckets;
    size_t    count;
    int       flags;
} StrMap;

/* ---- internal ---- */

static unsigned long sm_hash(const char *s, size_t num_buckets)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*s++))
        h = ((h << 5) + h) ^ (unsigned long)c;
    return h % num_buckets;
}

static SMEntry *sm_entry_new(const char *key, const char *value)
{
    SMEntry *e = malloc(sizeof(SMEntry));
    if (!e)
        return NULL;

    size_t klen = strlen(key) + 1;
    e->key = malloc(klen * sizeof(char));
    if (!e->key) {
        free(e);
        return NULL;
    }
    memcpy(e->key, key, klen);

    size_t vlen = strlen(value) + 1;
    e->value = malloc(vlen * sizeof(char));
    if (!e->value) {
        free(e->key);
        free(e);
        return NULL;
    }
    memcpy(e->value, value, vlen);

    e->next = NULL;
    return e;
}

static void sm_entry_free(SMEntry *e)
{
    if (!e)
        return;
    free(e->key);
    free(e->value);
    free(e);
}

/* ---- public API ---- */

/* Allocate a new StrMap with num_buckets initial buckets. */
StrMap *sm_new(size_t num_buckets)
{
    if (num_buckets == 0)
        num_buckets = STRMAP_DEFAULT_BUCKETS;

    StrMap *sm = malloc(sizeof(StrMap));
    if (!sm)
        return NULL;

    sm->buckets = malloc(num_buckets * sizeof(SMEntry *));
    if (!sm->buckets) {
        free(sm);
        return NULL;
    }
    memset(sm->buckets, 0, num_buckets * sizeof(SMEntry *));

    sm->num_buckets = num_buckets;
    sm->count       = 0;
    sm->flags       = 0;
    return sm;
}

/* Resize the bucket array to new_n_buckets; rehashes all entries. */
static int sm_resize(StrMap *sm, size_t new_n)
{
    SMEntry **new_buckets = malloc(new_n * sizeof(SMEntry *));
    if (!new_buckets)
        return -1;
    memset(new_buckets, 0, new_n * sizeof(SMEntry *));

    for (size_t i = 0; i < sm->num_buckets; i++) {
        SMEntry *e = sm->buckets[i];
        while (e) {
            SMEntry *next = e->next;
            unsigned long idx = sm_hash(e->key, new_n);
            e->next = new_buckets[idx];
            new_buckets[idx] = e;
            e = next;
        }
    }
    free(sm->buckets);
    sm->buckets     = new_buckets;
    sm->num_buckets = new_n;
    return 0;
}

/* Set (insert or update) key -> value. Returns 0 on success. */
int sm_set(StrMap *sm, const char *key, const char *value)
{
    /* Resize if load factor exceeded. */
    if ((double)(sm->count + 1) / (double)sm->num_buckets > STRMAP_LOAD_FACTOR) {
        if (sm_resize(sm, sm->num_buckets * 2) != 0)
            return -1;
    }

    unsigned long idx = sm_hash(key, sm->num_buckets);
    SMEntry *e = sm->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            /* Update existing value in-place. */
            size_t vlen = strlen(value) + 1;
            char *new_val = malloc(vlen * sizeof(char));
            if (!new_val)
                return -1;
            free(e->value);
            memcpy(new_val, value, vlen);
            e->value = new_val;
            return 0;
        }
        e = e->next;
    }

    /* New entry. */
    SMEntry *ne = sm_entry_new(key, value);
    if (!ne)
        return -1;
    ne->next = sm->buckets[idx];
    sm->buckets[idx] = ne;
    sm->count++;
    return 0;
}

/* Retrieve value for key; returns pointer to stored string or NULL. */
const char *sm_get(const StrMap *sm, const char *key)
{
    unsigned long idx = sm_hash(key, sm->num_buckets);
    const SMEntry *e = sm->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0)
            return e->value;
        e = e->next;
    }
    return NULL;
}

/* Delete key from map. Returns 0 if found/deleted, -1 if not found. */
int sm_delete(StrMap *sm, const char *key)
{
    unsigned long idx = sm_hash(key, sm->num_buckets);
    SMEntry **ep = &sm->buckets[idx];
    while (*ep) {
        if (strcmp((*ep)->key, key) == 0) {
            SMEntry *del = *ep;
            *ep = del->next;
            sm_entry_free(del);
            sm->count--;
            return 0;
        }
        ep = &(*ep)->next;
    }
    return -1;
}

/* Check whether key exists. Returns 1 if present, 0 otherwise. */
int sm_contains(const StrMap *sm, const char *key)
{
    return sm_get(sm, key) != NULL;
}

/* Iterate all entries; calls cb(key, value, userdata) for each. */
void sm_foreach(const StrMap *sm,
                void (*cb)(const char *, const char *, void *),
                void *userdata)
{
    for (size_t i = 0; i < sm->num_buckets; i++) {
        const SMEntry *e = sm->buckets[i];
        while (e) {
            cb(e->key, e->value, userdata);
            e = e->next;
        }
    }
}

/* Remove all entries; map remains valid (empty). */
void sm_clear(StrMap *sm)
{
    for (size_t i = 0; i < sm->num_buckets; i++) {
        SMEntry *e = sm->buckets[i];
        while (e) {
            SMEntry *next = e->next;
            sm_entry_free(e);
            e = next;
        }
        sm->buckets[i] = NULL;
    }
    sm->count = 0;
}

/* Free all entries, bucket array, and map header. */
void sm_free(StrMap *sm)
{
    if (!sm)
        return;
    sm_clear(sm);
    free(sm->buckets);
    free(sm);
}
