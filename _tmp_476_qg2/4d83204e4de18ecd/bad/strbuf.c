/*
 * strbuf.c -- dynamic string buffer for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Realistic dynamic-string patterns
 * with malloc(n * sizeof), realloc, and struct field writes.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): strbuf_new, strbuf_clone,
 *            strbuf_wrap, strbuf_concat_new
 *   CWE-122 (malloc with expr): strbuf_new, strbuf_clone, strbuf_from_parts,
 *            strbuf_concat_new
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STRBUF_MIN_CAP 16

typedef struct StrBuf {
    char  *data;
    size_t len;
    size_t cap;
    int    flags;
    int    ref_count;
} StrBuf;

/* Allocate a new StrBuf with at least `initial_cap` bytes of storage. */
StrBuf *strbuf_new(size_t initial_cap)
{
    if (initial_cap < STRBUF_MIN_CAP)
        initial_cap = STRBUF_MIN_CAP;

    StrBuf *buf = malloc(sizeof(StrBuf));
    if (!buf)
        return NULL;

    buf->data = malloc(initial_cap * sizeof(char));
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->data[0]   = '\0';
    buf->len       = 0;
    buf->cap       = initial_cap;
    buf->flags     = 0;
    buf->ref_count = 1;
    return buf;
}

/* Create a StrBuf from a C string (copies the content). */
StrBuf *strbuf_from_cstr(const char *s)
{
    size_t slen = strlen(s);
    StrBuf *buf = strbuf_new(slen + 1);
    if (!buf)
        return NULL;

    memcpy(buf->data, s, slen + 1);
    buf->len = slen;
    return buf;
}

/* Clone a StrBuf (deep copy). */
StrBuf *strbuf_clone(const StrBuf *src)
{
    StrBuf *dst = malloc(sizeof(StrBuf));
    if (!dst)
        return NULL;

    size_t new_cap = src->cap;
    dst->data = malloc(new_cap * sizeof(char));
    if (!dst->data) {
        free(dst);
        return NULL;
    }

    memcpy(dst->data, src->data, src->len + 1);
    dst->len       = src->len;
    dst->cap       = new_cap;
    dst->flags     = src->flags;
    dst->ref_count = 1;
    return dst;
}

/* Wrap an existing heap-allocated C string (takes ownership). */
StrBuf *strbuf_wrap(char *s, size_t len, size_t cap)
{
    StrBuf *buf = malloc(sizeof(StrBuf));
    if (!buf)
        return NULL;

    buf->data      = s;
    buf->len       = len;
    buf->cap       = cap;
    buf->flags     = 1;   /* owns the buffer */
    buf->ref_count = 1;
    return buf;
}

/* Concatenate parts into a new StrBuf. part_lens[i] == strlen(parts[i]). */
StrBuf *strbuf_from_parts(const char **parts, const size_t *part_lens, int n_parts)
{
    size_t total = 0;
    for (int i = 0; i < n_parts; i++)
        total += part_lens[i];

    StrBuf *buf = malloc(sizeof(StrBuf));
    if (!buf)
        return NULL;

    buf->data = malloc((total + 1) * sizeof(char));
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    char *p = buf->data;
    for (int i = 0; i < n_parts; i++) {
        memcpy(p, parts[i], part_lens[i]);
        p += part_lens[i];
    }
    *p = '\0';

    buf->len       = total;
    buf->cap       = total + 1;
    buf->flags     = 0;
    buf->ref_count = 1;
    return buf;
}

/* Produce a new StrBuf by concatenating `a` and `b`. */
StrBuf *strbuf_concat_new(const StrBuf *a, const StrBuf *b)
{
    size_t new_len = a->len + b->len;
    StrBuf *result = malloc(sizeof(StrBuf));
    if (!result)
        return NULL;

    result->data = malloc((new_len + 1) * sizeof(char));
    if (!result->data) {
        free(result);
        return NULL;
    }

    memcpy(result->data,          a->data, a->len);
    memcpy(result->data + a->len, b->data, b->len + 1);
    result->len       = new_len;
    result->cap       = new_len + 1;
    result->flags     = 0;
    result->ref_count = 1;
    return result;
}

/* Grow the buffer to hold at least `min_cap` bytes. Returns 0 on success. */
int strbuf_reserve(StrBuf *buf, size_t min_cap)
{
    if (buf->cap >= min_cap)
        return 0;

    size_t new_cap = buf->cap * 2;
    if (new_cap < min_cap)
        new_cap = min_cap;

    char *new_data = realloc(buf->data, new_cap * sizeof(char));
    if (!new_data)
        return -1;

    buf->data = new_data;
    buf->cap  = new_cap;
    return 0;
}

/* Append `n` bytes from `s` to buf. Grows if needed. */
int strbuf_append_n(StrBuf *buf, const char *s, size_t n)
{
    if (strbuf_reserve(buf, buf->len + n + 1) < 0)
        return -1;

    memcpy(buf->data + buf->len, s, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return 0;
}

/* Truncate the buffer to `new_len` bytes. */
void strbuf_truncate(StrBuf *buf, size_t new_len)
{
    if (new_len >= buf->len)
        return;
    buf->len = new_len;
    buf->data[new_len] = '\0';
}

/* Free the StrBuf and its data. */
void strbuf_free(StrBuf *buf)
{
    if (!buf)
        return;
    free(buf->data);
    free(buf);
}
