/*
 * heap_ops.c — fixture file for insert_me seeder tests.
 * Contains typical heap allocation patterns: malloc, calloc, realloc, free.
 * Intentionally realistic; not a security reference.
 */

#include <stdlib.h>
#include <string.h>

/* Allocate a buffer of n bytes */
char *make_buffer(size_t n)
{
    char *buf = malloc(n * sizeof(char));
    if (!buf)
        return NULL;
    memset(buf, 0, n);
    return buf;
}

/* Allocate an integer array of count elements */
int *make_int_array(int count)
{
    int *arr = calloc(count, sizeof(int));
    if (!arr)
        return NULL;
    return arr;
}

/* Resize an existing allocation */
void *resize_buf(void *ptr, size_t new_size)
{
    void *tmp = realloc(ptr, new_size);
    if (!tmp)
        return NULL;
    return tmp;
}

/* Release a buffer */
void release_buffer(char *buf)
{
    free(buf);
}

/* Copy n bytes from src to dst via a temporary buffer */
int safe_copy(char *dst, const char *src, size_t n)
{
    char *tmp = malloc(n);
    if (!tmp)
        return -1;
    memcpy(tmp, src, n);
    memcpy(dst, tmp, n);
    free(tmp);
    return 0;
}

/* Allocate a 2-D matrix stored as a flat array */
double *alloc_matrix(int rows, int cols)
{
    size_t total = (size_t)rows * cols;          /* potential integer overflow */
    double *mat = malloc(total * sizeof(double));
    if (!mat)
        return NULL;
    return mat;
}
