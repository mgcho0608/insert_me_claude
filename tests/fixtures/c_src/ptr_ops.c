/*
 * ptr_ops.c — fixture file for insert_me seeder tests.
 * Contains pointer dereference, array access, and loop patterns.
 * Intentionally realistic; not a security reference.
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct Node {
    int       value;
    struct Node *next;
} Node;

/* Sum all values in a linked list via arrow dereference */
int sum_list(Node *head)
{
    int total = 0;
    Node *cur = head;
    while (cur != NULL) {
        total += cur->value;        /* pointer_deref candidate */
        cur = cur->next;            /* pointer_deref candidate */
    }
    return total;
}

/* Array traversal — off-by-one via <= bound */
int sum_array(int *arr, int n)
{
    int total = 0;
    for (int i = 0; i <= n; i++) { /* loop_bound candidate: should be < n */
        total += arr[i];            /* array_index candidate */
    }
    return total;
}

/* Matrix allocation with potential integer overflow in size calculation */
void *alloc_matrix(int rows, int cols)
{
    size_t sz = rows * cols * sizeof(double);   /* integer_arithmetic candidate */
    return malloc(sz);
}

/* Pointer arithmetic — skip whitespace */
char *skip_spaces(char *p)
{
    while (*p == ' ')               /* pointer_deref candidate */
        p++;
    return p;
}

/* Array copy with explicit index */
void copy_array(int *dst, const int *src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];            /* array_index candidates */
    }
}

/* Dereference of a computed offset */
int read_field(Node **table, int idx, int field)
{
    Node *entry = table[idx];       /* array_index candidate */
    if (entry == NULL)
        return -1;
    return entry->value;            /* pointer_deref candidate */
}
