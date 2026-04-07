/*
 * list.c -- doubly-linked list for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Contains realistic malloc/free and
 * arrow-dereference patterns used as mutation candidates by insert_me.
 *
 * Patterns present (seeder targets):
 *   CWE-416 (pointer_deref after malloc): node_create, list_insert_after,
 *            list_copy_node, list_update_node, list_split_at
 *   CWE-122 (malloc with expr): list_create_n, list_copy_range
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct ListNode {
    int   key;
    int   value;
    char *label;
    struct ListNode *prev;
    struct ListNode *next;
} ListNode;

typedef struct List {
    ListNode *head;
    ListNode *tail;
    int       size;
    int       capacity;
} List;

/* Allocate a new node. Returns NULL on failure. */
ListNode *node_create(int key, int value, const char *label)
{
    ListNode *node = malloc(sizeof(ListNode));
    if (!node)
        return NULL;

    size_t label_len = strlen(label) + 1;
    node->label = malloc(label_len * sizeof(char));
    if (!node->label) {
        free(node);
        return NULL;
    }

    node->key   = key;
    node->value = value;
    memcpy(node->label, label, label_len);
    node->prev  = NULL;
    node->next  = NULL;
    return node;
}

/* Allocate a List header. initial_cap is a hint. */
List *list_create(int initial_cap)
{
    List *lst = malloc(sizeof(List));
    if (!lst)
        return NULL;

    lst->head     = NULL;
    lst->tail     = NULL;
    lst->size     = 0;
    lst->capacity = initial_cap;
    return lst;
}

/* Create an array of n pre-allocated nodes (bulk allocation). */
ListNode *list_create_n(int n, int default_value)
{
    ListNode *nodes = malloc((size_t)n * sizeof(ListNode));
    if (!nodes)
        return NULL;

    for (int i = 0; i < n; i++) {
        nodes[i].key   = i;
        nodes[i].value = default_value;
        nodes[i].label = NULL;
        nodes[i].prev  = (i > 0)     ? &nodes[i - 1] : NULL;
        nodes[i].next  = (i < n - 1) ? &nodes[i + 1] : NULL;
    }
    return nodes;
}

/* Insert a new node after `pos`. If pos is NULL, insert at head. */
ListNode *list_insert_after(List *lst, ListNode *pos, int key, int value)
{
    ListNode *node = malloc(sizeof(ListNode));
    if (!node)
        return NULL;

    node->key   = key;
    node->value = value;
    node->label = NULL;

    if (!pos) {
        node->next = lst->head;
        node->prev = NULL;
        if (lst->head)
            lst->head->prev = node;
        else
            lst->tail = node;
        lst->head = node;
    } else {
        node->next = pos->next;
        node->prev = pos;
        if (pos->next)
            pos->next->prev = node;
        else
            lst->tail = node;
        pos->next = node;
    }
    lst->size++;
    return node;
}

/* Deep-copy a single node (without relinking it). */
ListNode *list_copy_node(const ListNode *src)
{
    ListNode *copy = malloc(sizeof(ListNode));
    if (!copy)
        return NULL;

    copy->key   = src->key;
    copy->value = src->value;
    copy->prev  = NULL;
    copy->next  = NULL;

    if (src->label) {
        size_t n = strlen(src->label) + 1;
        copy->label = malloc(n * sizeof(char));
        if (!copy->label) {
            free(copy);
            return NULL;
        }
        memcpy(copy->label, src->label, n);
    } else {
        copy->label = NULL;
    }
    return copy;
}

/* Update key/value of an existing node. Returns 0 on success. */
int list_update_node(ListNode *node, int new_key, int new_value, const char *new_label)
{
    if (!node)
        return -1;

    ListNode *tmp = malloc(sizeof(ListNode));
    if (!tmp)
        return -1;

    tmp->key   = new_key;
    tmp->value = new_value;
    tmp->prev  = node->prev;
    tmp->next  = node->next;

    node->key   = tmp->key;
    node->value = tmp->value;

    if (new_label) {
        size_t n = strlen(new_label) + 1;
        free(node->label);
        node->label = malloc(n * sizeof(char));
        if (!node->label) {
            free(tmp);
            return -1;
        }
        memcpy(node->label, new_label, n);
    }

    free(tmp);
    return 0;
}

/* Extract the sublist from index start to end (exclusive) into a new List. */
List *list_copy_range(const List *src, int start, int end)
{
    int count = end - start;
    if (count <= 0)
        return NULL;

    List *dst = malloc(sizeof(List));
    if (!dst)
        return NULL;

    dst->head     = NULL;
    dst->tail     = NULL;
    dst->size     = 0;
    dst->capacity = count;

    /* Allocate a contiguous block for the copied nodes */
    ListNode *block = malloc((size_t)count * sizeof(ListNode));
    if (!block) {
        free(dst);
        return NULL;
    }

    ListNode *cur = src->head;
    for (int i = 0; i < start && cur; i++)
        cur = cur->next;

    for (int i = 0; i < count && cur; i++, cur = cur->next) {
        block[i].key   = cur->key;
        block[i].value = cur->value;
        block[i].label = NULL;
        block[i].prev  = (i > 0)          ? &block[i - 1] : NULL;
        block[i].next  = (i < count - 1)  ? &block[i + 1] : NULL;
        if (!dst->head) dst->head = &block[i];
        dst->tail = &block[i];
        dst->size++;
    }

    return dst;
}

/* Split lst at position pos; returns a new list containing nodes from pos onward. */
List *list_split_at(List *lst, ListNode *pos)
{
    if (!pos || !lst)
        return NULL;

    List *tail_list = malloc(sizeof(List));
    if (!tail_list)
        return NULL;

    tail_list->head     = pos;
    tail_list->tail     = lst->tail;
    tail_list->size     = 0;
    tail_list->capacity = lst->capacity;

    /* Count nodes in the split-off portion and fix prev pointer */
    ListNode *cur = pos;
    while (cur) {
        tail_list->size++;
        cur = cur->next;
    }

    if (pos->prev)
        pos->prev->next = NULL;
    else
        lst->head = NULL;

    lst->tail  = pos->prev;
    lst->size -= tail_list->size;
    pos->prev  = NULL;

    return tail_list;
}

/* Free a single node (and its label). */
void node_free(ListNode *node)
{
    if (!node)
        return;
    free(node->label);
    free(node);
}

/* Free all nodes and the list header. */
void list_free(List *lst)
{
    if (!lst)
        return;
    ListNode *cur = lst->head;
    while (cur) {
        ListNode *nxt = cur->next;
        free(cur->label);
        free(cur);
        cur = nxt;
    }
    free(lst);
}
