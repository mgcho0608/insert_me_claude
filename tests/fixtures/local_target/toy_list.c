/*
 * toy_list.c -- minimal singly-linked list for insert_me local-target pilot tests.
 *
 * EVALUATION ONLY: not production code.
 */

#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int value;
    char *label;
    struct Node *next;
} Node;

typedef struct {
    Node *head;
    int size;
} List;

/* Create a new list node with a copy of label. */
Node *node_create(int value, const char *label)
{
    Node *n = malloc(sizeof(Node));
    if (!n)
        return NULL;
    n->label = malloc(strlen(label) + 1);
    if (!n->label) {
        free(n);
        return NULL;
    }
    strcpy(n->label, label);
    n->value = value;
    n->next = NULL;
    return n;
}

/* Append a node to the list. */
int list_append(List *lst, int value, const char *label)
{
    if (!lst)
        return -1;
    Node *n = node_create(value, label);
    if (!n)
        return -1;
    if (!lst->head) {
        lst->head = n;
    } else {
        Node *cur = lst->head;
        while (cur->next)
            cur = cur->next;
        cur->next = n;
    }
    lst->size++;
    return 0;
}

/* Get the label of the first node. */
const char *list_first_label(const List *lst)
{
    if (!lst)
        return NULL;
    if (!lst->head)
        return NULL;
    return lst->head->label;
}

/* Free a single node. */
void node_free(Node *n)
{
    if (!n)
        return;
    free(n->label);
    free(n);
}

/* Free all nodes in a list. */
void list_clear(List *lst)
{
    if (!lst)
        return;
    Node *cur = lst->head;
    while (cur) {
        Node *next = cur->next;
        free(cur->label);
        free(cur);
        cur = next;
    }
    lst->head = NULL;
    lst->size = 0;
}
