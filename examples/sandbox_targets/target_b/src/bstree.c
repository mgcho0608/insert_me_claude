/*
 * bstree.c -- unbalanced binary search tree for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code. Left/right child pointer patterns
 * and recursive traversal provide CWE-416/CWE-415/CWE-401/CWE-122
 * mutation sites distinct from the array/list patterns.
 *
 * Patterns present:
 *   CWE-416 (pointer_deref after malloc): bst_insert, bst_find, bst_delete
 *   CWE-122 (malloc with expr): bst_new_node (key+val copy), bst_copy (recursive)
 *   CWE-415 (free_call): bst_delete_node, bst_free_node, bst_clear
 *   CWE-401 (free_call — remove): bst_delete, bst_free_node, bst_clear
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct BSTNode {
    char           *key;
    char           *value;
    struct BSTNode *left;
    struct BSTNode *right;
} BSTNode;

typedef struct BSTree {
    BSTNode *root;
    size_t   count;
    int      flags;
} BSTree;

/* ---- internal helpers ---- */

static BSTNode *bst_new_node(const char *key, const char *value)
{
    BSTNode *n = malloc(sizeof(BSTNode));
    if (!n)
        return NULL;

    size_t klen = strlen(key) + 1;
    n->key = malloc(klen * sizeof(char));
    if (!n->key) {
        free(n);
        return NULL;
    }
    memcpy(n->key, key, klen);

    size_t vlen = strlen(value) + 1;
    n->value = malloc(vlen * sizeof(char));
    if (!n->value) {
        free(n->key);
        free(n);
        return NULL;
    }
    memcpy(n->value, value, vlen);

    n->left  = NULL;
    n->right = NULL;
    return n;
}

static void bst_free_node(BSTNode *n)
{
    if (!n)
        return;
    free(n->key);
    free(n->value);
    free(n);
}

/* ---- public API ---- */

/* Allocate an empty BSTree. */
BSTree *bst_new(void)
{
    BSTree *t = malloc(sizeof(BSTree));
    if (!t)
        return NULL;
    t->root  = NULL;
    t->count = 0;
    t->flags = 0;
    return t;
}

/* Insert or update key/value. Returns 0 on success, -1 on allocation failure. */
int bst_insert(BSTree *t, const char *key, const char *value)
{
    BSTNode **cur = &t->root;
    while (*cur) {
        int cmp = strcmp(key, (*cur)->key);
        if (cmp == 0) {
            /* Update existing value. */
            size_t vlen = strlen(value) + 1;
            char *new_val = malloc(vlen * sizeof(char));
            if (!new_val)
                return -1;
            free((*cur)->value);
            memcpy(new_val, value, vlen);
            (*cur)->value = new_val;
            return 0;
        }
        cur = (cmp < 0) ? &(*cur)->left : &(*cur)->right;
    }

    BSTNode *n = bst_new_node(key, value);
    if (!n)
        return -1;
    *cur = n;
    t->count++;
    return 0;
}

/* Find value by key; returns pointer to stored value string, or NULL. */
const char *bst_find(const BSTree *t, const char *key)
{
    const BSTNode *cur = t->root;
    while (cur) {
        int cmp = strcmp(key, cur->key);
        if (cmp == 0)
            return cur->value;
        cur = (cmp < 0) ? cur->left : cur->right;
    }
    return NULL;
}

/* Find the in-order minimum node in a subtree (used by bst_delete). */
static BSTNode *bst_min_node(BSTNode *n)
{
    while (n->left)
        n = n->left;
    return n;
}

/* Delete a key from the tree. Returns 0 if deleted, -1 if not found. */
int bst_delete(BSTree *t, const char *key)
{
    BSTNode **cur = &t->root;
    while (*cur) {
        int cmp = strcmp(key, (*cur)->key);
        if (cmp == 0)
            break;
        cur = (cmp < 0) ? &(*cur)->left : &(*cur)->right;
    }
    if (!*cur)
        return -1;

    BSTNode *del = *cur;
    if (!del->left) {
        *cur = del->right;
    } else if (!del->right) {
        *cur = del->left;
    } else {
        /* Two children: replace with in-order successor. */
        BSTNode *succ = bst_min_node(del->right);
        char *sk = strdup(succ->key);
        char *sv = strdup(succ->value);
        bst_delete(t, succ->key);   /* recursive delete of successor */
        free(del->key);
        free(del->value);
        del->key   = sk;
        del->value = sv;
        t->count++;   /* compensate for the decrement in recursive call */
        return 0;
    }
    bst_free_node(del);
    t->count--;
    return 0;
}

/* In-order traversal; calls cb(key, value, userdata) for each node. */
static void bst_inorder_r(const BSTNode *n,
                           void (*cb)(const char *, const char *, void *),
                           void *userdata)
{
    if (!n)
        return;
    bst_inorder_r(n->left, cb, userdata);
    cb(n->key, n->value, userdata);
    bst_inorder_r(n->right, cb, userdata);
}

void bst_foreach(const BSTree *t,
                 void (*cb)(const char *, const char *, void *),
                 void *userdata)
{
    bst_inorder_r(t->root, cb, userdata);
}

/* Recursively deep-copy a subtree. */
static BSTNode *bst_copy_node(const BSTNode *src)
{
    if (!src)
        return NULL;
    BSTNode *n = bst_new_node(src->key, src->value);
    if (!n)
        return NULL;
    n->left  = bst_copy_node(src->left);
    n->right = bst_copy_node(src->right);
    return n;
}

/* Deep copy entire tree. Caller owns result. */
BSTree *bst_copy(const BSTree *src)
{
    BSTree *dst = malloc(sizeof(BSTree));
    if (!dst)
        return NULL;
    dst->root  = bst_copy_node(src->root);
    dst->count = src->count;
    dst->flags = src->flags;
    return dst;
}

/* Recursively free all nodes in a subtree. */
static void bst_clear_r(BSTNode *n)
{
    if (!n)
        return;
    bst_clear_r(n->left);
    bst_clear_r(n->right);
    bst_free_node(n);
}

/* Remove all nodes; tree struct remains valid (empty). */
void bst_clear(BSTree *t)
{
    bst_clear_r(t->root);
    t->root  = NULL;
    t->count = 0;
}

/* Free all nodes and the tree header. */
void bst_free(BSTree *t)
{
    if (!t)
        return;
    bst_clear(t);
    free(t);
}
