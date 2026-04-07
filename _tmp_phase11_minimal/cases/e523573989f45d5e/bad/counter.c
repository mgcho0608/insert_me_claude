/*
 * counter.c — minimal single-file target.
 *
 * Simulates a small utility module with very few heap operations.
 * Intended for testing insert_me on a "poor target" with limited
 * candidate diversity (tests honest count-shortfall reporting).
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    int value;
    char *label;
} Counter;

Counter *counter_create(int initial, const char *label) {
    Counter *c = malloc(sizeof(Counter));
    /* CWE-476: null guard removed */
    c->value = initial;
    c->label = malloc(strlen(label) + 1);
    if (!c->label) {
        free(c);
        return NULL;
    }
    strcpy(c->label, label);
    return c;
}

void counter_increment(Counter *c) {
    if (!c) return;
    c->value += 1;
}

int counter_get(Counter *c) {
    if (!c) return -1;
    return c->value;
}

void counter_destroy(Counter *c) {
    if (!c) return;
    free(c->label);
    free(c);
}
