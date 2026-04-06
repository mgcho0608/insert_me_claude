/*
 * uaf_demo.c -- minimal CWE-416 (Use After Free) demo fixture for insert_me.
 *
 * Contains a heap-allocated struct whose fields are written via arrow
 * dereferences within the same function scope.  The Seeder (pointer_deref
 * pattern with cwe416_use_after_free.json seed) ranks these dereference
 * sites; the Patcher inserts free() immediately before the top-ranked one,
 * producing a use-after-free vulnerability.
 *
 * Expected Seeder output (cwe416_use_after_free.json seed):
 *   process_record()  rec->id    -- arrow deref with prior malloc in scope
 *   process_record()  rec->value -- arrow deref with prior malloc in scope
 *
 * Expected mutation (Patcher, insert_premature_free strategy):
 *   Insert:  free(rec);
 *   Before:  rec->id    = id;      (or rec->value depending on seed RNG)
 *   Result:  use-after-free when rec is dereferenced after free().
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int id;
    int value;
} Record;

/*
 * Allocate a Record, set its fields, then print it.
 *
 * Seeder targets (arrow dereferences with prior malloc visible in scope):
 *   rec->id    = id;      -- candidate A
 *   rec->value = value;   -- candidate B
 */
void process_record(int id, int value)
{
    Record *rec = malloc(sizeof(Record));
    if (!rec)
        return;

    rec->id    = id;
    rec->value = value;
    printf("record id=%d value=%d\n", rec->id, rec->value);
    free(rec);
}
