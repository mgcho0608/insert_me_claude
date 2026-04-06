/*
 * heap_buf.c -- minimal demo source for insert_me.
 *
 * This file is intentionally small so that a new user can see exactly what
 * the Seeder finds and scores.  It is NOT a security-sensitive reference --
 * it is a demonstration fixture only.
 *
 * Expected Seeder output (cwe122_heap_overflow.json seed):
 *   process_request() line ~14  score 0.75  malloc with arithmetic
 *   sum_scores()       line ~24  score 0.75  for-loop with <= bound
 */

#include <stdlib.h>
#include <string.h>

// Copy user data into a heap buffer -- size derived from user-controlled len.
// Seeder target: malloc call with arithmetic in size argument.
void process_request(const char *data, size_t user_len)
{
    char *buf = malloc(user_len * sizeof(char));
    if (!buf) return;
    memcpy(buf, data, user_len);
    free(buf);
}

// Accumulate an array of integer scores.
// Seeder target: for-loop with <= bound (off-by-one, should be < count).
int sum_scores(int *scores, int count)
{
    int total = 0;
    for (int i = 0; i <= count; i++) {
        total += scores[i];
    }
    return total;
}
