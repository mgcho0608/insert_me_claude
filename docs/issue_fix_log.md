# Issue / Fix Log — insert_me Corpus Hardening

> **Phase:** 8 — Reliability, Reproducibility, and Corpus-Quality Hardening  
> **Scope:** Issues discovered during corpus generation against evaluation-only sandbox targets.
> Each entry records an observed quality problem, the evidence that confirmed it, the root cause
> in the insert_me pipeline, and the fix applied — plus the verification that the fix works.

---

## Format

Each entry follows this structure:

```
### IFL-NNN — Short title
**Observed:** What was seen (case file, line, diff context)
**Evidence:** Why this is a quality problem
**Root cause:** Where in the pipeline the fault originates
**Fix:** Code or config change applied
**Verification:** How the fix was confirmed to work
**Status:** FIXED / OPEN / WONT_FIX
```

---

## IFL-001 — Conditional-guard lines selected as CWE-416 targets

**Observed:** Seeder selected lines such as `if (!g->vertices)`, `if (!q->head)` as
top CWE-416 (`pointer_deref`) candidates. When `insert_premature_free` inserts `free(ptr)`
immediately before these lines, the pattern becomes:

```c
free(g);                     // ← inserted
if (!g->vertices) {          // ← derefs freed pointer — UAF
    free(g);                 // ← double-free if branch taken
    return NULL;
}
```

**Evidence:** The error-handling branch `if (!ptr->field) { free(ptr); }` creates a
second independent flaw (double-free) whenever the inner allocation fails. This violates
Criterion C1 (Single Primary Flaw).

**Root cause:** `seeder.py → _extract_candidates()` scored pointer-dereference lines
inside conditional guards (`if/while/for (`) the same as other pointer-dereference lines.
The existing `_has_prior_malloc_in_scope` boost was applied without penalising lines
inside guard expressions.

**Fix:** Added a `-0.30` score penalty in `_extract_candidates()` for any
`pointer_deref` candidate line that matches `^\s*(?:if|while|for)\s*\(`:

```python
if re.match(r"\s*(?:if|while|for)\s*\(", line):
    candidate.score = max(candidate.score - 0.30, 0.0)
```

Updated docstring in `_score_line()` to document the penalty.

**Verification:** Re-ran all 30 seed files. None of the 30 accepted cases inserts
`free()` before a conditional guard. All 30 cases classified VALID by Auditor.

**Status:** FIXED (commit 75d89d7)

---

## IFL-002 — Loop-body lines selected as CWE-416 targets

**Observed:** Case 4 (`cwe416_sb_003`, seed=3, original target `list.c:235`)
was selecting `tail_list->size++` inside a `while (cur) { ... }` loop body.
When `insert_premature_free` inserts `free(tail_list)` before that line:

```c
while (cur) {
    free(tail_list);     // ← inserted: executes on EVERY iteration
    tail_list->size++;   // ← UAF on first iteration, use of freed mem on all
    cur = cur->next;
}
```

**Evidence:** The free executes on every loop iteration, not just once. This is
a severe pattern that does not correspond to the "insert one premature free before
a pointer use" description. It introduces a loop-correlated multi-execution free,
which is a secondary flaw beyond the intended single UAF.

**Root cause:** `seeder.py` did not track whether a candidate line was inside a
loop body. The existing brace-tracking logic only detected function boundaries,
not loop boundaries.

**Fix:** Added `_is_inside_loop_body()` helper (backward brace-depth scan) and
a `-0.40` penalty in `_extract_candidates()` for `pointer_deref` candidates inside
a loop body:

```python
if ptr_name and _is_inside_loop_body(lines, lineno - 1):
    candidate.score = max(candidate.score - 0.40, 0.0)
```

`_is_inside_loop_body()` scans backward from the candidate line counting `{` and
`}`. When the brace depth goes negative (found the enclosing `{`), it checks
whether that line or the immediately preceding lines contain `while (` or `for (`.
Stops at function boundaries (bare `}` at column 0).

**Verification:** Re-ran `cwe416_sb_003` (seed=3). New target: `list.c:227`
(`tail_list->head = pos;` in `list_split_at`, before the while loop). Classified VALID.

**Status:** FIXED (commit 75d89d7)

---

## IFL-003 — Sub-malloc lines selected as CWE-416 targets

**Observed:** Cases 1, 5, 6, 7 (targeting `htable.c:71`, `graph.c:166`, `graph.c:52`,
`htable.c:49`) selected lines of the form `ptr->field = malloc(...)`. When
`insert_premature_free` inserts `free(ptr)` before these lines:

```c
free(e);                             // ← inserted
e->key = malloc(klen * sizeof(char)); // ← UAF: e already freed
if (!e->key) {
    free(e);                          // ← double-free if malloc fails
    return NULL;
}
```

**Evidence:** The standard error-handling idiom for sub-allocations is
`if (!ptr->field) { free(ptr); return NULL; }`. Inserting `free(ptr)` before
the sub-allocation converts this idiom into a double-free on the error path.
Two independent flaws: UAF + double-free. Violates C1.

**Root cause:** `seeder.py` scored `ptr->field = malloc(...)` lines as strong
`pointer_deref` candidates (arrow dereference detected, prior malloc in scope boost
applied). The sub-allocation pattern was not distinguished from plain field writes.

**Fix:** Added a `-0.35` penalty in `_extract_candidates()` for `pointer_deref`
candidate lines that match the sub-allocation pattern:

```python
if re.search(
    r"\b\w+\s*->\s*\w+\s*=\s*(?:malloc|calloc|realloc)\s*\(",
    line,
):
    candidate.score = max(candidate.score - 0.35, 0.0)
```

**Verification:** Re-ran all 30 seeds. No sub-allocation lines appear as CWE-416
targets in the accepted corpus. All 30 cases classified VALID by Auditor.

**Status:** FIXED (commit 75d89d7)

---

## IFL-004 — Function scope boundary crossed by backward scan

**Observed:** `_has_prior_malloc_in_scope()` was finding `ListNode *node = malloc(...)`
from function `list_insert_after` when scanning for `node` in `list_update_node` (where
`node` is a parameter, not an allocation). This produced a false `+0.25` score boost
for an `_update_node` candidate that was not genuinely an allocation-then-deref pattern.

**Evidence:** The `node` parameter in `list_update_node(List *lst, ListNode *node, ...)`
was matching the malloc assignment in the preceding function `list_insert_after`, because
the 100-line backward scan window crossed the function boundary.

**Root cause:** `_has_prior_malloc_in_scope()` and `_find_malloc_line()` scanned up to
100 lines backward without stopping at function boundaries.

**Fix:** Added a function-boundary guard: both functions now stop scanning when they
encounter a bare `}` at column 0 (the standard C function-closing-brace pattern):

```python
if raw.startswith("}") and raw.rstrip() in ("}", "};"):
    break
```

Also applied to `_find_malloc_line()` for consistency.

**Verification:** Re-ran all 30 seeds. Score distributions are unchanged for legitimate
cases. No cross-function false-positive boosts detected in the accepted corpus.

**Status:** FIXED (commit 75d89d7)

---

## IFL-005 — Duplicate file:line targets across different seeds

**Observed:** Before seed-integer adjustment, seeds `cwe416_sb_009` (seed=10)
and `cwe416_sb_011` (seed=14) both produced target `list.c:154`. Similarly,
`cwe416_sb_007` (seed=7) and `cwe416_sb_012` (seed=16) both produced `list.c:155`.
Two pairs of exact duplicates in a 23-case corpus.

**Evidence:** Duplicate targets produce identical mutations: the bad/good trees are
the same, the ground_truth records the same file:line. The corpus would contain
two copies of the same case, inflating the count with zero additional signal.
Violates C7 (Evaluator Usefulness — duplicate).

**Root cause:** The within-tier shuffle in `Seeder._order_targets()` uses the seed
integer to break ties among equal-score candidates. When multiple seeds produce the
same score tier with the same shuffle order, they select the same top candidate.
Seeds 10 and 14 happened to produce the same shuffle result for the `list.c:154` tier.

**Fix:** Changed seed integers for the affected files:
- `cwe416_sb_011`: seed 14 → 20 → new target `list.c:156` (same function, different line)
- `cwe416_sb_012`: seed 16 → 22 → new target `list.c:229` (different function)

**Verification:** Re-ran all 30 seeds. Duplicate check: `len(unique targets) == 30`. Confirmed.

**Status:** FIXED (commit 75d89d7)

---

## IFL-006 — Function signature regex produces single-character spurious names

**Observed:** `_find_enclosing_function()` returned `'f'` for all candidate lines,
regardless of the actual enclosing function. This caused `context.function_name` to be
`'f'` for every case in the corpus, and made the per-function diversity tracking in
`generate_corpus.py` report "Unique functions: 1" for all 30 cases.

**Evidence:** Debug scan showed `_FUNC_SIG_RE` matching `    if (` on lines like:
```
line 67: match='    if ('  group1='f'
```
The root cause is regex backtracking: `[\w_]+` (greedy) first matched `if` (2 chars),
then the rest of the pattern failed. The engine backtracked to `i` (1 char), leaving
`f (` for the next part of the pattern, where `(\w+)` captured `f` and `\s*\(` matched ` (`.

**Root cause:** `_FUNC_SIG_RE` lacked a negative lookahead for C statement keywords.
The catch-all alternative `[\w_]+\s*\**` can match the first character of any C keyword
(`if`, `while`, `for`, `memcpy`, `free`, etc.), leaving the rest of the keyword word
to be captured as the "function name".

**Fix:** Added a negative lookahead `(?!(?:if|while|for|switch|return|...)` after `^\s*`
in `_FUNC_SIG_RE`:

```python
_FUNC_SIG_RE = re.compile(
    r"^\s*"
    r"(?!(?:if|while|for|switch|return|break|continue|do|else|goto"
    r"|typedef|sizeof|free|memcpy|memmove|memset|strcpy|strcat)\b)"
    ...
)
```

**Verification:** Re-ran function name extraction for all corpus target lines.
All 30 cases now report their actual enclosing function (`queue_new`, `list_insert_after`,
`strbuf_concat_new`, etc.). `generate_corpus.py` now reports "Unique functions: 19".
All 406 tests still pass.

**Status:** FIXED (Phase 8 commit)

---

## Open Issues

No open issues at time of Phase 8 initial pass.

### Issue Template

```
## IFL-NNN — Title

**Observed:**
**Evidence:**
**Root cause:**
**Fix:**
**Verification:**
**Status:** OPEN
```
