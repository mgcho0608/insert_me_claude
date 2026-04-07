# insert_me Strategy Catalog

> **Phase 15 — multi-target portfolio orchestration + truth closure**  
> **Machine-readable form:** `config/strategy_catalog.json` (schema: `schemas/strategy_catalog.schema.json`)

This document lists all mutation strategies that insert_me knows about, with their
current implementation maturity, corpus admission status, and Juliet test suite
coverage anchors.

**Total entries: 15**

| Maturity | Count | Strategy IDs |
|---|---|---|
| IMPLEMENTED_AND_CORPUS_ADMITTED | 6 | alloc_size_undercount, insert_premature_free, insert_double_free, remove_free_call, remove_null_guard, remove_size_cast |
| PLANNED | 1 | CWE-787 |
| CANDIDATE | 8 | CWE-125, CWE-134, CWE-121, CWE-369, CWE-680, CWE-131, CWE-252, CWE-120 |

The **planning layer** (`insert-me plan-corpus`, `insert-me generate-corpus`, `insert-me plan-portfolio`, `insert-me generate-portfolio`) uses only
`IMPLEMENTED_AND_CORPUS_ADMITTED` strategies by default. All other entries are planning-layer BLOCKED.

---

## Maturity Levels

| Level | Meaning |
|---|---|
| `IMPLEMENTED_AND_CORPUS_ADMITTED` | In `patcher.py`, has tests, quality gate pass rate >= 80%, reproducibility 100%, sandbox seeds accepted |
| `IMPLEMENTED_EXPERIMENTAL` | In `patcher.py`, has unit tests, but **not yet corpus-admitted**: insufficient sandbox coverage, missing seeds, or quality gate not yet run |
| `PLANNED` | Design is documented; multi-line handler infrastructure available; implementation is next-priority |
| `CANDIDATE` | Feasibility assessed; no design or implementation yet |
| `DISABLED` | Was implemented; disabled due to quality issues |

---

## Corpus-Admitted Strategies

### CWE-122 — Heap-based Buffer Overflow
**Strategy:** `alloc_size_undercount`  
**Pattern type:** `malloc_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE122_Heap_Based_Buffer_Overflow__c_CWE129_*`

Transforms `malloc(<expr>)` → `malloc((<expr>) - 1)`. Introduces a one-byte undercount
in a heap allocation. When the caller writes the expected number of bytes the write
overflows the allocated region.

Quality gate pass rate: **100%** (30/30 sandbox_eval, 4/4 target_b)  
Corpus cases: **34**

Common failure modes:
- `malloc(sizeof(T))` without arithmetic — mutation is syntactically valid but semantically trivial
- `malloc` result unused — NOOP audit if pointer not written through

---

### CWE-416 — Use After Free
**Strategy:** `insert_premature_free`  
**Pattern type:** `pointer_deref`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE416_Use_After_Free__*`

Inserts `free(<ptr>);` immediately before a pointer dereference (`ptr->field` or `*ptr`).
The freed pointer is then used on the very next source line, producing a use-after-free.

Multi-signal scoring: prior-malloc-in-scope boost (+0.25), loop-body penalty (-0.40),
conditional-guard penalty (-0.30), sub-malloc penalty (-0.35).

Quality gate pass rate: **100%** (19/19 sandbox_eval, 5/5 target_b)  
Corpus cases: **24**

Common failure modes:
- Loop-body dereference: free inside a loop causes repeated free on second iteration
- Sub-malloc: free before `malloc(ptr->field)` creates a secondary flaw

---

### CWE-415 — Double Free
**Strategy:** `insert_double_free`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE415_Double_Free__*`

Inserts a duplicate `free(<ptr>);` immediately before an existing `free()` call.
Works on both `free(ptr)` and `free(ptr->field)`.

Seeder penalties: loop-body (-0.30), conditional-guard (-0.20), complex-expression (-0.50).

Quality gate pass rate: **~90%** (9/10 sandbox_eval, 3/3 target_b)  
Corpus cases: **13** (10 ACCEPT, 3 ACCEPT_WITH_NOTES)

---

### CWE-401 — Missing Release of Memory after Effective Lifetime
**Strategy:** `remove_free_call`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE401_Memory_Leak__*`

Replaces `free(<ptr>);` with a comment `/* CWE-401: free(ptr) removed - memory leak */`.
The heap-allocated object is never released, causing a memory leak.

Same seeder penalties as `insert_double_free`.

Quality gate pass rate: **~90%** (9/10 sandbox_eval, 3/3 target_b)  
Corpus cases: **13** (10 ACCEPT, 3 ACCEPT_WITH_NOTES)

---

### CWE-476 — NULL Pointer Dereference
**Strategy:** `remove_null_guard`  
**Pattern type:** `null_guard`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE476_NULL_Pointer_Dereference__*`

Replaces a null-check guard with a comment, leaving a NULL dereference reachable at the
subsequent `ptr->field` line. Uses the multi-line handler API (`_MULTILINE_STRATEGY_HANDLERS`).

**Dual-mode handler (Phase 10):**
- *Primary mode:* target line is the guard head (Seeder `null_guard` pattern). Forward scans
  for the deref within 4 lines. Guard body lines (`return`/`break`/`continue` on the next line)
  are detected and blanked out so they don't leave unreachable code.
- *Backward-compat mode:* target line is the dereference; backward scan finds the guard.

Guard forms matched: `!ptr`, `ptr == NULL`, `ptr == nullptr`, `ptr == 0`, reversed (`NULL == ptr`).  
Supported multiline form: `if (!ptr)\n    return NULL;` (body on separate line blanked in output).

Quality gate pass rate: **100%** (8/8 sandbox_eval seeds VALID; 5/5 VALID on target_b bstree/dynarray/strmap)  
Corpus cases: **8** (sandbox_eval seeds)

---

### CWE-190 — Integer Overflow or Wraparound
**Strategy:** `remove_size_cast`  
**Pattern type:** `malloc_size_cast`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Suitable for planning:** YES  
**Juliet anchor:** `CWE190_Integer_Overflow__*`

Removes the `(size_t)` cast from `malloc((size_t)EXPR * sizeof(T))`, enabling integer
overflow in the size arithmetic when `EXPR` is large. Conservative single-line handler:
exactly one `(size_t)` cast at the start of the malloc argument; double-cast lines are
correctly skipped (NOOP — expected behaviour).

Quality gate pass rate: **87.5%** (7/8 sandbox seeds VALID; 1 correct NOOP on double-cast line)  
Unique VALID targets: htable.c:176, htable.c:148, graph.c:90, list.c:193  
Note: `remove_size_cast` is primarily applicable to sandbox_eval; target_b and
moderate/minimal local fixtures have no `(size_t)`-cast malloc lines.

---

## Planned Strategies

### CWE-787 — Out-of-bounds Write
**Strategy:** *(not yet named)*  
**Pattern type:** `malloc_call`  
**Maturity:** PLANNED  
**Juliet anchor:** `CWE787_Write_What_Where_Condition__*`

Reduce the size of a heap allocation feeding a `memcpy`/`strcpy` so the write exceeds
the allocated region.

**Blocker:** Requires detecting the allocation that corresponds to the destination
pointer of the subsequent write.

---

## Candidate Strategies (Design Deferred)

These strategies are in the catalog for planning-space coverage; none are implemented.

| CWE | Name | Pattern Type | Key Blocker / Note |
|---|---|---|---|
| CWE-125 | Out-of-bounds Read | `array_index` | Simple single-line feasible; low priority |
| CWE-134 | Format String Injection | `format_string` | `string_operation` pattern exists; needs format-string detection |
| CWE-121 | Stack-based Buffer Overflow | `string_operation` | Buffer size detection requires declaration scan |
| CWE-369 | Divide By Zero | `custom` | Zero-guard removal; low security evaluation value |
| CWE-680 | Integer Overflow to Buffer Overflow | `malloc_call` | Two-stage mutation; deferred until CWE-190 is done |
| CWE-131 | Incorrect Calculation of Buffer Size | `malloc_call` | Replace `sizeof(T)` with `sizeof(T*)`; requires struct type detection |
| CWE-252 | Unchecked Return Value | `malloc_call` | Remove null-check after malloc; multi-line blocker |
| CWE-120 | Buffer Copy Without Checking Size | `string_operation` | Replace `strncpy(buf, src, n)` with `strcpy(buf, src)`; simple |

---

## Strategy–CWE Coverage Matrix

| Strategy | CWE | Maturity | Planning | Corpus Cases |
|---|---|---|---|---|
| `alloc_size_undercount` | CWE-122 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 34 (30 + 4 target_b) |
| `insert_premature_free` | CWE-416 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 24 (19 + 5 target_b) |
| `insert_double_free` | CWE-415 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 13 (10 + 3 target_b) |
| `remove_free_call` | CWE-401 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 13 (10 + 3 target_b) |
| `remove_null_guard` | CWE-476 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 8 sandbox_eval + 5 target_b |
| `remove_size_cast` | CWE-190 | IMPLEMENTED_AND_CORPUS_ADMITTED | VIABLE | 7/8 VALID (1 correct NOOP; sandbox_eval only) |
| *(planned)* | CWE-787 | PLANNED | BLOCKED | 0 |
| *(candidate x 8)* | CWE-125/134/121/369/680/131/252/120 | CANDIDATE | BLOCKED | 0 |

---

## Honest Assessment: Sustainable Case Count

With 6 implemented corpus-admitted strategies across 2 sandbox targets:

- **sandbox_eval** (6 C files, ~750 LOC): 56 seeds → 55 high-quality accepted cases (CWE-190: 7 VALID + 1 correct NOOP)
- **target_b** (3 C files, ~600 LOC): 20 seeds → 20 high-quality accepted cases (**100% ACCEPT**)

**Total sandbox accepted corpus: 76 seeds, ~75 unique accepted cases.**

**Sustainable corpus size at current quality:** ~65–75 cases per typical 2-target portfolio.

Each new well-structured 3–6 file C target contributes ~10–20 cases via the planning layer.
The planning layer (`plan-corpus`, `plan-portfolio`) computes this honestly: if only K < N accepted
cases are achievable it says so explicitly rather than generating low-quality cases
to pad the count.

---

## Planning Layer Suitability vs. Implementation Maturity

These are orthogonal concepts:

| | Planning-VIABLE | Planning-LIMITED | Planning-BLOCKED |
|---|---|---|---|
| What it means | >= 10 candidates across >= 3 files for this strategy in the target | 1–9 candidates or < 3 files | 0 candidates OR strategy not corpus-admitted |
| Set by | TargetInspector per target | TargetInspector per target | TargetInspector per target |
| Depends on | Target source code richness | Target source code richness | Target code OR strategy maturity |

A strategy can be IMPLEMENTED_AND_CORPUS_ADMITTED but still be Planning-BLOCKED on a
specific target if that target has no patterns that match the strategy's `pattern_type`.
Conversely, a richer target can make a strategy Planning-VIABLE that was Planning-LIMITED
on a smaller target.
