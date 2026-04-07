# insert_me Strategy Catalog

> **Phase 9 + Phase 4c partial** — 5 strategies implemented; 4 corpus-admitted  
> **Machine-readable form:** `config/strategy_catalog.json`

This document lists all mutation strategies that insert_me knows about, with their current implementation maturity, corpus admission status, and Juliet test suite coverage anchors.

---

## Maturity Levels

| Level | Meaning |
|---|---|
| `IMPLEMENTED_AND_CORPUS_ADMITTED` | In `patcher.py`, has tests, quality gate pass rate >= 80%, reproducibility 100%, sandbox seeds accepted |
| `IMPLEMENTED_EXPERIMENTAL` | In `patcher.py`, has unit tests, but **not yet corpus-admitted**: insufficient sandbox coverage, missing seeds, or quality gate not yet run |
| `PLANNED` | Design is documented; implementation is next-priority but not started |
| `PARTIAL` | Prototype exists but quality gate pass rate < 80% |
| `CANDIDATE` | Feasibility assessed; no design yet; deferred |
| `DISABLED` | Was implemented; disabled due to quality issues |

---

## Corpus-Admitted Strategies

### CWE-122 — Heap-based Buffer Overflow  
**Strategy:** `alloc_size_undercount`  
**Pattern type:** `malloc_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Juliet anchor:** `CWE122_Heap_Based_Buffer_Overflow__c_CWE129_*`

Transforms `malloc(<expr>)` → `malloc((<expr>) - 1)`. Introduces a one-byte undercount in a heap allocation. When the caller writes the expected number of bytes the write overflows the allocated region.

Quality gate pass rate: **100%** (30/30 across sandbox_eval, 4/4 across target_b)

---

### CWE-416 — Use After Free  
**Strategy:** `insert_premature_free`  
**Pattern type:** `pointer_deref`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Juliet anchor:** `CWE416_Use_After_Free__*`

Inserts `free(<ptr>);` immediately before a pointer dereference (`ptr->field` or `*ptr`). The freed pointer is then used on the very next source line, producing a use-after-free.

Multi-signal scoring in seeder: prior-malloc-in-scope boost (+0.25), loop-body penalty (-0.40), conditional-guard penalty (-0.30), sub-malloc penalty (-0.35).

Quality gate pass rate: **100%** (19/19 sandbox_eval seeds; 5/5 target_b seeds)

---

### CWE-415 — Double Free  
**Strategy:** `insert_double_free`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Juliet anchor:** `CWE415_Double_Free__*`

Inserts a duplicate `free(<ptr>);` immediately before an existing `free()` call. Works on both `free(ptr)` (simple identifier) and `free(ptr->field)` (single arrow dereference). The heap allocator receives two calls to release the same pointer, which is undefined behaviour.

Seeder penalties: loop-body (-0.30), conditional-guard (-0.20), complex-expression args (-0.50).

Quality gate pass rate: **~90%** (9/10 sandbox_eval seeds; 3/3 target_b seeds ACCEPT_WITH_NOTES)

---

### CWE-401 — Missing Release of Memory after Effective Lifetime  
**Strategy:** `remove_free_call`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED_AND_CORPUS_ADMITTED  
**Juliet anchor:** `CWE401_Memory_Leak__*`

Replaces a `free(<ptr>);` call with a comment `/* CWE-401: free(ptr) removed - memory leak */`. The heap-allocated object is never released, causing a memory leak.

Same seeder penalties as `insert_double_free`.

Quality gate pass rate: **~90%** (9/10 sandbox_eval seeds; 3/3 target_b seeds ACCEPT_WITH_NOTES)

---

### CWE-476 — NULL Pointer Dereference  
**Strategy:** `remove_null_guard`  
**Pattern type:** `null_guard` (or `pointer_deref` with multi-line handler)  
**Maturity:** IMPLEMENTED_EXPERIMENTAL

Replaces a null-check guard (`if (!ptr) return;` / `if (ptr == NULL) return;`) with a comment, leaving a NULL dereference reachable at the subsequent `ptr->field` line. Uses the multi-line handler API (`_MULTILINE_STRATEGY_HANDLERS`) since the guard and dereference are on different lines.

Guard forms matched: `!ptr`, `ptr == NULL`, `ptr == nullptr`, `ptr == 0`, and reversed (`NULL == ptr`).

**Corpus admission: NOT ADMITTED — explicit blockers:**

1. **Handler only matches single-line inline guards.** The backward scan in `_mutate_remove_null_guard` looks for a guard line of the form `if (!ptr) return;` (guard body on the same line). If the guard body is on the next line (`if (!ptr)\n    return NULL;`) the scan hits `return NULL;` first (a non-blank, non-comment, non-matching line) and aborts before reaching the `if` line.

2. **Only 1 viable target found across all 9 sandbox source files.** Simulation of the handler's matching logic against `sandbox_eval/src/` (6 files) and `sandbox_targets/target_b/src/` (3 files) found exactly one viable site: `graph.c` lines 264–265 (`if (!g) return;` + loop). All other null-check guards in the sandbox use multi-line body style.

3. **Corpus admission requires ≥5 viable targets per sandbox (quality gate C1).** With only 1 viable target there is no path to a 5-seed minimum-viable quality gate run.

**To unblock:** Extend `_mutate_remove_null_guard` to handle multi-line guard bodies (guard head on one line, `return`/`return NULL;` on the next). After that enhancement, re-scan sandbox files to locate seeds, write seed files under `examples/seeds/sandbox/` and `examples/seeds/target_b/`, and run the full quality gate.

---

## Planned Strategies

### CWE-190 — Integer Overflow or Wraparound  
**Strategy:** *(not yet named)*  
**Pattern type:** `malloc_call` (or a new `overflow_guard` type)  
**Maturity:** PLANNED

Remove the overflow check (e.g., `if (n > MAX) return;`) that precedes a multiplication-based `malloc(n * sizeof(T))`. The resulting allocation is undersized when `n` overflows.

**Blocker resolved:** Multi-line mutation infrastructure now in place (`MultilineMutationResult`, `_MULTILINE_STRATEGY_HANDLERS`). Implementation can proceed following the CWE-476 pattern.

---

### CWE-787 — Out-of-bounds Write  
**Strategy:** *(not yet named)*  
**Pattern type:** `malloc_call`  
**Maturity:** PLANNED

Target `memcpy`/`strcpy` calls whose destination is a heap allocation; mutate the allocation to be smaller than the write size.

**Blocker:** Requires detecting the allocation that corresponds to the destination pointer. Backward-scan heuristic feasible but not yet designed.

---

## Candidate Strategies (Design Deferred)

| CWE | Name | Key Blocker |
|---|---|---|
| CWE-125 | Out-of-bounds Read | Simple single-line feasible; low priority |
| CWE-134 | Format String Injection | `string_operation` pattern exists; needs format-string detection |
| CWE-121 | Stack Buffer Overflow | Buffer size detection requires declaration scan |
| CWE-369 | Divide By Zero | Zero-guard removal; low security evaluation value |
| CWE-680 | Integer Overflow to Buffer Overflow | Two-stage mutation needed |

---

## Strategy–CWE Coverage Matrix

| Strategy | CWE | Maturity | Corpus Proven |
|---|---|---|---|
| `alloc_size_undercount` | CWE-122 | IMPLEMENTED | 34 cases (30 + 4 target_b) |
| `insert_premature_free` | CWE-416 | IMPLEMENTED | 24 cases (19 + 5 target_b) |
| `insert_double_free` | CWE-415 | IMPLEMENTED | 13 cases (10 + 3 target_b) |
| `remove_free_call` | CWE-401 | IMPLEMENTED | 13 cases (10 + 3 target_b) |
| `remove_null_guard` | CWE-476 | IMPLEMENTED_EXPERIMENTAL | 0 — not admitted; handler only matches inline single-line guards; only 1 viable target in sandbox |
| *(planned)* | CWE-190, CWE-787 | PLANNED | 0 |
| *(candidate)* | CWE-125, CWE-134, CWE-121, CWE-369, CWE-680 | CANDIDATE | 0 |

---

## Honest Assessment: Sustainable Case Count

With 4 implemented strategies across 2 sandbox targets:

- **sandbox_eval** (6 C files, ~750 LOC): 40 high-quality cases, **100% ACCEPT**
- **target_b** (3 C files, ~600 LOC): 15 high-quality cases, **100% ACCEPT** (13 ACCEPT + 2 ACCEPT_WITH_NOTES → 86.7% strict ACCEPT rate)

**Sustainable corpus size at current quality:** ~50-55 cases.

Adding further targets (target_c, target_d, ...) would scale linearly; each new 3-file sandbox contributes ~15 cases. Quality gate strictly enforces no duplicate file:line targets.
