# insert_me Strategy Catalog

> **Phase 9** — Multi-strategy, multi-target corpus expansion  
> **Machine-readable form:** `config/strategy_catalog.json`

This document lists all mutation strategies that insert_me knows about, with their current implementation maturity and Juliet test suite coverage anchors.

---

## Maturity Levels

| Level | Meaning |
|---|---|
| `IMPLEMENTED` | Strategy is in `patcher.py`, has tests, and passes quality gate at >= 80% |
| `PLANNED` | Design is documented; implementation is next-priority but not started |
| `PARTIAL` | Prototype exists but quality gate pass rate < 80% |
| `CANDIDATE` | Feasibility assessed; no design yet; deferred |
| `DISABLED` | Was implemented; disabled due to quality issues |

---

## Implemented Strategies

### CWE-122 — Heap-based Buffer Overflow  
**Strategy:** `alloc_size_undercount`  
**Pattern type:** `malloc_call`  
**Maturity:** IMPLEMENTED  
**Juliet anchor:** `CWE122_Heap_Based_Buffer_Overflow__c_CWE129_*`

Transforms `malloc(<expr>)` → `malloc((<expr>) - 1)`. Introduces a one-byte undercount in a heap allocation. When the caller writes the expected number of bytes the write overflows the allocated region.

Quality gate pass rate: **100%** (30/30 across sandbox_eval, 4/4 across target_b)

---

### CWE-416 — Use After Free  
**Strategy:** `insert_premature_free`  
**Pattern type:** `pointer_deref`  
**Maturity:** IMPLEMENTED  
**Juliet anchor:** `CWE416_Use_After_Free__*`

Inserts `free(<ptr>);` immediately before a pointer dereference (`ptr->field` or `*ptr`). The freed pointer is then used on the very next source line, producing a use-after-free.

Multi-signal scoring in seeder: prior-malloc-in-scope boost (+0.25), loop-body penalty (-0.40), conditional-guard penalty (-0.30), sub-malloc penalty (-0.35).

Quality gate pass rate: **100%** (19/19 sandbox_eval seeds; 5/5 target_b seeds)

---

### CWE-415 — Double Free  
**Strategy:** `insert_double_free`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED  
**Juliet anchor:** `CWE415_Double_Free__*`

Inserts a duplicate `free(<ptr>);` immediately before an existing `free()` call. Works on both `free(ptr)` (simple identifier) and `free(ptr->field)` (single arrow dereference). The heap allocator receives two calls to release the same pointer, which is undefined behaviour.

Seeder penalties: loop-body (-0.30), conditional-guard (-0.20), complex-expression args (-0.50).

Quality gate pass rate: **~90%** (9/10 sandbox_eval seeds; 3/3 target_b seeds ACCEPT_WITH_NOTES)

---

### CWE-401 — Missing Release of Memory after Effective Lifetime  
**Strategy:** `remove_free_call`  
**Pattern type:** `free_call`  
**Maturity:** IMPLEMENTED  
**Juliet anchor:** `CWE401_Memory_Leak__*`

Replaces a `free(<ptr>);` call with a comment `/* CWE-401: free(ptr) removed - memory leak */`. The heap-allocated object is never released, causing a memory leak.

Same seeder penalties as `insert_double_free`.

Quality gate pass rate: **~90%** (9/10 sandbox_eval seeds; 3/3 target_b seeds ACCEPT_WITH_NOTES)

---

## Planned Strategies

### CWE-476 — NULL Pointer Dereference  
**Strategy:** *(not yet named)*  
**Pattern type:** `pointer_deref`  
**Maturity:** PLANNED

Remove or invert the null-check guard before a pointer dereference. Target: `if (!ptr) return;` followed by `ptr->field`. Mutation: remove the guard line.

**Blocker:** Patcher currently operates on single lines. Removing a guard requires a two-line deletion mode. Design needed before implementation.

---

### CWE-190 — Integer Overflow or Wraparound  
**Strategy:** *(not yet named)*  
**Pattern type:** `malloc_call`  
**Maturity:** PLANNED

Remove the overflow check (e.g., `if (n > MAX) return;`) that precedes a multiplication-based `malloc(n * sizeof(T))`. The resulting allocation is undersized when `n` overflows.

**Blocker:** Multi-line mutation (delete the guard, keep the malloc). Same requirement as CWE-476.

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
| *(planned)* | CWE-476, CWE-190, CWE-787 | PLANNED | 0 |
| *(candidate)* | CWE-125, CWE-134, CWE-121, CWE-369, CWE-680 | CANDIDATE | 0 |

---

## Honest Assessment: Sustainable Case Count

With 4 implemented strategies across 2 sandbox targets:

- **sandbox_eval** (6 C files, ~750 LOC): 40 high-quality cases, **100% ACCEPT**
- **target_b** (3 C files, ~600 LOC): 15 high-quality cases, **100% ACCEPT** (13 ACCEPT + 2 ACCEPT_WITH_NOTES → 86.7% strict ACCEPT rate)

**Sustainable corpus size at current quality:** ~50-55 cases.

Adding further targets (target_c, target_d, ...) would scale linearly; each new 3-file sandbox contributes ~15 cases. Quality gate strictly enforces no duplicate file:line targets.
