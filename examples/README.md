# Examples — insert_me

---

## Current phase (Phase 9 + Phase 4c partial — batch CLI, multi-line patcher, 5 strategies)

All four core pipeline stages are implemented.  You can run the pipeline today and get
**a complete output bundle**: real bad/good source trees, `validation_result.json` from
five rule-based plausibility checks, and `ground_truth.json` / `audit.json` /
`audit_result.json` from the real Auditor.

---

## `demo/` — minimal runnable demo

A self-contained demo you can run right now.

**Source file:** `demo/src/heap_buf.c`
A minimal C file with two clearly labeled Seeder candidates:
- `malloc(user_len * sizeof(char))` — heap buffer size with arithmetic
- `for (i <= count)` — off-by-one loop bound

**To run (real mode — default):**

```bash
# From the repository root
insert-me run \
  --seed-file examples/seeds/cwe122_heap_overflow.json \
  --source examples/demo/src

# Validate the generated bundle (replace <run-id> with the printed run ID)
insert-me validate-bundle output/<run-id>/
```

**Expected result:**
- `patch_plan.json` — `status: "APPLIED"`, one target in `heap_buf.c`
- `bad/heap_buf.c` — mutated: `malloc((user_len * sizeof(char)) - 1)`
- `good/heap_buf.c` — byte-identical copy of original
- `ground_truth.json` — one mutation record, `validation_passed: true`
- `validation_result.json` — `overall: "PASS"`, five checks passing
- `audit_result.json` — `classification: "VALID"`

**To preview without modifying sources (dry-run):**

```bash
insert-me run \
  --seed-file examples/seeds/cwe122_heap_overflow.json \
  --source examples/demo/src \
  --dry-run
```

Dry-run: `status: "PLANNED"`, no source copies, `ground_truth.json` `mutations: []`.

---

## CWE-416 Use After Free demo

**Source file:** `demo/src/uaf_demo.c`
A minimal C file with a `process_record()` function that allocates a `Record` struct
and writes to it via arrow dereferences — candidates for `insert_premature_free`.

**To run (real mode):**

```bash
insert-me run \
  --seed-file examples/seeds/cwe416_use_after_free.json \
  --source examples/demo/src

insert-me validate-bundle output/<run-id>/
```

**Expected result:**
- `patch_plan.json` — `status: "APPLIED"`, one target in `uaf_demo.c`
- `bad/uaf_demo.c` — `free(rec);` inserted before `rec->id = id;` (or `rec->value`)
- `good/uaf_demo.c` — byte-identical copy of original
- `ground_truth.json` — `mutation_type: "insert_premature_free"`, `extra.freed_pointer: "rec"`
- `audit_result.json` — `classification: "VALID"`

**What changed (bad/ vs good/):**
```diff
+     free(rec);
      rec->id    = id;
```
One extra line in `bad/`; all other content identical.

---

## `seeds/` — canonical seed files

| File | CWE | Pattern type | Strategy | Status |
|---|---|---|---|---|
| `cwe122_heap_overflow.json` | CWE-122 Heap Buffer Overflow | `malloc_call` | `alloc_size_undercount` | corpus-admitted |
| `cwe416_use_after_free.json` | CWE-416 Use After Free | `pointer_deref` | `insert_premature_free` | corpus-admitted |
| `cwe415_double_free.json` | CWE-415 Double Free | `free_call` | `insert_double_free` | corpus-admitted |
| `cwe401_memory_leak.json` | CWE-401 Memory Leak | `free_call` | `remove_free_call` | corpus-admitted |
| `cwe476_null_deref.json` | CWE-476 NULL Pointer Dereference | `null_guard` | `remove_null_guard` | experimental — not corpus-admitted |
| `cwe190_integer_overflow.json` | CWE-190 Integer Overflow | `malloc_call` | *(planned)* | planned |

Corpus-admitted strategies have sandbox seeds under `examples/seeds/sandbox/` and `examples/seeds/target_b/`.
`remove_null_guard` is implemented but not yet corpus-admitted (handler only matches single-line inline guards; see `docs/strategy_catalog.md` for details).

These seed files are valid inputs to `insert-me run --seed-file`.

---

## `expected_outputs/` — reference artifacts for schema testing

Reference JSON artifacts used in the schema test suite
(`tests/test_schemas.py`).  These are not output from a real run — they are
hand-crafted examples that exercise the schema validators.

---

---

## `evaluation/` — evaluation demo fixtures

Normalized detector reports for testing the `insert-me evaluate` command against the CWE-416 demo bundle.

| File | Description | Expected match level | Adjudication verdict |
|---|---|---|---|
| `exact_match_report.json` | Finding in `uaf_demo.c` at correct line with CWE-416 | `exact` | N/A |
| `family_match_report.json` | Finding in `uaf_demo.c` with CWE-415 (double-free, same family) | `family` | N/A |
| `no_match_report.json` | Finding in `other.c` with CWE-122 (different file and CWE) | `no_match` | N/A |
| `semantic_match_report.json` | `uaf_demo.c` line 42, message contains "use after free" | `semantic` | `match` (score ≈ 0.70) |
| `semantic_unresolved_report.json` | `uaf_demo.c` line 100, weak keyword "freed memory issue" | `semantic` | `unresolved` (score ≈ 0.45) |

**To run the evaluation demo:**

```bash
# Step 1: Run the CWE-416 pipeline to create a bundle
insert-me run \
  --seed-file examples/seeds/cwe416_use_after_free.json \
  --source examples/demo/src

# Step 2: Evaluate the exact-match report against the bundle (replace <run-id>)
insert-me evaluate \
  --bundle output/<run-id>/ \
  --tool-report examples/evaluation/exact_match_report.json \
  --tool cppcheck-demo

# Step 3: Inspect results
cat output/<run-id>/match_result.json
cat output/<run-id>/coverage_result.json
```

**Expected result (exact match):**
- `match_result.json` — one match record with `match_level: "exact"`, `coverage_rate: 1.0`
- `coverage_result.json` — `matched: 1`, `unmatched: 0`, `false_positives: 0`, `coverage_rate: 1.0`

**Family match example:**
```bash
insert-me evaluate \
  --bundle output/<run-id>/ \
  --tool-report examples/evaluation/family_match_report.json \
  --tool cppcheck-demo
```
Result: `match_level: "family"` — CWE-415 (double-free) and CWE-416 (use-after-free) share the `use-after-free` family.

**Semantic match example (HeuristicAdjudicator):**
```bash
insert-me evaluate \
  --bundle output/<run-id>/ \
  --tool-report examples/evaluation/semantic_match_report.json \
  --tool cppcheck-demo
# --adjudicator heuristic is the default; omitting it is equivalent
```
Result: `match_level: "semantic"`, `adjudication.verdict: "match"` in `match_result.json`.
`adjudication_result.json` and `adjudication_summary` in `coverage_result.json` are written.

---

## Planned examples (future phases)

The following examples will be added as later pipeline stages are implemented:

| Example | Phase | Description |
|---|---|---|
| `custom_adapter/` | Phase 7B | Custom LLM adapter wiring example (labels.json enrichment) |
| `cwe476_sandbox_seeds/` | Phase 4c-remaining | CWE-476 sandbox seeds (requires handler enhancement for multi-line guards) |
| `cwe190_seeds/` | Phase 4c-remaining | CWE-190 integer overflow guard removal seeds |
