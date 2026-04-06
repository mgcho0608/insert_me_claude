# Examples — insert_me

---

## Current phase (Phase 7A — Juliet identity + per-project evaluation foundation)

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
| `cwe122_heap_overflow.json` | CWE-122 Heap Buffer Overflow | `malloc_call` | `alloc_size_undercount` | implemented |
| `cwe416_use_after_free.json` | CWE-416 Use After Free | `pointer_deref` | `insert_premature_free` | implemented |
| `cwe190_integer_overflow.json` | CWE-190 Integer Overflow | `integer_arithmetic` | `integer_size_overflow` | not yet implemented |

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

| File | Description | Expected match level |
|---|---|---|
| `exact_match_report.json` | Finding in `uaf_demo.c` at correct line with CWE-416 | `exact` |
| `family_match_report.json` | Finding in `uaf_demo.c` with CWE-415 (double-free, same family) | `family` |
| `no_match_report.json` | Finding in `other.c` with CWE-122 (different file and CWE) | `no_match` |

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

---

## Planned examples (future phases)

The following examples will be added as later pipeline stages are implemented:

| Example | Phase | Description |
|---|---|---|
| `basic_cwe122/` | Phase 8 | Additional CWE seeds exercising new strategies |
| `no_llm/` | Phase 7B | Full run with `--no-llm`, confirming offline operation |
| `custom_adapter/` | Phase 7B | Custom LLM adapter wiring example |
| `multi_target/` | Phase 4b | Larger source tree, multiple ranked candidates |
