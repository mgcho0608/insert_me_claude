# Examples — insert_me

---

## Current phase (Phase 5 — Validator complete)

The Seeder, Patcher, and Validator are implemented. You can run the pipeline today and get
**real bad/good source trees** with one inserted vulnerability (`alloc_size_undercount`
strategy: `malloc(<expr>)` → `malloc((<expr>) - 1)`) plus a real `validation_result.json`
from five rule-based plausibility checks.

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

## `seeds/` — canonical seed files

| File | CWE | Pattern type | Difficulty |
|---|---|---|---|
| `cwe122_heap_overflow.json` | CWE-122 Heap Buffer Overflow | `malloc_call` | easy |
| `cwe416_use_after_free.json` | CWE-416 Use After Free | `free_call` | medium |
| `cwe190_integer_overflow.json` | CWE-190 Integer Overflow | `integer_arithmetic` | hard |

These seed files are valid inputs to `insert-me run --seed-file`.

---

## `expected_outputs/` — reference artifacts for schema testing

Reference JSON artifacts used in the schema test suite
(`tests/test_schemas.py`).  These are not output from a real run — they are
hand-crafted examples that exercise the schema validators.

---

## Planned examples (future phases)

The following examples will be added as later pipeline stages are implemented:

| Example | Phase | Description |
|---|---|---|
| `basic_cwe122/` | Phase 6 | End-to-end: seed → real mutation → bad/good pair |
| `no_llm/` | Phase 6 | Full run with `--no-llm`, confirming offline operation |
| `custom_adapter/` | Phase 7 | Custom LLM adapter wiring example |
| `multi_target/` | Phase 6 | Larger source tree, multiple ranked candidates |
