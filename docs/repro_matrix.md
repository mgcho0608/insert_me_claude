# Reproducibility Matrix

> **Updated:** 2026-04-07 (Phase 13 — added fresh-plan repro section)
> **Seed-level check tool:** `scripts/check_reproducibility.py --runs 3`  
> **Plan-level check tool:** `scripts/check_plan_stability.py --runs 3`  
> **Scope:** Seed-level (all sandbox seeds) + Plan-level (local-target and sandbox fixtures)

This document records two classes of reproducibility check:

1. **Seed-level** — each seed file run N times; deterministic artifact fields must be identical.
2. **Fresh-plan** — `plan-corpus` run N times on the same source + count; `corpus_plan.json` must be byte-identical.

---

## Verified Fields

The following fields are compared across runs (from `ground_truth.json` and `audit_result.json`):

| Field | Source artifact |
|---|---|
| `target.file` | `ground_truth.json` |
| `target.line` | `ground_truth.json` |
| `mutation_type` | `ground_truth.json` |
| `original_fragment` | `ground_truth.json` |
| `mutated_fragment` | `ground_truth.json` |
| `classification` | `audit_result.json` |

---

## Matrix: sandbox_eval (40 seeds)

**Source root:** `examples/sandbox_eval/src`  
**Seeds directory:** `examples/seeds/sandbox`  
**Run date:** 2026-04-06  
**Runs:** 3  

| Seed | Strategy | CWE | Result |
|---|---|---|---|
| cwe122_sb_001 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_002 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_003 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_004 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_005 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_006 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_007 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_008 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_009 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_010 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_sb_011 | alloc_size_undercount | CWE-122 | PASS |
| cwe401_sb_001 | remove_free_call | CWE-401 | PASS |
| cwe401_sb_002 | remove_free_call | CWE-401 | PASS |
| cwe401_sb_003 | remove_free_call | CWE-401 | PASS |
| cwe401_sb_004 | remove_free_call | CWE-401 | PASS |
| cwe401_sb_005 | remove_free_call | CWE-401 | PASS |
| cwe415_sb_001 | insert_double_free | CWE-415 | PASS |
| cwe415_sb_002 | insert_double_free | CWE-415 | PASS |
| cwe415_sb_003 | insert_double_free | CWE-415 | PASS |
| cwe415_sb_004 | insert_double_free | CWE-415 | PASS |
| cwe415_sb_005 | insert_double_free | CWE-415 | PASS |
| cwe416_sb_001 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_002 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_003 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_004 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_005 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_006 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_007 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_008 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_009 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_010 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_011 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_012 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_013 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_014 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_015 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_016 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_017 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_018 | insert_premature_free | CWE-416 | PASS |
| cwe416_sb_019 | insert_premature_free | CWE-416 | PASS |

**Summary: 40 / 40 PASS**

---

## Matrix: target_b (15 seeds)

**Source root:** `examples/sandbox_targets/target_b/src`  
**Seeds directory:** `examples/seeds/target_b`  
**Run date:** 2026-04-06  
**Runs:** 3  

| Seed | Strategy | CWE | Result |
|---|---|---|---|
| cwe122_tb_001 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_tb_002 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_tb_003 | alloc_size_undercount | CWE-122 | PASS |
| cwe122_tb_004 | alloc_size_undercount | CWE-122 | PASS |
| cwe401_tb_001 | remove_free_call | CWE-401 | PASS |
| cwe401_tb_002 | remove_free_call | CWE-401 | PASS |
| cwe401_tb_003 | remove_free_call | CWE-401 | PASS |
| cwe415_tb_001 | insert_double_free | CWE-415 | PASS |
| cwe415_tb_002 | insert_double_free | CWE-415 | PASS |
| cwe415_tb_003 | insert_double_free | CWE-415 | PASS |
| cwe416_tb_001 | insert_premature_free | CWE-416 | PASS |
| cwe416_tb_002 | insert_premature_free | CWE-416 | PASS |
| cwe416_tb_003 | insert_premature_free | CWE-416 | PASS |
| cwe416_tb_004 | insert_premature_free | CWE-416 | PASS |
| cwe416_tb_005 | insert_premature_free | CWE-416 | PASS |

**Summary: 15 / 15 PASS**

---

## Combined Totals

| Target | Seeds | PASS | FAIL | Pass Rate |
|---|---|---|---|---|
| sandbox_eval | 40 | 40 | 0 | 100% |
| target_b | 15 | 15 | 0 | 100% |
| **Total** | **55** | **55** | **0** | **100%** |

All 55 seed/target combinations reproduce identically across 3 independent runs.

---

## Fresh-Plan Reproducibility Matrix (Phase 13)

> **Tool:** `scripts/check_plan_stability.py --runs 3`
> **Scope:** `plan-corpus` run 3 times on each target; `corpus_plan.json` compared byte-for-byte.

| Target | Class | Count | Runs | Verdict | Shared fingerprint |
|---|---|---|---|---|---|
| `examples/sandbox_eval/src` | Bundled | 20 | 3 | **STABLE** | all identical |
| `examples/local_targets/moderate/src` | Local pilot | 5 | 3 | **STABLE** | all identical |
| `examples/local_targets/minimal/src` | Local pilot | 5 | 3 | **STABLE** | all identical |

All fresh-plan runs on the above targets produce byte-identical `corpus_plan.json` files.
Fresh-plan stability is continuously verified by `TestFreshPlanReproducibility` (5 tests in
`tests/test_reproducibility.py`).

### How to run fresh-plan stability check

```bash
# Quick check (2 runs, moderate fixture)
python scripts/check_plan_stability.py \
    --source examples/local_targets/moderate/src \
    --count 5

# Full check with report (3 runs, sandbox_eval)
python scripts/check_plan_stability.py \
    --source examples/sandbox_eval/src \
    --count 20 \
    --runs 3 \
    --output plan_repro_report.json
```

---

## Seed-Level Reproducibility Matrix

> **Tool:** `scripts/check_reproducibility.py --runs 3`
> **Scope:** All seed files across both sandbox targets

---

## How to Regenerate (Seed-Level)

```bash
# sandbox_eval
python scripts/check_reproducibility.py \
    --seeds-dir examples/seeds/sandbox \
    --source-root examples/sandbox_eval/src \
    --runs 3 --no-color

# target_b
python scripts/check_reproducibility.py \
    --seeds-dir examples/seeds/target_b \
    --source-root examples/sandbox_targets/target_b/src \
    --runs 3 --no-color
```
