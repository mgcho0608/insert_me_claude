# Corpus Quality Gate — insert_me

> **Version:** 1.3  
> **Phase:** 16 -- workload characterization + support envelope  
> **Applies to:** Seeded cases generated from evaluation-only targets (sandbox, local, and portfolio)

This document defines the formal acceptance rubric for every case in the insert_me corpus.  
It governs whether a generated case is **ACCEPT**, **ACCEPT_WITH_NOTES**, **REVISE**, or **REJECT**.

The rubric is strict by design. Raw case count is never a goal. A smaller corpus of clean,
individually trustworthy cases is more valuable than a large corpus with ambiguous or
multi-flaw entries.

---

## 1. Classification Summary

| Class | Meaning | Action |
|---|---|---|
| **ACCEPT** | All criteria pass; no concerns | Add to accepted corpus |
| **ACCEPT_WITH_NOTES** | Criteria met but a minor concern is noted | Add with documented note; review periodically |
| **REVISE** | A fixable issue found (seed, seeder, or patcher fault) | Fix root cause; re-run seed; re-classify |
| **REJECT** | Unfixable or quality-disqualifying issue | Exclude from corpus; document reason |

---

## 2. Criteria

Each criterion lists:
- what is checked
- how it is verified (automated or human)
- the fail mode and its classification impact

---

### C1 — Single Primary Flaw

**What:** Exactly one vulnerability is introduced by the mutation. No secondary flaws
(double-free, use-after-free at a second site, memory leak introduced by the inserted
code itself) are present.

**Verification:** Automated + human  
- Automated: `audit_result.json → classification == "VALID"`  
  The Auditor checks that the mutation is structural and that the bad tree
  differs from the good tree in exactly the expected way.
- Human: Read the diff between `bad/` and `good/` trees. Confirm exactly one change
  is present and that the inserted code does not create an independent secondary flaw.

**Known failure modes and causes:**
| Mode | Cause | Fix |
|---|---|---|
| `free(ptr)` before `ptr->field = malloc(...)` — error path `if (!ptr->field) { free(ptr); }` becomes double-free | Sub-malloc target selected | `-0.35` penalty added to seeder for sub-malloc lines |
| `free(ptr)` inside `while (cur) { ... }` — free executes on every iteration | Loop-body target selected | `-0.40` penalty added to seeder for loop-body lines |
| `free(ptr)` before `if (!ptr) { ... }` null-check — double-free on error path | Conditional-guard target selected | `-0.30` penalty added to seeder for guard-expression lines |

**REJECT if:** diff shows more than one changed region, or the change introduces an
independent secondary vulnerability class.

---

### C2 — Bad/Good Pair Discipline

**What:** The `good/` tree is byte-identical to the original source. The `bad/` tree
differs from `good/` in exactly one location (one line replaced or one line inserted).
Both trees are syntactically well-formed C/C++.

**Verification:** Automated  
- `validation_result.json → checks[*].status == "pass"` for all 5 checks  
- `validation_result.json → overall == "pass"` (all 5 checks pass)

**REVISE if:** any validation check fails.  
**REJECT if:** bad and good trees are identical (no mutation applied, NOOP).

---

### C3 — Minimal Semantic Delta

**What:** The mutation is the smallest possible code change that produces the intended
vulnerability class. Exactly one expression or one statement is modified; nothing else
changes.

**Verification:** Automated  
- `ground_truth.json → mutations[0].original_fragment != mutations[0].mutated_fragment`  
- `mutation_type` is a known corpus-admitted strategy:  
  `alloc_size_undercount`, `insert_premature_free`, `insert_double_free`, `remove_free_call`  
  (or `remove_null_guard` if experimental seed is explicitly admitted)  
- For `alloc_size_undercount`: mutated fragment matches pattern `malloc((...) - 1)`  
- For `insert_premature_free`: mutated fragment is exactly `free(<ptr>);`  
- For `insert_double_free`: mutated fragment is exactly `free(<ptr>);` (duplicate before existing free)  
- For `remove_free_call`: mutated fragment is a `/* CWE-401: free(ptr) removed */` comment

**REJECT if:** original and mutated fragments are identical.  
**REVISE if:** mutation_type is unknown or fragment patterns do not match expectations.

---

### C4 — Explicit Vulnerable Intent

**What:** The vulnerability is documented in a machine-readable way. The seed file
declares the CWE class and strategy. The ground truth records the exact code change.

**Verification:** Automated  
- `ground_truth.json → cwe_id` is present and matches the seed's `cwe_id`  
- `ground_truth.json → mutations[0].mutation_type` matches the seed's `mutation_strategy`  
- `ground_truth.json → mutations[0].file` and `line` are non-empty

**REJECT if:** cwe_id is missing or does not match the seed.

---

### C5 — Oracle Completeness

**What:** `ground_truth.json` contains all fields required for detector evaluation.
A downstream evaluator must be able to determine file, line, CWE class, and fragment
change without examining the source tree.

**Verification:** Automated  
Required fields in `ground_truth.json`:
- `cwe_id`
- `spec_id`
- `seed`
- `mutations[0].file` — non-empty relative path
- `mutations[0].line` — positive integer
- `mutations[0].mutation_type` — known strategy
- `mutations[0].original_fragment` — non-empty
- `mutations[0].mutated_fragment` — non-empty
- `validation_passed` — boolean

**REVISE if:** any required field is missing or empty.

---

### C6 — Plausibility in Local Code Context

**What:** The insertion point occurs in realistic, allocating code — not in a test
function, dead code, or trivially unreachable path. The pointer or allocation variable
is actively used in the surrounding context. The mutation does not produce an obviously
nonsensical code pattern that no real code would exhibit.

**Verification:** Human  
Review the diff between `bad/` and `good/` trees. Verify:
1. The target function performs real allocation and field initialisation
2. The pointer variable appears before and after the insertion point
3. For `insert_premature_free`: the subsequent pointer dereferences are real uses
4. For `alloc_size_undercount`: a copy/write operation follows the malloc

**ACCEPT_WITH_NOTES if:** the code pattern is plausible but the function is extremely
simple (trivial scaffold with no realistic usage).  
**REVISE if:** the insertion point is inside a test or stub function.

---

### C7 — Evaluator Usefulness

**What:** The case produces well-defined match behavior for the exact/family/semantic
evaluation hierarchy. A static analysis tool can plausibly detect the inserted flaw.
The case contributes distinct signal relative to other cases in the corpus.

**Verification:** Human + automated  
- Automated duplicate check: no other case in the accepted corpus targets the same
  `file:line` pair.
- Human: confirm the case is semantically distinct from its nearest neighbors in the
  corpus (different function, different allocation variable, or different CWE sub-pattern).

**ACCEPT_WITH_NOTES if:** three or more accepted cases already target the same source
function (different lines, but same function body — reduced independent signal).  
**REJECT if:** exact duplicate (same file:line as an already-accepted case).

---

### C8 — Reproducibility / Auditability

**What:** Running the same seed file against the same source tree always produces the
same bundle. The `run_id` (a deterministic hash) is stable across runs. The
`source_hash` in `audit.json` matches the actual source tree content.

**Verification:** Automated — `scripts/check_reproducibility.py`  
The script runs each seed N times (default: 2) into separate temporary directories
and compares the following fields across runs:

| Artifact | Fields compared |
|---|---|
| `patch_plan.json` | `targets[*].{file, line, mutation_strategy, candidate_score}`, `source_hash` |
| `ground_truth.json` | `mutations[*].{file, line, mutation_type, original_fragment, mutated_fragment}` |
| `audit_result.json` | `classification`, `confidence` |
| `validation_result.json` | `verdict`, `checks[*].{name, passed}` |

Timestamps (`audited_at`) and monotonic counters are excluded from comparison.

**REJECT if:** any reproducibility check fails for this seed.  
**REVISE if:** the seed fails reproducibility due to a known, fixable seeder issue.

---

## 3. Automated vs. Human Checks

| Criterion | Automated | Human |
|---|---|---|
| C1 — Single Primary Flaw | Partial (audit classification) | Required (diff review) |
| C2 — Bad/Good Pair Discipline | Full | — |
| C3 — Minimal Semantic Delta | Full | — |
| C4 — Explicit Vulnerable Intent | Full | — |
| C5 — Oracle Completeness | Full | — |
| C6 — Plausibility in Local Context | — | Required |
| C7 — Evaluator Usefulness | Partial (duplicate check) | Required (distinctness) |
| C8 — Reproducibility | Full | — |

The `scripts/generate_corpus.py` tool runs all automated checks (C1–C5, C7 duplicate,
C8) and flags cases that require human review (C1 secondary flaw check, C6, C7
distinctness). Cases that fail no automated criteria but have unchecked human criteria
are classified as `ACCEPT_WITH_NOTES (human-review-pending)` until review is complete.

---

## 4. Thresholds for ACCEPT_WITH_NOTES

A case is classified **ACCEPT_WITH_NOTES** (not ACCEPT) when any of the following hold:

| Condition | Note recorded |
|---|---|
| `candidate_score < 0.70` | Lower-confidence seeder selection |
| `≥ 3` other accepted cases target the same source function | Reduced per-function signal diversity |
| C6 or C7 human check not yet completed | Human review pending |

ACCEPT_WITH_NOTES cases are valid corpus entries. They are tracked separately so that
quality trends can be monitored over time.

---

## 5. Summary Decision Tree

```
                    ┌─────────────────────────────────────────┐
                    │  Run pipeline; load artifacts            │
                    └────────────────┬────────────────────────┘
                                     │
              ┌──────────────────────▼───────────────────────────┐
              │  audit_result.classification == "VALID"?         │
              │  AND validation_result.verdict == "pass"?        │
              │  AND original_fragment != mutated_fragment?      │
              │  AND all oracle fields present?                  │
              └──────────────────────┬───────────────────────────┘
                          NO │                      │ YES
                             ▼                      ▼
              ┌──────────────────────┐   ┌──────────────────────────────┐
              │ classification==NOOP │   │  Duplicate file:line in      │
              │ or INVALID?          │   │  accepted corpus?            │
              └──────────┬───────────┘   └──────────────┬───────────────┘
                YES ─────┤ NO                      YES ──┤ NO
                         │                               │
                         ▼                               ▼
                      REJECT             ┌───────────────────────────────┐
                                         │  candidate_score < 0.70?      │
                         REVISE          │  OR ≥3 cases same function?   │
                (audit==AMBIGUOUS,       │  OR human checks pending?     │
                 validation fail)        └──────────────┬────────────────┘
                                               YES ─────┤ NO
                                                        │
                                                        ▼
                                              ACCEPT_WITH_NOTES
                                                        │ NO
                                                        ▼
                                                     ACCEPT
```

---

## 6. Corpus Health Targets

The following targets apply to the accepted sandbox corpus:

| Metric | Target |
|---|---|
| ACCEPT rate | ≥ 80% of generated cases |
| REJECT rate | ≤ 5% of generated cases |
| Unique target files | ≥ 4 distinct source files |
| Unique target functions | ≥ 12 distinct functions |
| Reproducibility pass rate | 100% |
| Duplicate rate | 0% |

If targets are not met, expand the sandbox source suite before generating more cases.
Do not lower quality thresholds to hit case count targets.

---

## 7. Planning Layer and the Quality Gate

The planning layer (`insert-me plan-corpus`, `insert-me generate-corpus`) is designed
to feed into — not bypass — the quality gate.

### How plan-corpus relates to the quality gate

`plan-corpus` does NOT accept cases; it synthesises candidate seed files.
Planned cases are **NOT** accepted corpus cases until they pass the quality gate.

The planning layer is honest about this:
- `corpus_plan.json` tracks `planned_count` and `projected_accepted_count` (estimated
  from historical strategy pass rates)
- `acceptance_summary.json` (from `generate-corpus`) tracks the actual
  `attempted_count`, `accepted_count`, `rejected_count`, and `error_count`
- The planning layer will not inflate the planned count to hit `requested_count`

### Acceptance summary format

`generate-corpus` writes `acceptance_summary.json` with these fields:

```json
{
  "schema_version": "1.0",
  "source_root": "/path/to/source",
  "requested_count": 30,
  "planned_count": 28,
  "projected_accepted_count": 25,
  "attempted_count": 28,
  "accepted_count": 24,
  "rejected_count": 4,
  "error_count": 0,
  "unresolved_count": 0,
  "honest": true,
  "shortfall_message": "Only 28 cases planned (requested 30)...",
  "strategy_allocation": { "alloc_size_undercount": 14, "insert_premature_free": 8, ... },
  "plan_path": "corpus_out/_plan/corpus_plan.json"
}
```

The `honest` field is `true` when `planned_count < requested_count` — i.e., the system
acknowledged it could not honestly reach the requested count.

### Quality gate integration for planned cases

Each case synthesised by `plan-corpus` has its own seed file under `_plan/seeds/`.
When `generate-corpus` executes, each case goes through:

1. **Seeder** — selects the same target (deterministic seed integer)
2. **Patcher** — applies the mutation
3. **Validator** — five rule-based plausibility checks
4. **Auditor** — classifies as VALID / NOOP / AMBIGUOUS / INVALID
5. **Quality gate** — ACCEPT / ACCEPT_WITH_NOTES / REVISE / REJECT

Cases classified NOOP or INVALID are counted as `rejected_count`.
The quality gate criteria in sections 2–4 apply without exception.

### What the planning layer cannot guarantee

The planning layer uses historical pass-rate priors (`_STRATEGY_PASS_RATE`) to project
accepted counts. These priors are based on the bundled sandbox targets. For a novel
local target, actual accepted counts may differ. Always review `acceptance_summary.json`
after `generate-corpus` to confirm actual yield.

If `accepted_count` is significantly below `projected_accepted_count`, investigate:
- Concentration: are cases clustering in one file or function?
- Pattern quality: are the selected sites in low-scoring regions?
- Run `insert-me inspect-target` and review `concentration_risk` signals
