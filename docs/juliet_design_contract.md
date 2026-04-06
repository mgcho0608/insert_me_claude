# Juliet Design Contract — insert_me

> "insert_me is a deterministic, Juliet-derived seeded vulnerability insertion and per-project evaluation framework for C/C++ codebases. It inserts auditable bad/good variants into arbitrary target projects and evaluates how well a detector report matches the inserted ground truth, optionally using an LLM for semantic adjudication."

---

## 1. Purpose

The Juliet Test Suite (NIST/MITRE) established a widely-used benchmark methodology for vulnerability detectors: for each CWE, it provides pairs of `bad` (vulnerable) and `good` (safe) code variants, each with exactly one deliberate flaw, documented in a structured way so that detector results can be evaluated against a known oracle.

`insert_me` adapts those principles to a different context: instead of generating standalone synthetic test cases, it **inserts vulnerabilities into real project source trees**. The Juliet design contract governs how insert_me mutations are defined and constrained to preserve the key properties that make Juliet-style evaluation meaningful:

- Every mutation has a single, documented, deliberate flaw
- The flaw site is explicitly recorded in a machine-readable oracle
- Safe and vulnerable variants are byte-comparable
- Results are fully reproducible given a seed

Without these invariants, a detector's results cannot be meaningfully interpreted against the oracle — a "no match" could mean the tool missed the bug, or that the bug was not actually inserted cleanly.

---

## 2. Core Juliet Principles

### 2.1 Single Primary Flaw

Each inserted variant has exactly one vulnerability. The mutation applies a minimal, targeted change at one location in one file. There is no incidental introduction of secondary flaws, no cascading changes, and no interaction with other mutation sites.

**Rationale:** A detector report cannot be evaluated against an oracle that has multiple simultaneous flaws, because it becomes impossible to attribute a finding to a specific known defect.

### 2.2 Bad/Good Pair Discipline

Every run produces two source trees:

- `bad/` — the mutated (vulnerable) version
- `good/` — byte-identical to the original, unmodified source

The `good/` tree is a byte-exact copy of the original source before mutation. The only difference between `bad/` and `good/` is the single mutation at the recorded site. No other files differ.

This mirrors Juliet's `bad()` / `good()` function pair structure, adapted for whole-project mutation.

### 2.3 Minimal Semantic Delta

The mutation changes only the minimum code necessary to introduce the intended vulnerability. Examples:

- `alloc_size_undercount`: one sub-expression in one malloc size argument is modified (`n` → `n - 1`)
- `insert_premature_free`: one line is inserted immediately before a dereference site

No surrounding logic is modified. No variable renames. No refactoring. The semantic delta is as small as possible while still producing a real, exploitable instance of the target CWE.

### 2.4 Explicit Vulnerable Intent

The vulnerability is always deliberate and documented. The mutation strategy is declared in the seed file. The CWE class is recorded in both the seed and the ground truth oracle. The exact code change is captured in `ground_truth.json` as `original_fragment` and `mutated_fragment`.

There is no "accidental" vulnerability production. Every mutation is traceable from seed → strategy → site → fragment → CWE.

### 2.5 Oracle Completeness

`ground_truth.json` records exactly what was inserted. For each mutation it captures:

| Field | What it records |
|---|---|
| `file` | Relative path of the mutated file |
| `line` | 1-based line number of the insertion point |
| `mutation_type` | Strategy identifier |
| `original_fragment` | Source text before mutation |
| `mutated_fragment` | Source text after mutation (the vulnerability) |
| `extra` | Strategy-specific metadata (e.g. `freed_pointer` for CWE-416) |

The oracle is complete: no information required to evaluate a detector result is missing from `ground_truth.json`. A downstream tool (evaluator, checker, reviewer) never needs to re-examine source code to know what was inserted.

### 2.6 Reproducibility / Auditability

Given the same seed file and the same source tree, `insert_me` always produces the same output, byte-for-byte. The run ID is a deterministic hash of the seed data, source tree path, and pipeline version. All provenance is captured in `audit.json`.

This means:

- Results can be reproduced independently to verify findings
- The same ground truth can be re-generated after a pipeline upgrade
- Evaluations can be replayed without re-running the full pipeline

---

## 3. Principle-to-Strategy Mapping

| Principle | alloc_size_undercount | insert_premature_free |
|---|---|---|
| Single Primary Flaw | One undersized malloc call | One premature free inserted |
| Bad/Good Pair | bad/ has one modified expression; good/ is byte-identical | bad/ has one extra free() line; good/ is byte-identical |
| Minimal Delta | One sub-expression modified (`n` → `n - 1`) | One line inserted (`free(ptr);`) |
| Explicit Intent | CWE-122 documented in seed and ground_truth | CWE-416 documented in seed and ground_truth |
| Oracle Complete | file/line/original_fragment/mutated_fragment recorded | file/line/freed_pointer in extra recorded |
| Reproducible | Deterministic seed selects malloc site | Deterministic seed selects dereference site |

---

## 4. Adaptation from Juliet Synthetic Cases to Project-Scale Insertion

The original Juliet Test Suite generates **standalone synthetic test cases**: each testcase is a self-contained C file with `bad()` and `good()` functions that isolate exactly one vulnerability pattern, wrapped in a harness that exercises both paths. These files are purpose-built with no real project context.

`insert_me` instead inserts a flaw into an **existing project function**, preserving real code context. The mutation site is a real production code pattern — a real malloc call, a real pointer dereference — not a synthetic harness.

The ground truth oracle (`ground_truth.json`) plays the same structural role as Juliet's `bad`/`good` function pair: it defines exactly where the vulnerability is and what it looks like. But the host code is a real project, not a synthetic scaffold.

This has two important consequences:

1. **Realism:** The vulnerability is embedded in realistic surrounding code. Detectors that rely on interprocedural analysis, data flow, or project-level context encounter the flaw in a realistic setting, not a stripped-down test harness.

2. **Evaluation difficulty:** A detector must locate the flaw within a real project, where false positives from legitimate code patterns are possible. The ground truth oracle (and the evaluator) distinguish between findings that correspond to the inserted flaw and findings that do not.

The Juliet principle — one documented flaw, a safe comparison variant, a complete oracle — is preserved. The substrate changes from synthetic to real.

---

## 5. Evaluation Oracle

`ground_truth.json` serves as the oracle for the `insert-me evaluate` command.

The evaluator compares each entry in `ground_truth.mutations` against the findings in a normalized detector report (`detector_report.schema.json`). For each mutation, it assigns a match level:

| Level | Condition |
|---|---|
| `exact` | Same file (basename), same CWE ID, finding line within ±2 of mutation line |
| `family` | Mutation CWE and finding CWE belong to the same CWE family group |
| `semantic` | Keyword from the mutation's CWE family found in the finding message |
| `no_match` | None of the above |

The oracle guarantees that the evaluator knows exactly what to look for:

- **File:** `ground_truth.mutations[i].file` — where to find the vulnerability
- **Line:** `ground_truth.mutations[i].line` — where in the file
- **CWE:** `ground_truth.cwe_id` — what class of vulnerability was inserted

These three fields together constitute the minimum evidence needed to evaluate whether a detector found the inserted flaw. The `exact` match level requires all three to align; lower levels relax the criteria in a principled way when the detector reports a related but not identical finding.

When LLM adjudication is enabled (Phase 7B), semantic matches are resolved by the LLM using the full finding context. When disabled, semantic matches are flagged with `adjudication_pending=True` and left unresolved — this does not fail the evaluation.

Summary statistics are written to `coverage_result.json`, which records `coverage_rate` (matched / total_mutations), per-level counts, and false positive count (findings not linked to any inserted mutation).
