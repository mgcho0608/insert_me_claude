# insert_me

**Target-aware, count-driven seeded vulnerability corpus generation for C/C++.**

> **Repository:** `insert_me_claude` is the public incubation repository for the `insert_me`
> package. The package name, CLI command (`insert-me`), and all artifact identities are
> `insert_me` throughout. The `_claude` suffix in the repository name reflects its origin as
> a Claude-assisted build and carries no meaning for end users or downstream integrators.
> When this project moves to a production home, the `insert_me` package identity is what carries forward.

---

## Current Status — Phase 15 (multi-target portfolio orchestration + truth closure)

| | |
|---|---|
| **Phase** | 15 — multi-target portfolio orchestration + canonical interface truth sync |
| **Tests** | 688 passing, 1 skipped |
| **Corpus-admitted strategies** | 6 (CWE-122/416/415/401/476/190) |
| **Sandbox seeds** | 76 accepted (56 sandbox_eval + 20 target_b) — 100% reproducible |
| **Mutation strategies** | `alloc_size_undercount` (CWE-122) · `insert_premature_free` (CWE-416) · `insert_double_free` (CWE-415) · `remove_free_call` (CWE-401) · `remove_null_guard` (CWE-476) · `remove_size_cast` (CWE-190) |
| **Default mode** | Real patching + validation + audit |
| **Dry-run mode** | `--dry-run` flag — all artifacts emitted, no source modifications |
| **Artifacts emitted** | All 5 core artifacts, schema-validated on every run |
| **`patch_plan.json` status** | `APPLIED` (mutation applied) · `PLANNED` (dry-run/no compatible target) · `PENDING` (no C/C++ sources found) |
| **`audit_result.json`** | `VALID` (validator pass) · `INVALID` (fail) · `AMBIGUOUS` (skip+mutations) · `NOOP` (no mutations) |
| **Evaluation strategy** | `exact` / `family` / `semantic` / `no_match` — per-mutation match against inserted ground truth |
| **Adjudicator** | `HeuristicAdjudicator` (default, offline) · `DisabledAdjudicator` · `LLMAdjudicator` (Phase 7B placeholder) |

---

## What it is

insert_me is a deterministic, Juliet-derived seeded vulnerability insertion and
per-project evaluation framework for C/C++ codebases.

**What insert_me actually does:**

Given a local evaluation-only C/C++ target project and a requested count (e.g. 30):

1. **Inspects the target** — enumerates candidate sites for each supported vulnerability
   strategy (CWE family); classifies each strategy as VIABLE / LIMITED / BLOCKED for that
   specific target; reports concentration risk and projected yield.

2. **Plans a corpus** — deterministically allocates the requested count across strategies
   and files, respecting diversity constraints; synthesises concrete seed files; honestly
   reports when the requested count is not achievable.

3. **Generates and evaluates cases** — runs each planned case through the full pipeline
   (Seeder → Patcher → Validator → Auditor → quality gate); produces accepted/rejected
   summaries.

4. **Orchestrates across multiple targets** — distributes a global count across a list of
   C/C++ source trees, applies global diversity constraints, and produces a unified portfolio
   plan with per-target sub-plans and portfolio-level diagnostics.

Each executed case produces:

- **Bad/good source pairs** — the original (good) and the mutated (bad) version.
- **Patch plan** — planned transformations before source files are modified.
- **Validation artifacts** — five rule-based plausibility checks.
- **Audit result** — VALID / NOOP / AMBIGUOUS / INVALID classification.
- **Ground-truth records** — machine-readable annotations of what was inserted and where.

The primary use case is generating labelled corpora for vulnerability research, detector
benchmarking, and security tooling evaluation — without relying on manual seed authoring,
LLMs, compilers, or real CVEs.

---

## What it is NOT

| Not this | Why |
|---|---|
| A fuzzer | `insert_me` is deterministic and structured, not random |
| A vulnerability scanner | It generates; it does not detect |
| `check_me` | `check_me` is a separate checker/verifier tool |
| `bench_me` | `bench_me` is a separate benchmarking harness |
| A cloud service | No mandatory external calls; runs fully offline |
| An LLM wrapper | LLM use is a narrow, optional, replaceable layer |

---

## Internal Reuse — Quick Reference

For engineers picking this up for the first time inside an organisation:

| | |
|---|---|
| **What it is** | A Python CLI that inserts known vulnerabilities into C/C++ source trees and produces fully annotated, schema-validated output bundles — single-case, single-target batch, or multi-target portfolio. |
| **Current maturity** | Phase 15 — multi-target portfolio orchestration. Full pipeline: 6 corpus-admitted mutation strategies (CWE-122/416/415/401/476/190), planning layer (TargetInspector/SeedSynthesizer/CorpusPlanner/PortfolioPlanner), all CLI subcommands incl. `plan-portfolio` + `generate-portfolio`, 15-entry strategy catalog (6 admitted / 1 planned / 8 candidate), 2 sandbox targets + local-target fixtures, portfolio artifacts (portfolio_plan.json, portfolio_index.json), 688 tests. Not production-hardened; alpha-quality. |
| **Install path** | `pip install -e .` from source. No PyPI release exists yet. |
| **Python versions** | 3.11, 3.12 — **CI-tested**. 3.10 — **statically reviewed only** (single shim: `tomllib` → `tomli`). No other version-specific features used. |
| **Dependencies** | `jsonschema>=4.17` + `tomli>=1.2.0` on Python 3.10 only. No other mandatory runtime dependencies. |
| **Network access** | None required for core operation. All schema validation ships with the package. |
| **License** | **Undecided.** See `NOTICE.txt`. Internal/research use only. Do not redistribute without explicit permission. |
| **First command** | `pip install -e . && insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json --source examples/demo/src` |

**What to expect from a run today:**
- One mutation applied to the source tree: any of the 6 corpus-admitted strategies (`alloc_size_undercount` CWE-122, `insert_premature_free` CWE-416, `insert_double_free` CWE-415, `remove_free_call` CWE-401, `remove_null_guard` CWE-476, `remove_size_cast` CWE-190)
- Five deterministic rule-based plausibility checks
- Five JSON artifacts: `patch_plan.json`, `validation_result.json`, `audit_result.json`, `ground_truth.json`, `audit.json`

**What is NOT available yet:**
- Additional mutation strategies (CWE-787 Out-of-bounds Write) — planned; single remaining PLANNED entry in strategy catalog
- AST-based or compiler-backed patching/validation — future phases
- Phase 7B: real LLM adjudicator (placeholder exists; `LLMAdjudicator.adjudicate()` raises `NotImplementedError`)

---

## Core Goals

1. **Reproducibility** — The same seed file + source tree always produces the same output, byte-for-byte.
2. **Auditability** — Every output carries a complete provenance record.
3. **Portability** — Runs in air-gapped / restricted enterprise environments with zero cloud calls.
4. **Composability** — Outputs integrate cleanly with downstream tools (checkers, benchmarks, CI).
5. **LLM-agnosticism** — Any LLM-assisted step can be replaced by a weaker internal model or
   disabled entirely without breaking the core pipeline.

---

## Canonical Interface

Three usage patterns are supported, in order of increasing scope:

### Pattern 1 — Single-case seeded experiment (expert / manual)

For one-off experiments with a hand-authored seed file. Lowest overhead; full control.

```bash
# Run one seed against a source tree
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project

# Batch: every .json seed file in a directory
insert-me batch --seed-dir examples/seeds/sandbox \
                --source /path/to/c-project

# Validate a completed output bundle
insert-me validate-bundle output/<run-id>/

# Pretty-print an audit record
insert-me audit output/<run-id>/audit.json

# Evaluate a detector report against the inserted ground truth
insert-me evaluate --bundle output/<run-id>/ \
                   --tool-report report.json \
                   --tool cppcheck \
                   [--adjudicator heuristic|disabled]
```

### Pattern 2 — Single-target target-aware corpus generation (recommended for one target)

Inspect a source tree, plan a corpus toward a count, and execute it. Honest shortfall
reporting if the target cannot supply the requested count.

```bash
# Preflight: suitability check before planning
insert-me inspect-target --source /path/to/c-project

# Plan only (no execution) — produces corpus_plan.json + seeds/
insert-me plan-corpus --source /path/to/c-project --count 30 --output-dir corpus_plan/

# Plan + execute — full pipeline for each planned case
insert-me generate-corpus --source /path/to/c-project --count 30 --output-root corpus_out/

# Replay a saved plan without re-planning
insert-me generate-corpus --from-plan corpus_out/_plan/ --output-root corpus_out_replay/
```

### Pattern 3 — Multi-target portfolio generation (recommended for multiple targets)

Allocate a global count across multiple source trees, apply global diversity constraints,
and produce a unified portfolio with per-target sub-plans and portfolio-level diagnostics.

```bash
# Plan only — produces portfolio_plan.json + per-target sub-plans
insert-me plan-portfolio --targets-file examples/targets/sandbox_targets.json \
                         --count 30 --output-dir portfolio_plan/

# Plan + execute — full pipeline across all targets
insert-me generate-portfolio --targets-file examples/targets/sandbox_targets.json \
                              --count 30 --output-root portfolio_out/

# Replay a saved portfolio plan without re-planning
insert-me generate-portfolio --from-plan portfolio_out/_plan/portfolio_plan.json \
                              --output-root portfolio_replay/
```

### Legacy interface (backward-compatible)

```bash
insert-me run --seed 42 --spec specs/cwe-122.toml --source /path/to/project
```

The `--seed INT --spec PATH` form is kept for backward compatibility. For new runs,
prefer `--seed-file PATH`. The two forms are mutually exclusive.

---

## When to use which pattern

| Use case | Recommended pattern |
|---|---|
| One-off / manual experiment with known seed | Pattern 1 (`run --seed-file`) |
| Batch against existing hand-authored seeds | Pattern 1 (`batch --seed-dir`) |
| Count-driven corpus for one target | Pattern 2 (`generate-corpus`) |
| Reproducible replay of a single-target corpus | Pattern 2 (`generate-corpus --from-plan`) |
| Multi-target corpus with global count | Pattern 3 (`generate-portfolio`) |
| Reproducible replay of a portfolio | Pattern 3 (`generate-portfolio --from-plan`) |
| Checking target suitability before committing | Pattern 2/3 (`inspect-target`) |

---

## Seed Files

Seed files are JSON documents conforming to `seed.schema.json`. They define:
- The vulnerability class (CWE ID)
- The integer seed for deterministic target selection
- The mutation strategy
- Pattern constraints for target selection in the source tree

Example seed files are in `examples/seeds/`:

| File | CWE | Difficulty |
|---|---|---|
| `cwe122_heap_overflow.json` | CWE-122 Heap Buffer Overflow | easy |
| `cwe416_use_after_free.json` | CWE-416 Use After Free | medium |
| `cwe190_integer_overflow.json` | CWE-190 Integer Overflow | hard |

---

## Pipeline Workflow

```
[seed.json]          <- seed.schema.json (canonical input)
       |
       v
  +-------------+
  |   Seeder    |  Implemented -- lexical source scan -> ranked PatchTargetList
  +------+------+
         |  patch_plan.json  <- patch_plan.schema.json
         v
  +-------------+
  |   Patcher   |  Phase 14 -- 6 corpus-admitted strategies:
  +------+------+    alloc_size_undercount (CWE-122)
         |           insert_premature_free (CWE-416)
         |           insert_double_free    (CWE-415)
         |           remove_free_call      (CWE-401)
         |           remove_null_guard     (CWE-476)
         |           remove_size_cast      (CWE-190)
         v
  +-----------------+
  |    Validator    |  Phase 5 -- five deterministic rule-based checks
  +------+----------+
         |  validation_result.json  <- validation_result.schema.json
         v
  +-------------+
  |   Auditor   |  Phase 6 -- ground truth, provenance, classification
  +------+------+
         |  audit_result.json  ground_truth.json  audit.json
         v
  [output bundle]
    bad/  good/  + all JSON artifacts above
         |
         |  (optional, separate step)
         v
  +-------------+
  |  Evaluator  |  Phase 7A -- match detector report against ground truth
  +------+------+    (insert-me evaluate --bundle ... --tool-report ...)
         |  match_result.json  coverage_result.json
         v
  +-------------------+
  |  Adjudicator      |  Phase 7B-prep -- resolves semantic matches offline
  +------+------------+    HeuristicAdjudicator (default) / DisabledAdjudicator
         |  adjudication_result.json
         v
  [evaluation artifacts]
```

An optional LLM adapter may be invoked after the Auditor for label enrichment (`labels.json`, Phase 7B).
The adjudicator boundary is hardened: `AdjudicatorBase` ABC accepts `HeuristicAdjudicator` (offline
default), `DisabledAdjudicator`, or a future `LLMAdjudicator`. These are side-channels — they do not
modify any deterministic artifact.

---

## Seeder: Supported Pattern Types

The Seeder uses lexical/regex heuristics (no external AST parser) to extract ranked patch
candidates from C/C++ source files. Each seed file specifies a `pattern_type`; the Seeder
scores candidates with strategy-specific rules (base score 0.4, capped at 1.0).

| `pattern_type` | Detected constructs | Notes |
|---|---|---|
| `malloc_call` | `malloc(...)` | Higher score for arithmetic in size arg |
| `calloc_call` | `calloc(...)` | Two-argument alloc |
| `realloc_call` | `realloc(...)` | Reallocation patterns |
| `free_call` | `free(...)` | Double-free / use-after-free sites |
| `string_operation` | `strcpy`, `strncpy`, `strcat`, `strncat`, `sprintf`, `gets`, `scanf`, `memcpy`, `memmove`, `read`, `recv`, `recvfrom` | Scored by danger level: `gets` > `read`/`recv` > `memcpy`/`strcpy` > others |
| `format_string` | `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsprintf` | Extra score for bare variable as format arg |
| `integer_arithmetic` | `x * sizeof(...)` patterns | Integer overflow in size calculations |
| `array_index` | `arr[...]` subscript access | Extra score for arithmetic in subscript |
| `loop_bound` | `for (...)` headers | Extra score for `<=` condition (off-by-one) |
| `pointer_deref` | `*ptr`, `ptr->field` | Arrow operator scores higher |
| `null_guard` | `if (!ptr) return;`, `if (ptr == NULL) ...` | CWE-476 guard-removal pattern; +0.40 for single-line return guard |
| `malloc_size_cast` | `malloc((size_t)EXPR * sizeof(T))` | CWE-190 cast-removal pattern; +0.35 score boost |
| `custom` | Union of all dangerous patterns | Fallback for novel CWEs |

Deterministic ordering: score descending → (file, line) ascending → seed-integer shuffle
within equal-score tiers, so different seeds explore different candidates first.

---

## Validator: Plausibility Checks

After applying a mutation, the Validator runs five deterministic, compiler-free checks:

| Check | Passes when |
|---|---|
| `mutation_applied` | At least one mutation record was produced by the Patcher |
| `good_tree_integrity` | `good/` copy of the mutated file is byte-identical to the original source |
| `bad_tree_changed` | `bad/` file differs from `good/` and contains the expected `mutated_fragment` |
| `mutation_scope` | Exactly one file differs between `bad/` and `good/` |
| `simple_syntax_sanity` | The mutated line has balanced parentheses; the file is non-empty |

In dry-run mode, validation is skipped (`overall: "SKIP"`, `checks: []`).

The Validator verdict drives the `audit_result.json` classification:
`VALID` (all pass) · `INVALID` (any fail) · `AMBIGUOUS` (skip with mutations) · `NOOP` (no mutations).

---

## Output Bundle Layout

For each run, `insert_me` produces an **output bundle** under `output/<run-id>/`:

```
output/
+-- <run-id>/
    +-- bad/                      Mutated source tree (vulnerability inserted)
    +-- good/                     Original source tree (clean copy)
    +-- patch_plan.json           Planned transformations (schema: patch_plan)
    +-- validation_result.json    Plausibility verdict (schema: validation_result)
    +-- audit_result.json         Classification (schema: audit_result)
    +-- ground_truth.json         Mutation annotation (schema: vuln_spec)
    +-- audit.json                Provenance record (schema: audit_record)
    +-- labels.json               (optional) LLM-enriched semantic labels
```

For **corpus generation** (`generate-corpus`), additional artifacts are written to the output root:

```
corpus_out/
+-- _plan/
|   +-- corpus_plan.json          Plan allocation and per-case details
|   +-- seeds/                    Synthesised seed files (one per planned case)
+-- cases/                        Per-case output bundles (one subdirectory per case)
+-- corpus_index.json             Corpus manifest with fingerprints
+-- acceptance_summary.json       Requested/planned/accepted/rejected counts
+-- shortfall_report.json         Plan + execution shortfall attribution
+-- generation_diagnostics.json   Per-category failure attribution
```

For **portfolio generation** (`generate-portfolio`), portfolio-level artifacts wrap the per-target view:

```
portfolio_out/
+-- portfolio_plan.json                  Global allocation plan (schema: portfolio_plan)
+-- portfolio_index.json                 Portfolio manifest + fingerprints (schema: portfolio_index)
+-- portfolio_acceptance_summary.json    Global requested/planned/accepted (schema: portfolio_acceptance_summary)
+-- portfolio_shortfall_report.json      Global shortfall attribution (schema: portfolio_shortfall_report)
+-- _plan/
|   +-- portfolio_plan.json              Plan used for replay
|   +-- targets/
|       +-- <name>/_plan/corpus_plan.json + seeds/
+-- targets/
    +-- <name>/
        +-- corpus_index.json            Per-target corpus manifest
        +-- acceptance_summary.json      Per-target acceptance counts
        +-- shortfall_report.json        Per-target shortfall
        +-- cases/                       Per-target case bundles
```

All schemas are bundled and versioned. No network access needed for validation.
Run `insert-me validate-bundle output/<run-id>/` to verify any single-case bundle.

---

## Artifact Schemas

All inputs and outputs are defined by versioned JSON schemas in `schemas/`.
See `docs/artifact_contracts.md` for the full specification.

| Schema file | Artifact | Stage |
|---|---|---|
| `seed.schema.json` | Seed definition | **Input** |
| `targets.schema.json` | Portfolio targets file | **Input** |
| `patch_plan.schema.json` | Planned transformations | Seeder output |
| `validation_result.schema.json` | Plausibility verdict | Validator output |
| `audit_result.schema.json` | Classification (VALID/NOOP/AMBIGUOUS/INVALID) | Auditor output |
| `vuln_spec.json` | Ground truth annotation | Auditor structural output |
| `audit_record.json` | Provenance record | Auditor provenance output |
| `corpus_plan.schema.json` | Corpus plan allocation | Planning layer output |
| `portfolio_plan.schema.json` | Portfolio global plan | Portfolio layer output |
| `portfolio_index.schema.json` | Portfolio manifest + fingerprints | Portfolio layer output |
| `portfolio_acceptance_summary.schema.json` | Portfolio acceptance counts | Portfolio layer output |
| `portfolio_shortfall_report.schema.json` | Portfolio shortfall attribution | Portfolio layer output |

---

## Deterministic-First Philosophy

The entire core pipeline — seed expansion, vulnerability selection, patching, ground
truth generation, and audit logging — is **fully deterministic given a seed file and a source tree**.

LLM assistance is confined to a **narrow, optional adapter layer** used only for:

- Semantic label refinement (e.g., "is this variant more realistic?")
- Tie-breaking between equivalent patch candidates
- Natural-language description generation for human-readable reports

If the LLM adapter is disabled or unavailable, these steps fall back to rule-based defaults.
The core artifacts (bad/good pairs, ground truth, audit log) are always produced deterministically.

This means:

- You can swap `claude-*` for an internal LLM, a local model, or a stub, at any time.
- Regression tests do not require an LLM.
- Outputs can be reproduced in environments with no outbound network access.

---

## Try It Now

These commands work against the bundled demo fixture today.

```bash
# 1. Install (editable)
pip install -e .

# 2. Run against the demo fixture
insert-me run \
  --seed-file examples/seeds/cwe122_heap_overflow.json \
  --source examples/demo/src
```

Example output:
```
[insert-me] starting pipeline
  seed-file : examples/seeds/cwe122_heap_overflow.json
  source    : examples/demo/src
  output    : output
[insert-me] bundle written to: output/9576dfc551a54e4c/
  patch_plan.json       : output/9576dfc551a54e4c/patch_plan.json
  validation_result.json: output/9576dfc551a54e4c/validation_result.json
  audit_result.json     : output/9576dfc551a54e4c/audit_result.json
  ground_truth.json     : output/9576dfc551a54e4c/ground_truth.json
  audit.json            : output/9576dfc551a54e4c/audit.json
```

```bash
# 3. Validate the bundle (replace 9576dfc551a54e4c with the run ID printed above)
insert-me validate-bundle output/9576dfc551a54e4c/

# 4. Inspect the audit record
insert-me audit output/9576dfc551a54e4c/audit.json
```

**What to expect today (real mode -- default):**
- `patch_plan.json` -- `status: "APPLIED"`, one target from `heap_buf.c`
- `ground_truth.json` -- one mutation record: `malloc(user_len * sizeof(char))` → `malloc((user_len * sizeof(char)) - 1)`, `validation_passed: true`
- `bad/heap_buf.c` -- mutated source (the vulnerability inserted)
- `good/heap_buf.c` -- byte-identical copy of the original
- `validation_result.json` -- `overall: "PASS"`, five rule-based checks all passing
- `audit_result.json` -- `classification: "VALID"` (Validator confirmed plausibility)
- `validate-bundle` exits 0 -- all artifacts are schema-valid

To skip patching and emit plan-only artifacts:
```bash
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source examples/demo/src \
              --dry-run
```
Dry-run: `patch_plan.json` status is `PLANNED`, `ground_truth.json` mutations is `[]`,
`audit_result.json` classification is `NOOP`, no source files are modified.

---

## Quick Start

```bash
# Install (editable)
pip install -e .

# Pattern 1: one-off seed run
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project

# Pattern 2: target-aware corpus for one source tree
insert-me generate-corpus --source examples/sandbox_eval/src --count 20

# Pattern 3: multi-target portfolio across two source trees
insert-me generate-portfolio \
    --targets-file examples/targets/sandbox_targets.json \
    --count 30
```

---

## Sandbox Corpus and Quality Gate

Two sandbox targets are included with a combined 76-seed accepted corpus:

| Target | Source | Seeds | Strategies | Accept rate |
|---|---|---|---|---|
| `sandbox_eval` | `examples/sandbox_eval/src/` (6 files) | 56 (11 CWE-122 · 19 CWE-416 · 5 CWE-415 · 5 CWE-401 · 8 CWE-476 · 8 CWE-190) | 6 | 100% (CWE-190: 87.5% VALID, 1 correct NOOP) |
| `target_b` | `examples/sandbox_targets/target_b/src/` (3 files) | 20 (4 CWE-122 · 5 CWE-416 · 3 CWE-415 · 3 CWE-401 · 5 CWE-476) | 5 | 100% |

All 76 seeds reproduce byte-identically across 3 runs each (76/76 PASS).

**CWE-476 (`remove_null_guard`) is corpus-admitted** as of Phase 10. The dual-mode handler supports both single-line inline guards (`if (!ptr) return;`) and multi-line guard forms. 8 CWE-476 sandbox seeds with 8/8 VALID; 5 target_b seeds with 5/5 VALID.

**CWE-190 (`remove_size_cast`) is corpus-admitted** as of Phase 14. Removes `(size_t)` cast from `malloc((size_t)EXPR * sizeof(T))`. 7/8 VALID (87.5%); 1 correct NOOP (double-cast line, conservatively skipped).

**Reproduce the full corpus from a fresh clone:**
```bash
python scripts/generate_corpus.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --output-dir  output/corpus \
  --manifest    examples/corpus_manifest.json
```

**Verify reproducibility (all seeds, 3 runs each):**
```bash
python scripts/check_reproducibility.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src
```

See `docs/corpus_quality_gate.md` for the acceptance rubric,
`docs/repro_runbook.md` for the operator-independent reproduction guide,
and `docs/issue_fix_log.md` for a record of issues found and fixed during hardening.

---

## Local Target Pilot

insert_me also works on user-provided local evaluation-only C/C++ projects.

**Step 1: Inspect the target (preflight check)**
```bash
insert-me inspect-target --source /path/to/local/toy_project
```
Reports candidate density, concentration risk, and a suitability tier
(pilot-single / pilot-small-batch / corpus-generation). No mutations applied.

**Step 2: Run a single seed**
```bash
insert-me run --seed-file examples/seeds/sandbox/cwe416_sb_001.json \
              --source /path/to/local/toy_project
```

**Step 3: Run a small batch or generate a full corpus**
```bash
# Small batch
insert-me batch --seed-dir my_seeds/ --source /path/to/local/toy_project

# Full corpus (target-aware planning + execution)
insert-me generate-corpus --source /path/to/local/toy_project --count 20
```

**Step 4: Or use portfolio generation for multiple targets**
```bash
insert-me generate-portfolio \
    --targets-file my_targets.json \
    --count 40
```

See `docs/local_target_pilot.md` for the full workflow including quality review,
reproducibility verification, and the decision tree for scaling to corpus generation.

**Suitable local targets:** evaluation-only toy/lab projects, small C programs with
clear `malloc`/`free`/pointer patterns, purpose-built sandbox files.

**Not recommended:** real production codebases, macro-heavy or template-heavy code,
targets with no `malloc`/`free` patterns. See `docs/local_target_pilot.md §1.2`.

---

## Portfolio Generation (Multi-Target)

Portfolio generation allocates a global count across multiple C/C++ source trees,
applies global diversity constraints, and produces unified portfolio-level artifacts
alongside per-target corpus outputs.

**Targets file format** (`examples/targets/sandbox_targets.json`):
```json
{
  "schema_version": "1.0",
  "targets": [
    {"name": "sandbox_eval", "path": "../sandbox_eval/src"},
    {"name": "target_b",     "path": "../sandbox_targets/target_b/src"}
  ]
}
```

**Portfolio artifacts produced:**

| Artifact | Description |
|---|---|
| `portfolio_plan.json` | Global allocation plan with per-target summaries and entries |
| `portfolio_index.json` | Corpus manifest, fingerprints, per-target/per-strategy breakdowns |
| `portfolio_acceptance_summary.json` | Requested/planned/accepted counts, by_target, by_strategy |
| `portfolio_shortfall_report.json` | Machine-readable shortfall attribution (plan + execution) |

**Portfolio shortfall categories:**

| Category key | Meaning |
|---|---|
| `target_capacity_limit` | Target's effective candidate capacity < allocated sub-count |
| `strategy_blocked_no_candidates` | Strategy has zero candidates on a target |
| `global_diversity_constraint_per_target` | Cases dropped by `max_per_target` limit |
| `global_diversity_constraint_per_strategy` | Cases dropped by `max_per_strategy_global` limit |
| `no_viable_targets` | All targets returned zero effective capacity |
| `experimental_strategy_excluded` | Experimental strategies excluded from corpus |
| `sweep_exhausted` | All candidates consumed; count still short |

**Reproducibility guarantee:**
Same targets-file + same `--count` + same constraint flags => same `portfolio_plan.json` (byte-identical).
Use `--from-plan portfolio_plan.json` to replay a portfolio without re-planning.

---

## Portability

`insert_me` is designed to be dropped into restricted enterprise environments:

- **No mandatory cloud calls.** All LLM calls are behind an optional adapter interface.
- **No mandatory internet access.** All schema validation and rule sets ship with the package.
- **Minimal dependencies.** Core pipeline uses Python stdlib + `jsonschema` (+ `tomli` on Python 3.10). See `pyproject.toml`.
- **Python 3.10--3.12.** No Python 3.11-specific features beyond `tomllib`, which is shimmed automatically.
- **Configurable via files.** All behaviour is driven by `config/` TOML files.
- **Self-contained output.** Output bundles carry everything needed for downstream tools.

To deploy in an air-gapped environment: copy the package, its dependencies, and your seed files.
No registration, no keys, no outbound calls required for core operation.

---

## License

**Undecided.** Intended for internal/research use only. Do not redistribute without explicit written permission.

See `NOTICE.txt` at the repository root for the full rights statement and a list of third-party dependency licenses.

A formal license has not yet been chosen. The `pyproject.toml` reflects this as `"Proprietary -- license TBD. Internal/research use only."` and `NOTICE.txt` is bundled into any distribution until a decision is made.
