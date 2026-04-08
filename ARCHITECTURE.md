# Architecture — insert_me

---

## Overview

`insert_me` is structured as a **linear, deterministic pipeline** with a thin optional boundary
for LLM-assisted enrichment. The design goal is that every stage can be understood, tested, and
replaced in isolation, and that the full pipeline produces identical outputs for identical inputs
regardless of which optional components are active.

---

## Current Implementation Status

**Phase 15.8 complete — single source of truth + auto-synced docs.**
Full pipeline operational: 6 corpus-admitted mutation strategies (CWE-122/416/415/401/476/190),
multi-line patcher infrastructure, all CLI subcommands including `insert-me plan-portfolio` and
`insert-me generate-portfolio` (multi-target corpus orchestration), 2 sandbox targets,
76-seed accepted corpus (100% reproducible), 4 portfolio JSON schemas
(portfolio_plan/index/acceptance_summary/shortfall_report — all `additionalProperties: false`),
corpus_index.json with fingerprints, `scripts/check_plan_stability.py` for fresh-plan
reproducibility verification, `config/project_status.json` as single authoritative status
manifest, `tests/test_doc_drift.py` (manifest-driven drift checks), `scripts/check_public_status.py`
for live validation report. Test count is tracked in manifest; not hard-coded in docs.

| Pipeline stage | Status | Notes |
|---|---|---|
| Seeder | **Complete** (Phase 3, hardened Phase 8/14) | 13 pattern types incl. `null_guard`, `malloc_size_cast`; free_call/loop-body/sub-malloc scoring penalties |
| Patcher | **Phase 4b/8/4c/10/14** | 6 corpus-admitted strategies (CWE-122/416/415/401/476/190); multi-line handler infrastructure in place |
| Validator | **Complete** (Phase 5) | Five deterministic checks; no compiler required |
| Auditor | **Complete** (Phase 6) | Deterministic slice; writes ground_truth, audit, audit_result |
| Evaluator | **Complete** (Phase 7A) | Optional separate step; compares detector reports against ground truth |
| Adjudicator | **Phase 7B-prep** | `HeuristicAdjudicator` (offline default) · `DisabledAdjudicator` · `LLMAdjudicator` placeholder |
| LLM Adapter | Interface only | `NoOpAdapter` always available; LLM enrichment (labels.json) deferred to Phase 7B |
| Corpus tooling | **Phase 8–15** | `scripts/generate_corpus.py` · `scripts/check_reproducibility.py` · `scripts/check_plan_stability.py` · `insert-me batch` · `insert-me inspect-target` · `insert-me plan-corpus` · `insert-me generate-corpus` (incl. `--from-plan` replay) · `corpus_index.json` with fingerprints |
| Planning layer (single-target) | **Phase 9/11/12** | `src/insert_me/planning/` -- `TargetInspector`, `SeedSynthesizer`, `CorpusPlanner` (incl. `from_dict()` for replay); count-driven; deterministic; suitability tiers VIABLE/LIMITED/BLOCKED |
| Portfolio layer (multi-target) | **Phase 15** | `src/insert_me/planning/portfolio.py` -- `PortfolioPlanner`, `PortfolioPlan`, `PortfolioConstraints`, `load_targets_file`; proportional allocation; global diversity constraints; `insert-me plan-portfolio` · `insert-me generate-portfolio` (incl. `--from-plan` replay) |

The pipeline orchestrator (`pipeline/__init__.py`) coordinates all four stages.
Each stage's `run()` method is implemented and called in sequence.

---

## Pipeline Stages

```
┌──────────────────────────────────────────────────────────────────────┐
│                         insert_me pipeline                            │
│                                                                       │
│  [seed.json]              <- schema: seed.schema.json                │
│  [Config TOML]                                                        │
│        |                                                              │
│        v                                                              │
│  ┌───────────┐   seed -> PatchTargetList                             │
│  │  Seeder   │   DETERMINISTIC  [✓ Phase 3 COMPLETE]                 │
│  └─────┬─────┘                                                        │
│        |  [patch_plan.json]  <- schema: patch_plan.schema.json       │
│        v                                                              │
│  ┌───────────┐   PatchPlan -> bad/good source trees                  │
│  │  Patcher  │   DETERMINISTIC  [✓ Phase 15 — 6 strategies]             │
│  └─────┬─────┘                                                        │
│        |                                                              │
│        v                                                              │
│  ┌─────────────┐  PatchResult -> plausibility verdict                │
│  │  Validator  │  DETERMINISTIC  [✓ Phase 5 COMPLETE — 5 checks]    │
│  └──────┬──────┘                                                      │
│         |  [validation_result.json]  <- validation_result.schema.json│
│         v                                                             │
│  ┌───────────┐   -> ground_truth.json, audit.json, audit_result.json │
│  │  Auditor  │   DETERMINISTIC  [✓ Phase 6 COMPLETE — minimal slice] │
│  └─────┬─────┘                                                        │
│        |                                                              │
│        ├───────────────────────────────┐                             │
│        v                               v                             │
│  [Output Bundle]                  ┌──────────────────┐              │
│  bad/  good/  (written in real mode)  │   LLM Adapter    │ OPTIONAL │
│  patch_plan.json                  │  (label enrich.) │              │
│  validation_result.json           └────────┬─────────┘              │
│  audit_result.json                         | [labels.json]           │
│  ground_truth.json                         |                         │
│  audit.json                                |                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Stage Responsibilities

### Seeder (`pipeline/seeder.py`) — Phase 3 COMPLETE

**Deterministic.**

- Accepts: a seed artifact (seed JSON) and a source tree path.
- Discovers all C/C++ source files under the source root (`.c`, `.cpp`, `.cc`, `.cxx`,
  `.h`, `.hpp`, `.hh`), honouring exclude patterns from `source_constraints`.
- Scans each file line-by-line using compiled regex patterns keyed by `pattern_type`.
  **No external AST parser** — lexical/regex heuristics only.
- Assigns a deterministic plausibility score (base 0.4, capped at 1.0) per line using
  strategy-specific rules (e.g. arithmetic in malloc size arg, `<=` in for-loop bound).
- Orders candidates: score DESC → (file, line) ASC → seed-integer shuffle within equal tiers.
- Filters by `min_candidate_score` and `max_targets` from the seed file.
- Output: `PatchTargetList` — an ordered, seed-deterministic sequence of `PatchTarget` instances.
- Also computes a 16-char hex SHA-256 source tree hash (`source_hash`) committed to
  `patch_plan.json` and `audit.json`.

No LLM calls.  No file writes.  `Seeder.run()` is fully implemented.

### Patcher (`pipeline/patcher.py`) — Phase 4b/8/4c partial

**Deterministic.**

- Copies source_root byte-identically to `good/`.
- Copies source_root to `bad/` and applies one mutation to the first compatible target.
- Output: `PatchResult` — paths to bad/good trees, list of `Mutation` records (0 or 1).
- Supports both **single-line handlers** (`_STRATEGY_HANDLERS`) and **multi-line handlers** (`_MULTILINE_STRATEGY_HANDLERS`). Multi-line handlers receive `(lines, line_idx)` and may modify any line in the file via `MultilineMutationResult.line_replacements`.

**Implemented strategies:**

| Strategy | CWE | Handler type | Corpus status | Rule |
|---|---|---|---|---|
| `alloc_size_undercount` | CWE-122 | single-line | corpus-admitted | `malloc(<expr>)` → `malloc((<expr>) - 1)` |
| `insert_premature_free` | CWE-416 | single-line | corpus-admitted | Insert `free(ptr);` before a pointer dereference |
| `insert_double_free` | CWE-415 | single-line | corpus-admitted | Insert duplicate `free(ptr);` before existing free |
| `remove_free_call` | CWE-401 | single-line | corpus-admitted | Replace `free(ptr);` with a memory-leak comment |
| `remove_null_guard` | CWE-476 | multi-line | corpus-admitted | Replace null-check guard (`if (!ptr) return;` or multiline form) with a comment; dual-mode handler |
| `remove_size_cast` | CWE-190 | single-line | corpus-admitted | Remove `(size_t)` cast from `malloc((size_t)EXPR * sizeof(T))`; enables integer overflow in size arithmetic |

One mutation per run (first compatible target only). No AST parser — regex + paren-counting only.
If the strategy is unrecognised or cannot be applied, the target is moved to `skipped_targets`.

Additional strategies are registered in `_STRATEGY_HANDLERS` (single-line) or
`_MULTILINE_STRATEGY_HANDLERS` (multi-line) when implemented.

### Validator (`pipeline/validator.py`) — Phase 5 COMPLETE

**Deterministic.**

- Accepts: a `PatchResult` (or `None` in dry-run mode) and the original `source_root`.
- In dry-run mode: returns an empty SKIP verdict immediately without file I/O.
- In real mode: runs five checks — `mutation_applied`, `good_tree_integrity`,
  `bad_tree_changed`, `mutation_scope`, `simple_syntax_sanity`.
- No compiler invocation; all checks are rule-based and operate on file contents.
- Output: `ValidationVerdict` — `overall` (PASS/FAIL/SKIP) + per-check `CheckResult` records.

**Checks summary:**

| Check | Passes when |
|---|---|
| `mutation_applied` | At least one `Mutation` record exists in `PatchResult` |
| `good_tree_integrity` | `good/` copy of mutated file is byte-identical to original source |
| `bad_tree_changed` | `bad/` file differs from `good/` and contains `mutated_fragment` |
| `mutation_scope` | Exactly 1 file differs between `bad/` and `good/` |
| `simple_syntax_sanity` | Mutated line has balanced parentheses; file is non-empty |

### Auditor (`pipeline/auditor.py`) — Phase 6 COMPLETE (minimal slice)

**Deterministic.**

- Accepts: `PatchResult | None`, `ValidationVerdict`, `BundlePaths`, run metadata
  (run_id, seed, seed_data, pipeline_version, spec_path, spec_hash, source_root, source_hash).
- Writes three artifacts in order: `ground_truth.json` → `audit.json` → `audit_result.json`.
- All three are schema-validated before writing.
- Output: `(GroundTruthRecord, AuditRecord)`.

**Classification logic for `audit_result.json`:**

| Condition | Classification | Confidence |
|---|---|---|
| Mutations present + Validator PASS | `VALID` | medium |
| Mutations present + Validator FAIL | `INVALID` | medium |
| Mutations present + Validator SKIP | `AMBIGUOUS` | low |
| No mutations (dry-run or no compatible target) | `NOOP` | low |

**`labels.json` enrichment (Phase 7):**
The `llm_adapter` parameter is accepted but not invoked.  `labels.json` is never written
in this phase.  Deferred to Phase 7.

### Evaluator (`pipeline/evaluator.py`) — Phase 7A COMPLETE

**Deterministic. Optional, post-run step.**

- Accepts: an insert_me output bundle path, a normalized detector report dict, and a tool name.
- Loads `ground_truth.json` from the bundle to get the mutation oracle.
- For each mutation, compares against all detector findings using a 3-level precedence hierarchy:
  - `exact` — same file basename + same CWE ID + finding line within ±2 of mutation line
  - `family` — both CWEs map to the same CWE family group (18 CWEs across 9 families)
  - `semantic` — keyword from the mutation's CWE family found in the finding message; marks `adjudication_pending=True`
  - `no_match` — none of the above
- Tracks false positives: findings not linked to any mutation.
- Writes `match_result.json` (per-mutation detail) and `coverage_result.json` (summary statistics).
- After matching, invokes the configured **Adjudicator** to resolve `semantic` cases:
  - `HeuristicAdjudicator` (default) — deterministic offline scoring; produces MATCH/UNRESOLVED/NO_MATCH verdicts
    based on file, line proximity, CWE family, and keyword signals.
  - `DisabledAdjudicator` — no-op; semantic matches stay flagged as `adjudication_pending=True`.
  - `LLMAdjudicator` — Phase 7B placeholder; raises `NotImplementedError`.
- When verdicts exist, writes `adjudication_result.json` and adds `adjudication_summary` to `coverage_result.json`.
- The evaluation never fails due to absent LLM; `--adjudicator disabled` is always safe.

**Invoked via:** `insert-me evaluate --bundle PATH --tool-report PATH --tool NAME [--adjudicator heuristic|disabled]`

Not wired into `run_pipeline()` — it is a separate, optional post-run step.

### LLM Adapter (`llm/adapter.py`)

**Optional. Replaceable.**

- Provides a single abstract interface: `LLMAdapter`.
- Default implementation: `NoOpAdapter` — returns empty enrichments. Always available.
- Optional implementations: thin wrappers around any LLM API.
- **Swapping the adapter has zero effect on deterministic outputs.**  Only `labels.json`
  (Auditor enrichment, Phase 7B) changes.

---

## Artifact Flow (current phase)

```
seed.json + source tree
        |
        v
    Seeder.run()             [REAL — lexical scan + ranking]
        |
        |-- patch_plan.json  (orchestrator; APPLIED/PLANNED/PENDING)
        |
    Real mode (default):
        Patcher.run()        [REAL — copies source, applies one mutation]
        |-- bad/             mutated source tree
        |-- good/            byte-identical copy of original
        |
    Dry-run mode (--dry-run):
        [Patcher not invoked; bad/ and good/ created as empty dirs]
        |
    Both modes:
        Validator.run()      [REAL — 5 checks in real mode; SKIP in dry-run]
        |-- validation_result.json  (orchestrator)
        |
        Auditor.run()        [REAL — writes 3 artifacts, schema-validated]
        |-- ground_truth.json       (real mutation records; empty in dry-run)
        |-- audit.json              (full provenance, real validation_verdict)
        |-- audit_result.json       (VALID/INVALID/AMBIGUOUS/NOOP)
        |
        v
    output/<run-id>/
```

---

## Deterministic vs Optional LLM Components

| Component | Deterministic? | LLM-dependent? | Implemented? | Output artifact |
|---|---|---|---|---|
| Seeder | Yes | No | **Yes (Phase 3)** | `patch_plan.json` |
| Patcher | Yes | No | **Yes (Phase 4b/8/4c)** | `bad/` `good/` trees |
| Validator (rule checks) | Yes | No | **Yes (Phase 5)** | `validation_result.json` |
| Validator (soft score) | No | Optional | Deferred (Phase 7+) | adds field to `validation_result.json` |
| Auditor (structural) | Yes | No | **Yes (Phase 6)** | `ground_truth.json` `audit.json` `audit_result.json` |
| Auditor (label enrich.) | No | Optional | No (Phase 7B) | `labels.json` |
| Evaluator | Yes | No | **Yes (Phase 7A)** | `match_result.json` `coverage_result.json` |
| Adjudicator (heuristic) | Yes | No | **Yes (Phase 7B-prep)** | `adjudication_result.json` + `adjudication_summary` in coverage |
| Adjudicator (LLM) | No | Yes | Placeholder (Phase 7B) | (same as heuristic) |
| LLM Adapter | N/A | Yes | Stub (NoOp) | (side-channel only) |

---

## Why This Design Is Robust for Weaker LLMs

The LLM is never in the critical path for structural correctness:

- Bad/good pairs will be produced by the deterministic Patcher.
- Ground truth will be written by the deterministic Auditor from structured records.
- Audit provenance is written from pipeline state, not LLM output.

The LLM adapter is called **after** the ground truth is already determined, for enrichment only.
A weaker model that produces poor semantic labels simply produces a less informative `labels.json`
— it does not corrupt the core output.

This also means:

- You can run the full pipeline with `--no-llm` and get complete, valid output bundles.
- Swapping to a weaker internal model requires only changing one config key.
- Integration tests for the core pipeline never require LLM mocking.

---

## Module Map

```
src/insert_me/
├── __init__.py          # Package version, public re-exports
├── cli.py               # CLI entrypoint — run/batch/inspect-target/plan-corpus/generate-corpus/plan-portfolio/generate-portfolio/validate-bundle/audit/evaluate
├── config.py            # Config loader + dataclass (TOML + CLI overrides)
├── schema.py            # Schema loader, artifact validation, validate_bundle()
├── artifacts.py         # BundlePaths, run ID derivation, write_json_artifact
├── pipeline/
│   ├── __init__.py      # Orchestrator — run_pipeline() [Phases 3–6 wired]
│   ├── seeder.py        # Seeder, PatchTarget, PatchTargetList  [Phase 3: COMPLETE]
│   ├── patcher.py       # Patcher, Mutation, PatchResult, MultilineMutationResult [Phase 4b/8/4c/14: 6 strategies]
│   ├── validator.py     # Validator, ValidationVerdict           [Phase 5: COMPLETE]
│   ├── auditor.py       # Auditor, GroundTruthRecord, AuditRecord [Phase 6: COMPLETE]
│   └── evaluator.py     # shim — re-exports from evaluation/    [backward compat]
├── planning/
│   ├── __init__.py      # Public API re-exports (CorpusPlanner, TargetInspector, PortfolioPlanner, …)
│   ├── inspector.py     # TargetInspector — suitability scan; VIABLE/LIMITED/BLOCKED tiers [Phase 9]
│   ├── seed_synthesis.py # SeedSynthesizer — deterministic seed-integer sweep [Phase 9]
│   ├── corpus_planner.py # CorpusPlanner — single-target allocation, plan generation, write() [Phase 9]
│   └── portfolio.py     # PortfolioPlanner, PortfolioPlan, PortfolioConstraints, load_targets_file [Phase 15]
├── evaluation/
│   ├── __init__.py      # Public API re-exports
│   ├── evaluator.py     # Evaluator, MatchRecord, EvaluationResult [Phase 7A]
│   ├── matching.py      # exact/family/semantic match + CWE families + emit_match_result
│   ├── coverage.py      # emit_coverage_result (with adjudication_summary)
│   ├── adjudication.py  # AdjudicatorBase, Heuristic/Disabled/LLMAdjudicator [Phase 7B-prep]
│   └── detector_report.py # load/validate detector report JSON
└── llm/
    ├── __init__.py      # Adapter registry
    └── adapter.py       # LLMAdapter ABC + NoOpAdapter           [Phase 7B: NoOp only]
```

---

## Configuration

All behaviour is driven by TOML config files. Key sections:

- `[pipeline]` — seed_file, seed, spec path, source path, output root, run ID override
- `[llm]` — adapter name, endpoint, model, enabled flag
- `[validator]` — which rule checks to enable
- `[auditor]` — output format options, label enrichment toggle

Built-in defaults are used when no config file is provided (suitable for quick-start use).

---

## Schema Contracts

All artifacts (inputs and outputs) are validated against versioned JSON schemas in `schemas/`.
Schema versions are carried in every artifact under `"schema_version"`.

| Schema file | Covers |
|---|---|
| `seed.schema.json` | Seed/case definition (pipeline input) |
| `patch_plan.schema.json` | Seeder output: planned transformations |
| `validation_result.schema.json` | Validator output: plausibility verdict |
| `audit_result.schema.json` | Auditor classification: VALID/NOOP/AMBIGUOUS/INVALID |
| `vuln_spec.json` | Ground truth mutation annotation |
| `audit_record.json` | Provenance record |
| `detector_report.schema.json` | Normalized detector report (Evaluator input) |
| `match_result.schema.json` | Per-mutation match evaluation (Evaluator output) |
| `coverage_result.schema.json` | Coverage summary statistics (Evaluator output) |
| `adjudication_result.schema.json` | Adjudicator verdicts for semantic matches (heuristic or LLM; optional) |
| `corpus_plan.schema.json` | Single-target corpus plan allocation |
| `targets.schema.json` | Portfolio targets file (input to plan-portfolio/generate-portfolio) |
| `portfolio_plan.schema.json` | Global portfolio allocation plan |
| `portfolio_index.schema.json` | Portfolio manifest + fingerprints |
| `portfolio_acceptance_summary.schema.json` | Portfolio acceptance counts by target and strategy |
| `portfolio_shortfall_report.schema.json` | Portfolio shortfall attribution (plan + execution) |

Schema loading, resolution (`.schema.json` vs `.json`), and validation are centralised in
`src/insert_me/schema.py`. Use the `SCHEMA_*` constants — never hardcode schema names.

See `docs/artifact_contracts.md` for the full artifact specification.

---

## Portfolio Orchestration Layer (Phase 15)

The portfolio layer sits above the single-target planning layer and coordinates
corpus generation across multiple evaluation-only C/C++ source trees.

```
targets.json
    |
    v
PortfolioPlanner.plan()
    |
    +-- Inspect each target (TargetInspector)
    |   => effective capacity (VIABLE=full, LIMITED=half, BLOCKED=0)
    |
    +-- Allocate globally (proportional to capacity)
    |   => floor-integer distribution + remainder by highest fractional part
    |
    +-- Plan each sub-allocation (CorpusPlanner per target)
    |   => case_id_prefix = sanitised target name (globally unique IDs)
    |
    +-- Global greedy selection
    |   sort: (-suitability_weight, -score, target_name, strategy, seed_integer)
    |   limits: max_per_target (hard), max_per_strategy_global (hard)
    |   warnings: max_per_target_fraction (soft), max_per_strategy_fraction (soft)
    |
    +-- Shortfall diagnostics
    |   machine-readable categories: target_capacity_limit, strategy_blocked,
    |   global_diversity_constraint_*, no_viable_targets, sweep_exhausted
    |
    v
PortfolioPlan + per_target_plans (dict[str, CorpusPlan])
    |
    v
generate-portfolio CLI
    |
    +-- write portfolio_plan.json + per-target sub-plans
    +-- execute pipeline per target (reuses _execute_plan_cases)
    +-- _finish_generate_corpus per target (per-target corpus artifacts)
    +-- write portfolio_index.json
    +-- write portfolio_acceptance_summary.json
    +-- write portfolio_shortfall_report.json
```

**Reproducibility guarantee:** Same targets-file + same `--count` + same constraints =>
byte-identical `portfolio_plan.json` and `portfolio_fingerprint`.

**Replay:** `insert-me generate-portfolio --from-plan portfolio_plan.json` re-executes
the same cases in the same order without re-planning.
