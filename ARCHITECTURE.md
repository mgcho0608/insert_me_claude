# Architecture — insert_me

---

## Overview

`insert_me` is structured as a **linear, deterministic pipeline** with a thin optional boundary
for LLM-assisted enrichment. The design goal is that every stage can be understood, tested, and
replaced in isolation, and that the full pipeline produces identical outputs for identical inputs
regardless of which optional components are active.

---

## Current Implementation Status

**Phase 7A — Juliet identity + per-project evaluation foundation: complete.** The pipeline scans a real C/C++ source
tree, applies one mutation, validates the result with five rule-based checks, and writes a
complete schema-valid bundle including real `ground_truth.json`, `audit.json`, and a
verdict-derived `audit_result.json`. The new Evaluator compares a normalized detector report
against the ground truth oracle and produces match_result.json and coverage_result.json.

| Pipeline stage | Status | Notes |
|---|---|---|
| Seeder | **Complete** (Phase 3) | Lexical/regex source scan; real targets in `patch_plan.json` |
| Patcher | **Phase 4b** | `alloc_size_undercount` (CWE-122) + `insert_premature_free` (CWE-416); one mutation per run |
| Validator | **Complete** (Phase 5) | Five deterministic checks; no compiler required |
| Auditor | **Complete** (Phase 6) | Deterministic slice; writes ground_truth, audit, audit_result |
| Evaluator | **Complete** (Phase 7A) | Optional separate step; compares detector reports against ground truth |
| LLM Adapter | Interface only | `NoOpAdapter` always available; LLM adjudicator deferred to Phase 7B |

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
│  │  Patcher  │   DETERMINISTIC  [✓ Phase 4b — two strategies]          │
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

### Patcher (`pipeline/patcher.py`) — Phase 4b

**Deterministic.**

- Copies source_root byte-identically to `good/`.
- Copies source_root to `bad/` and applies one line-level mutation to the first compatible target.
- Output: `PatchResult` — paths to bad/good trees, list of `Mutation` records (0 or 1).

**Implemented strategies:**

| Strategy | CWE | Rule |
|---|---|---|
| `alloc_size_undercount` | CWE-122 | `malloc(<expr>)` → `malloc((<expr>) - 1)` |
| `insert_premature_free` | CWE-416 | Insert `free(ptr);` immediately before a pointer dereference |

**Phase 4 scope limits:**
- One mutation per run (first compatible target only).
- No AST parser — regex + paren-counting only.
- If the target line has no applicable dereference/malloc call, or the strategy is unrecognised,
  the target is added to `skipped_targets` and `bad/` remains identical to `good/`.

Additional strategies (integer overflow variants, etc.) are registered in `_STRATEGY_HANDLERS`
when implemented.

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
- LLM adjudication is an optional boundary: when disabled, `semantic` cases are flagged but not resolved.
  The evaluation never fails due to absent LLM.

**Invoked via:** `insert-me evaluate --bundle PATH --tool-report PATH --tool NAME`

Not wired into `run_pipeline()` — it is a separate, optional post-run step.

### LLM Adapter (`llm/adapter.py`)

**Optional. Replaceable.**

- Provides a single abstract interface: `LLMAdapter`.
- Default implementation: `NoOpAdapter` — returns empty enrichments. Always available.
- Optional implementations: thin wrappers around any LLM API.
- **Swapping the adapter has zero effect on deterministic outputs.**  Only `labels.json`
  (Auditor enrichment) and `adjudication_result.json` (Evaluator adjudication, Phase 7B)
  change.

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
| Patcher | Yes | No | **Partial (Phase 4a)** | `bad/` `good/` trees |
| Validator (rule checks) | Yes | No | **Yes (Phase 5)** | `validation_result.json` |
| Validator (soft score) | No | Optional | Deferred (Phase 7+) | adds field to `validation_result.json` |
| Auditor (structural) | Yes | No | **Yes (Phase 6)** | `ground_truth.json` `audit.json` `audit_result.json` |
| Auditor (label enrich.) | No | Optional | No (Phase 7) | `labels.json` |
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
├── cli.py               # CLI entrypoint (argparse) — run/validate-bundle/audit/evaluate
├── config.py            # Config loader + dataclass (TOML + CLI overrides)
├── schema.py            # Schema loader, artifact validation, validate_bundle()
├── artifacts.py         # BundlePaths, run ID derivation, write_json_artifact
├── pipeline/
│   ├── __init__.py      # Orchestrator — run_pipeline() [Phases 3–6 wired]
│   ├── seeder.py        # Seeder, PatchTarget, PatchTargetList  [Phase 3: COMPLETE]
│   ├── patcher.py       # Patcher, Mutation, PatchResult        [Phase 4b: two strategies]
│   ├── validator.py     # Validator, ValidationVerdict           [Phase 5: COMPLETE]
│   ├── auditor.py       # Auditor, GroundTruthRecord, AuditRecord [Phase 6: COMPLETE]
│   └── evaluator.py     # Evaluator, MatchRecord, EvaluationResult [Phase 7A: COMPLETE]
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
| `adjudication_result.schema.json` | LLM adjudication results (Phase 7B, optional) |

Schema loading, resolution (`.schema.json` vs `.json`), and validation are centralised in
`src/insert_me/schema.py`. Use the `SCHEMA_*` constants — never hardcode schema names.

See `docs/artifact_contracts.md` for the full artifact specification.
