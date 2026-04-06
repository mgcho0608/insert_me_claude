# Architecture — insert_me

---

## Overview

`insert_me` is structured as a **linear, deterministic pipeline** with a thin optional boundary
for LLM-assisted enrichment. The design goal is that every stage can be understood, tested, and
replaced in isolation, and that the full pipeline produces identical outputs for identical inputs
regardless of which optional components are active.

---

## Current Implementation Status

**Phase 3 — Seeder: complete.** The pipeline can scan a real C/C++ source tree, extract ranked
patch targets, and emit a schema-valid output bundle.  Source files are never modified.

| Pipeline stage | Status | Notes |
|---|---|---|
| Seeder | **Complete** (Phase 3) | Lexical/regex source scan; real targets in `patch_plan.json` |
| Patcher | **Partial** (Phase 4a) | `alloc_size_undercount` strategy only; one mutation per run |
| Validator | **Stub** (Phase 5) | `Validator.run()` raises `NotImplementedError` |
| Auditor | **Stub** (Phase 6) | `Auditor.run()` raises `NotImplementedError` |
| LLM Adapter | Interface only | `NoOpAdapter` always available; real adapters deferred |

The pipeline orchestrator (`pipeline/__init__.py`) coordinates Seeder and Patcher
directly.  Validator and Auditor class methods are not yet called; the orchestrator
emits placeholder artifacts for those stages.

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
│  ┌───────────┐   PatchPlan -> mutated source tree                    │
│  │  Patcher  │   DETERMINISTIC  [⧖ Phase 4 — STUB]                  │
│  └─────┬─────┘                                                        │
│        |                                                              │
│        v                                                              │
│  ┌─────────────┐  source tree -> plausibility verdict                │
│  │  Validator  │  DETERMINISTIC  [⧖ Phase 5 — STUB]                 │
│  └──────┬──────┘                                                      │
│         |  [validation_result.json]  <- validation_result.schema.json│
│         v                                                             │
│  ┌───────────┐   -> ground_truth.json, audit.json, audit_result.json │
│  │  Auditor  │   DETERMINISTIC  [⧖ Phase 6 — STUB]                  │
│  └─────┬─────┘                                                        │
│        |                                                              │
│        ├───────────────────────────────┐                             │
│        v                               v                             │
│  [Output Bundle]                  ┌──────────────────┐              │
│  bad/  good/  (empty until Ph.4)  │   LLM Adapter    │ OPTIONAL     │
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

### Patcher (`pipeline/patcher.py`) — Phase 4a PARTIAL

**Deterministic.**

- Copies source_root byte-identically to `good/`.
- Copies source_root to `bad/` and applies one line-level mutation to the first compatible target.
- Output: `PatchResult` — paths to bad/good trees, list of `Mutation` records (0 or 1).

**Currently implemented strategy:**

| Strategy | Rule |
|---|---|
| `alloc_size_undercount` | `malloc(<expr>)` → `malloc((<expr>) - 1)` |

**Phase 4 scope limits:**
- One mutation per run (first compatible target only).
- No AST parser — regex + paren-counting only.
- If the target line has no malloc call, or the strategy is unrecognised, the target
  is added to `skipped_targets` and `bad/` remains identical to `good/`.

Future strategies (`insert_premature_free`, integer overflow variants, etc.) are
registered in `_STRATEGY_HANDLERS` when implemented.

### Validator (`pipeline/validator.py`) — Phase 5 STUB

**Deterministic (planned).**

- Will accept a `PatchResult`.
- Will run rule-based checks: syntactic well-formedness, non-triviality, scope sanity.
- Output: `ValidationVerdict` — pass/fail + per-check `CheckResult` records.

`Validator.run()` currently raises `NotImplementedError`.  The dataclasses
(`ValidationVerdict`, `CheckResult`, `CheckStatus`) are defined and stable.

### Auditor (`pipeline/auditor.py`) — Phase 6 STUB

**Deterministic (planned).**

- Will accept `PatchResult`, `ValidationVerdict`, config, spec, seed, pipeline version.
- Will write `ground_truth.json` and `audit.json`.
- Optional LLM adapter call for `labels.json` enrichment.
- Output: `GroundTruthRecord`, `AuditRecord`.

`Auditor.run()` currently raises `NotImplementedError`.  The dataclasses
(`GroundTruthRecord`, `AuditRecord`, `MutationRecord`) are defined and stable.

### LLM Adapter (`llm/adapter.py`)

**Optional. Replaceable.**

- Provides a single abstract interface: `LLMAdapter`.
- Default implementation: `NoOpAdapter` — returns empty enrichments. Always available.
- Optional implementations: thin wrappers around any LLM API.
- **Swapping the adapter has zero effect on deterministic outputs.**  Only `labels.json`
  and optional description fields change.

---

## Artifact Flow (current phase)

The pipeline orchestrator currently produces all five core artifacts directly,
without calling Patcher/Validator/Auditor.run():

```
seed.json + source tree
        |
        v
    Seeder.run()          [REAL — lexical scan + ranking]
        |
        |-- patch_plan.json         (status=PLANNED/PENDING, real targets)
        |
    Real mode (default: --dry-run not set):
        Patcher.run()             [REAL — copies source, applies one mutation]
        |-- bad/                  mutated source tree
        |-- good/                 byte-identical copy of original
        |
    Dry-run mode (--dry-run flag):
        [Patcher not invoked; bad/ and good/ created as empty dirs]
        |
    Both modes:
        |-- patch_plan.json         (APPLIED/PLANNED/PENDING; real Seeder targets)
        |-- validation_result.json  (overall=SKIP, Validator pending Phase 5)
        |-- audit_result.json       (AMBIGUOUS if mutated, NOOP otherwise)
        |-- ground_truth.json       (real mutation record if applied, else mutations=[])
        |-- audit.json              (full provenance, real source_hash)
        |
        v
    output/<run-id>/
```

---

## Deterministic vs Optional LLM Components

| Component | Deterministic? | LLM-dependent? | Implemented? | Output artifact |
|---|---|---|---|---|
| Seeder | Yes | No | **Yes (Phase 3)** | `patch_plan.json` |
| Patcher | Yes | No | No (Phase 4) | `bad/` `good/` trees |
| Validator (rule checks) | Yes | No | No (Phase 5) | `validation_result.json` |
| Validator (soft score) | No | Optional | No (Phase 5+) | adds field to `validation_result.json` |
| Auditor (structural) | Yes | No | No (Phase 6) | `ground_truth.json` `audit.json` `audit_result.json` |
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
├── cli.py               # CLI entrypoint (argparse) — run/validate-bundle/audit
├── config.py            # Config loader + dataclass (TOML + CLI overrides)
├── schema.py            # Schema loader, artifact validation, validate_bundle()
├── artifacts.py         # BundlePaths, run ID derivation, write_json_artifact
├── pipeline/
│   ├── __init__.py      # Orchestrator — run_pipeline() [Phase 2-3: full dry-run]
│   ├── seeder.py        # Seeder, PatchTarget, PatchTargetList  [Phase 3: COMPLETE]
│   ├── patcher.py       # Patcher, Mutation, PatchResult        [Phase 4: STUB]
│   ├── validator.py     # Validator, ValidationVerdict           [Phase 5: STUB]
│   └── auditor.py       # Auditor, GroundTruthRecord, AuditRecord [Phase 6: STUB]
└── llm/
    ├── __init__.py      # Adapter registry
    └── adapter.py       # LLMAdapter ABC + NoOpAdapter           [Phase 7: NoOp only]
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

Schema loading, resolution (`.schema.json` vs `.json`), and validation are centralised in
`src/insert_me/schema.py`. Use the `SCHEMA_*` constants — never hardcode schema names.

See `docs/artifact_contracts.md` for the full artifact specification.
