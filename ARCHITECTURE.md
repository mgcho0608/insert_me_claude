# Architecture — insert_me

---

## Overview

`insert_me` is structured as a **linear, deterministic pipeline** with a thin optional boundary
for LLM-assisted enrichment. The design goal is that every stage can be understood, tested, and
replaced in isolation, and that the full pipeline produces identical outputs for identical inputs
regardless of which optional components are active.

---

## Pipeline Stages

```
┌──────────────────────────────────────────────────────────────────────┐
│                         insert_me pipeline                            │
│                                                                       │
│  [seed.json]              ← schema: seed.schema.json                 │
│  [Config TOML]                                                        │
│        │                                                              │
│        ▼                                                              │
│  ┌───────────┐   seed → PatchTargetList                              │
│  │  Seeder   │   DETERMINISTIC                                        │
│  └─────┬─────┘                                                        │
│        │  [patch_plan.json]  ← schema: patch_plan.schema.json        │
│        ▼                                                              │
│  ┌───────────┐   PatchPlan → mutated source tree                     │
│  │  Patcher  │   DETERMINISTIC                                        │
│  └─────┬─────┘                                                        │
│        │                                                              │
│        ▼                                                              │
│  ┌─────────────┐  source tree → plausibility verdict                 │
│  │  Validator  │  DETERMINISTIC (rule-based)                         │
│  └──────┬──────┘                                                      │
│         │  [validation_result.json]  ← validation_result.schema.json │
│         ▼                                                             │
│  ┌───────────┐   → ground_truth.json, audit.json, audit_result.json  │
│  │  Auditor  │   DETERMINISTIC                                        │
│  └─────┬─────┘                                                        │
│        │                                                              │
│        ├─────────────────────────────────┐                           │
│        ▼                                 ▼                           │
│  [Output Bundle]                  ┌──────────────────┐              │
│  bad/  good/                      │   LLM Adapter    │ OPTIONAL     │
│  ground_truth.json                │  (label enrich.) │              │
│  audit.json                       └────────┬─────────┘              │
│  audit_result.json                         │ [labels.json]           │
│  validation_result.json                    │                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Stage Responsibilities

### Seeder (`pipeline/seeder.py`)

**Deterministic.**

- Accepts: a numeric seed, a vulnerability specification (TOML), and a source tree path.
- Expands the seed into a ranked, ordered list of **patch targets**: candidate locations in the
  source tree where the specified vulnerability class can be plausibly inserted.
- Uses only static analysis (AST walking, pattern matching) and the seed for ordering decisions.
- Output: `PatchTargetList` — an ordered sequence of `PatchTarget` dataclass instances.

No randomness beyond `random.seed(seed)`. No LLM calls. No I/O side effects.

### Patcher (`pipeline/patcher.py`)

**Deterministic.**

- Accepts: a `PatchTargetList` and a source tree path.
- Applies AST-level or line-level mutations to produce the **bad** (vulnerable) version.
- Copies the original to produce the **good** (clean) version.
- Output: `PatchResult` — paths to bad/good trees, list of applied `Mutation` records.

All mutations are rule-based transforms. The Patcher does not decide *what* to insert — the
Seeder already made that decision. The Patcher only executes it.

### Validator (`pipeline/validator.py`)

**Deterministic.**

- Accepts: a `PatchResult`.
- Confirms: syntactic well-formedness, semantic plausibility of the mutation, absence of obvious
  disqualifying artifacts (e.g., mutation that breaks compilation trivially).
- Output: `ValidationVerdict` — pass/fail + structured reason codes.

The Validator does NOT require LLM input. It runs a set of rule-based checks. The LLM adapter
may later add a soft plausibility score alongside, but this is advisory only.

### Auditor (`pipeline/auditor.py`)

**Deterministic.**

- Accepts: `PatchResult`, `ValidationVerdict`, config, spec, seed, pipeline version.
- Writes `ground_truth.json` — full annotation of what was inserted, where, why it is a
  vulnerability instance of the specified class.
- Writes `audit.json` — full provenance record.
- Output: `AuditRecord` and `GroundTruthRecord` dataclasses + written files.

The Auditor is the final pipeline stage. Its outputs are authoritative.

### LLM Adapter (`llm/adapter.py`)

**Optional. Replaceable.**

- Provides a single abstract interface: `LLMAdapter`.
- Default implementation: `NoOpAdapter` — returns stub/empty enrichments. Always available.
- Optional implementations: thin wrappers around any LLM API (Anthropic, OpenAI-compatible,
  local model HTTP endpoint, etc.).
- Called only by: Auditor (for label enrichment), and optionally Validator (for soft scoring).
- **Swapping the adapter has zero effect on deterministic outputs.** Only `labels.json` and
  optional description fields change.

---

## Artifact Flow

```
seed.json ──────────────┐
(seed.schema.json)      │
Config TOML  ───────────┼──► Seeder ──► PatchTargetList
Source tree  ───────────┘        │
                                  │  writes: patch_plan.json
                                  ▼  (patch_plan.schema.json)
                              Patcher ──► PatchResult (bad/ good/ Mutations)
                                  │
                                  ▼
                              Validator ──► ValidationVerdict
                                  │  writes: validation_result.json
                                  │  (validation_result.schema.json)
                       ┌──────────┴──────────────┐
                       ▼                         ▼
                   Auditor              LLM Adapter (optional)
                       │                         │
                       ▼                         ▼
               ground_truth.json            labels.json
               audit.json
               audit_result.json
               (audit_result.schema.json)
```

All artifacts are written to a single **output bundle directory** identified by a run ID
derived deterministically from the seed + spec + source tree hash.

---

## Deterministic vs Optional LLM Components

| Component | Deterministic? | LLM-dependent? | Can be disabled? | Output artifact |
|---|---|---|---|---|
| Seeder | Yes | No | N/A | `patch_plan.json` |
| Patcher | Yes | No | N/A | `bad/` `good/` trees |
| Validator (rule checks) | Yes | No | N/A | `validation_result.json` |
| Validator (soft score) | No | Optional | Yes — skipped | adds field to `validation_result.json` |
| Auditor (structural output) | Yes | No | N/A | `ground_truth.json` `audit.json` `audit_result.json` |
| Auditor (label enrichment) | No | Optional | Yes — stub | `labels.json` |
| LLM Adapter | N/A | Yes | Yes — NoOpAdapter | (side-channel only) |

---

## Why This Design Is Robust for Weaker LLMs

The LLM is never in the critical path for structural correctness:

- Bad/good pairs are always produced by the deterministic Patcher.
- Ground truth is always written by the deterministic Auditor from structured records.
- Audit provenance is always written from pipeline state, not LLM output.

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
├── cli.py               # CLI entrypoint (argparse)
├── config.py            # Config loader + dataclass
├── schema.py            # Schema loader + JSON validation
├── artifacts.py         # Output path helpers, run ID derivation
├── pipeline/
│   ├── __init__.py      # Pipeline orchestrator
│   ├── seeder.py        # Seed expansion → PatchTargetList
│   ├── patcher.py       # Mutation application → PatchResult
│   ├── validator.py     # Plausibility validation → ValidationVerdict
│   └── auditor.py       # Ground truth + audit record writing
└── llm/
    ├── __init__.py      # Adapter registry
    └── adapter.py       # LLMAdapter ABC + NoOpAdapter
```

---

## Configuration

All behaviour is driven by TOML config files (see `config/default.toml`). Key sections:

- `[pipeline]` — seed, spec path, source path, output root, run ID override
- `[llm]` — adapter name, endpoint, model, enabled flag
- `[validator]` — which rule checks to enable
- `[auditor]` — output format options, label enrichment toggle

---

## Schema Contracts

All artifacts (inputs and outputs) are validated against versioned JSON schemas in `schemas/`.
Schema versions are pinned in `pyproject.toml` and carried in every artifact under `"schema_version"`.

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
