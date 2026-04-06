# Artifact Contracts — insert_me

This document is the **authoritative specification** for all artifacts produced and
consumed by `insert_me`. Downstream tools (`check_me`, `bench_me`, human reviewers)
must treat this document as ground truth.

Schema files are in `schemas/`. Use the `SCHEMA_*` constants in `insert_me.schema`
when referencing schemas in code — never hardcode schema names.

---

## Output Bundle Layout

A single `insert_me run` produces one **output bundle** under `output/<run-id>/`:

```
output/<run-id>/
├── bad/                      Mutated C/C++ source tree (vulnerability inserted)
├── good/                     Clean C/C++ source tree (byte-identical to original)
├── patch_plan.json           Seeder output: planned transformations (§1)
├── validation_result.json    Validator output: plausibility verdict (§2)
├── audit_result.json         Auditor classification: VALID/NOOP/AMBIGUOUS/INVALID (§3)
├── ground_truth.json         Vulnerability annotation (§4)
├── audit.json                Provenance record (§5)
└── labels.json               (optional) LLM-enriched semantic labels (§6)
```

The `<run-id>` is a 16-character hex string derived deterministically from:
`SHA-256(canonical_seed_json || source_tree_path || pipeline_version)[:16]`

All five core artifacts (`patch_plan`, `validation_result`, `audit_result`,
`ground_truth`, `audit`) are produced by every run including dry-run mode.
`labels.json` is produced only when the LLM adapter is enabled with `write_labels = true`.

---

## §1 patch_plan.json

Schema: `schemas/patch_plan.schema.json` (version 1.0)
Pipeline stage: Seeder output → Patcher input

Contains the deterministically ordered list of intended source mutations. Produced
before any source files are modified.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `plan_id` | string | Deterministic identifier for this plan |
| `run_id` | string | 16-char hex run identifier |
| `seed_id` | string | `seed_id` from the input seed artifact |
| `seed` | integer | Integer seed (carried from seed artifact) |
| `status` | string | `PENDING` / `PLANNED` / `APPLIED` / `ABORTED` |
| `created_at` | string | ISO 8601 UTC timestamp |
| `targets` | array | Ordered list of planned patch targets (see §1.1) |

In dry-run mode: `status = "PENDING"`, `targets = []`.

### §1.1 Target record

Each entry in `targets`:

| Field | Type | Description |
|---|---|---|
| `target_id` | string | Stable local identifier within this plan |
| `file` | string | Source file path relative to source tree root |
| `line` | integer (≥1) | 1-based line number of primary mutation point |
| `mutation_strategy` | string | Strategy the Patcher will apply |
| `candidate_score` | number (0–1) | Plausibility score assigned by the Seeder |
| `context` | object | AST-walking context (strategy-specific) |

---

## §2 validation_result.json

Schema: `schemas/validation_result.schema.json` (version 1.0)
Pipeline stage: Validator output

Rule-based plausibility verdict on the applied mutations. Fully deterministic — no LLM involved.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `result_id` | string | Deterministic identifier for this result |
| `run_id` | string | 16-char hex run identifier |
| `plan_id` | string | Links to the patch_plan that was validated |
| `overall` | string | `PASS` / `FAIL` / `SKIP` |
| `checks` | array | Per-check results (see §2.1) |

In dry-run mode: `overall = "SKIP"`, `checks = []`.

### §2.1 Check record

| Field | Type | Description |
|---|---|---|
| `name` | string | Check identifier (e.g. `"syntax"`, `"non_trivial"`, `"scope"`) |
| `status` | string | `pass` / `fail` / `skip` / `error` |
| `reason` | string | Human-readable explanation (required for fail/error) |

---

## §3 audit_result.json

Schema: `schemas/audit_result.schema.json` (version 1.0)
Pipeline stage: Auditor output

Final classification of the run. Primarily deterministic (rule-based); may include
optional LLM-assisted evidence items.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `audit_id` | string | Deterministic identifier for this audit |
| `run_id` | string | 16-char hex run identifier |
| `classification` | string | `VALID` / `NOOP` / `AMBIGUOUS` / `INVALID` |
| `confidence` | string | `high` / `medium` / `low` |
| `evidence` | array | Evidence items supporting the classification (see §3.1) |

In dry-run mode: `classification = "NOOP"`, `confidence = "low"`, one neutral evidence item.

### §3.1 Evidence record

| Field | Type | Description |
|---|---|---|
| `source` | string | `validator` / `patcher` / `seeder` / `rule_engine` / `llm_adapter` / `human` |
| `observation` | string | Plain-text description of what was observed |
| `weight` | string | `strong` / `moderate` / `weak` / `neutral` / `contradicts` |

### Classification semantics

| Value | Meaning |
|---|---|
| `VALID` | Structurally sound, plausible, non-trivial vulnerability instance. Safe for corpus inclusion. |
| `NOOP` | Run completed but mutation produced no meaningful semantic change. |
| `AMBIGUOUS` | Conflicting signals; requires human review before corpus inclusion. |
| `INVALID` | Failed structural checks or clearly not a real vulnerability instance. |

---

## §4 ground_truth.json

Schema: `schemas/vuln_spec.json` (version 1.0)
Pipeline stage: Auditor structural output

Machine-readable annotation of what vulnerability was inserted and where.
This is the primary artifact consumed by `check_me` and `bench_me`.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `run_id` | string | 16-char hex run identifier |
| `cwe_id` | string | CWE identifier, e.g. `"CWE-122"` |
| `spec_id` | string | `seed_id` from the input seed artifact |
| `seed` | integer | Integer seed for this run |
| `validation_passed` | boolean | Whether the Validator accepted the mutation |
| `mutations` | array | Applied mutation records (see §4.1) |

In dry-run mode: `mutations = []`, `validation_passed = false`.

### §4.1 Mutation record

| Field | Type | Description |
|---|---|---|
| `file` | string | Relative path from source tree root |
| `line` | integer (≥1) | 1-based line of primary insertion point |
| `mutation_type` | string | Mutation strategy identifier |
| `original_fragment` | string | Source fragment before mutation |
| `mutated_fragment` | string | Source fragment after mutation (the vulnerability) |
| `extra` | object | Optional mutation-specific metadata |

### Stability guarantee

Once `schema_version = "1.0"` is finalised, no fields will be removed and no
existing field types will change without a version bump to `"2.0"`.

---

## §5 audit.json

Schema: `schemas/audit_record.json` (version 1.0)
Pipeline stage: Auditor provenance output

Complete provenance record for a run. Contains everything needed to reproduce or
verify the run's inputs and pipeline version.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `run_id` | string | 16-char hex run identifier |
| `seed` | integer | Integer seed |
| `spec_path` | string | Path to the seed/spec file at time of run |
| `spec_hash` | string | SHA-256 hex of the seed/spec file contents |
| `source_root` | string | Path to source tree root |
| `source_hash` | string | Content hash of source tree (or `"dry-run"`) |
| `pipeline_version` | string | insert_me package version |
| `timestamp_utc` | string | ISO 8601 UTC timestamp |
| `validation_verdict` | object | Validator result summary (see §5.1) |

### §5.1 validation_verdict

```json
{
  "passed": false,
  "checks": [
    { "name": "syntax", "status": "pass" },
    { "name": "non_trivial", "status": "pass" }
  ]
}
```

`status` is one of: `"pass"`, `"fail"`, `"skip"`.

---

## §6 labels.json (optional)

Produced only when the LLM adapter is enabled and `auditor.write_labels = true`.
**Absence of this file never indicates a broken run.**

Schema: `schemas/labels.json` (version 1.0) — not yet defined; consumers must check `schema_version`.

### Fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `run_id` | string | Links to ground_truth.json and audit.json |
| `adapter` | string | LLM adapter name used for enrichment |
| `model` | string | Model identifier (adapter-specific) |
| `enrichments` | array | Per-mutation enrichment records (see §6.1) |

### §6.1 Enrichment record

| Field | Type | Description |
|---|---|---|
| `mutation_index` | integer | Index into `ground_truth.json` mutations array |
| `description` | string | Natural-language description of the vulnerability |
| `realism_score` | number or null | 0.0–1.0 plausibility estimate |
| `tags` | array of strings | Semantic tags |

---

## Cross-artifact linking

All artifacts share the same `run_id`. This is the stable key for joining records
across artifacts and for referencing a specific run in external systems.

The `plan_id` in `patch_plan.json` is echoed in `validation_result.json` to link
the two artifacts explicitly.

---

## Input artifact

### seed.json

Schema: `schemas/seed.schema.json` (version 1.0)

The canonical input to the pipeline. Contains the seed integer, CWE class,
mutation strategy, and target constraints in one versioned artifact.

See `examples/seeds/` for examples of each supported CWE class.

Key required fields:

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `seed_id` | string | Unique identifier for this seed definition |
| `seed` | integer | Deterministic seed integer |
| `cwe_id` | string | CWE identifier (e.g. `"CWE-122"`) |
| `vulnerability_class` | string | Human-readable class name |
| `mutation_strategy` | string | Strategy the Seeder/Patcher will apply |
| `target_pattern` | object | Pattern the Seeder uses to find candidates |

---

## Downstream compatibility

### check_me

`check_me` should consume `ground_truth.json` to know what to look for, and
`audit.json` to verify provenance. It must not require `labels.json`.

### bench_me

`bench_me` should consume `ground_truth.json` for labelling and `bad/` + `good/`
trees as the analysis targets. `audit.json` provides reproducibility metadata.

### validate-bundle

Run `insert-me validate-bundle output/<run-id>/` to verify that all present
artifacts in a bundle conform to their schemas. This command is safe to run on
any bundle, including dry-run bundles.

### Corpus indexing

A corpus-level `corpus_index.json` (future, Phase 9) will aggregate `run_id`
values and bundle paths across a directory of runs.
