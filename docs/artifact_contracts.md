# Artifact Contracts — insert_me

This document is the **authoritative specification** for all artifacts produced and
consumed by `insert_me`. Downstream tools (`check_me`, `bench_me`, human reviewers)
must treat this document as ground truth.

Schema files are in `schemas/`. Use the `SCHEMA_*` constants in `insert_me.schema`
when referencing schemas in code — never hardcode schema names.

---

## Current Phase

**Phase 7B-prep — deterministic semantic adjudication baseline (complete).**

All four core pipeline stages are real.  In the default (real) mode the pipeline produces
actual bad/good source trees, validates the mutation with five rule-based checks, and the
Auditor writes `ground_truth.json`, `audit.json`, and `audit_result.json` from actual pipeline
state.  The `evaluate` command compares a normalized detector report against the ground
truth oracle, producing `match_result.json` and `coverage_result.json`.  Semantic matches are
now adjudicated offline by the built-in `HeuristicAdjudicator` (no LLM required), producing
`adjudication_result.json` and an `adjudication_summary` in `coverage_result.json`.
`labels.json` enrichment (Phase 7B — LLM adapter) remains deferred.

| Artifact field | Real mode (default) | Dry-run (`--dry-run`) | Future |
|---|---|---|---|
| `patch_plan.json` `status` | `APPLIED` (mutated) · `PLANNED` (skipped) · `PENDING` (no sources) | `PLANNED` / `PENDING` | N/A |
| `patch_plan.json` `targets` | Real Seeder output | Real Seeder output | N/A |
| `bad/` `good/` | Written with real source trees | Empty dirs | N/A |
| `ground_truth.json` `mutations` | Real record(s) when mutation applied | `[]` | N/A |
| `ground_truth.json` `validation_passed` | `true` when Validator passes | `false` | N/A |
| `validation_result.json` `overall` | `PASS` / `FAIL` / `SKIP` | `SKIP` | N/A |
| `validation_result.json` `checks` | Real check results (5 checks) | `[]` | N/A |
| `audit_result.json` `classification` | `VALID` (pass) · `INVALID` (fail) · `AMBIGUOUS` (skip+mut) · `NOOP` | `NOOP` | N/A |
| `audit.json` `validation_verdict.passed` | Real verdict | `false` | N/A |

---

## Output Bundle Layout

A single `insert_me run` produces one **output bundle** under `output/<run-id>/`:

```
output/<run-id>/
├── bad/                      Mutated C/C++ source tree  (written in real mode; empty in dry-run)
├── good/                     Clean C/C++ source tree    (written in real mode; empty in dry-run)
├── patch_plan.json           Seeder output: planned transformations (§1)
├── validation_result.json    Validator output: plausibility verdict (§2)
├── audit_result.json         Classification: VALID/NOOP/AMBIGUOUS/INVALID (§3)
├── ground_truth.json         Vulnerability annotation (§4)
├── audit.json                Provenance record (§5)
├── labels.json               (optional) LLM-enriched semantic labels (§6)
├── match_result.json         (optional) Per-mutation match evaluation (§7, evaluate command)
├── coverage_result.json      (optional) Coverage statistics (§7, evaluate command)
└── adjudication_result.json  (optional) Adjudicator verdicts for semantic matches (§7.4)
```

In real mode (default), `bad/` and `good/` contain the mutated and original source trees.
In dry-run mode (`--dry-run`), both directories are created but left empty.

The `<run-id>` is a 16-character hex string derived deterministically from:
`SHA-256(canonical_seed_json || source_tree_path || pipeline_version)[:16]`

All five core artifacts (`patch_plan`, `validation_result`, `audit_result`,
`ground_truth`, `audit`) are produced by every run.
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
| `plan_id` | string | Deterministic identifier for this plan (`plan-<run_id>`) |
| `run_id` | string | 16-char hex run identifier |
| `seed_id` | string | `seed_id` from the input seed artifact |
| `seed` | integer | Integer seed (carried from seed artifact) |
| `status` | string | `PENDING` / `PLANNED` / `APPLIED` / `ABORTED` |
| `created_at` | string | ISO 8601 UTC timestamp |
| `targets` | array | Ordered list of planned patch targets (see §1.1) |
| `skipped_candidates` | integer | Candidates found but filtered out (below min_score or beyond max_targets) |
| `source_tree_hash` | string | 16-char hex SHA-256 of the source file set (same as `audit.json` `source_hash`) |

**`status` semantics in current phase:**
- `PLANNED` — Seeder found at least one candidate meeting the score threshold.
- `PENDING` — No qualifying candidates (source tree empty, no C/C++ files, or all
  candidates below `min_candidate_score`).

`APPLIED` is produced by the Patcher when a mutation is successfully written.
`ABORTED` is reserved for future use (no abort path is currently implemented).

### §1.1 Target record

Each entry in `targets`:

| Field | Type | Description |
|---|---|---|
| `target_id` | string | Stable local identifier within this plan (e.g. `"t0001"`) |
| `file` | string | Source file path relative to source tree root |
| `line` | integer (≥1) | 1-based line number of primary mutation point |
| `mutation_strategy` | string | Strategy the Patcher will apply (from seed file) |
| `candidate_score` | number (0–1) | Plausibility score assigned by the Seeder |
| `context` | object | Lexical context: `expression` (matched line) + `function_name` |

---

## §2 validation_result.json

Schema: `schemas/validation_result.schema.json` (version 1.0)
Pipeline stage: Validator output

Rule-based plausibility verdict on the applied mutations. Fully deterministic — no LLM involved.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `result_id` | string | Deterministic identifier for this result (`vr-<run_id>`) |
| `run_id` | string | 16-char hex run identifier |
| `plan_id` | string | Links to the patch_plan that was validated |
| `overall` | string | `PASS` / `FAIL` / `SKIP` |
| `checks` | array | Per-check results (see §2.1) |
| `notes` | string | Optional note (used in current phase to explain SKIP) |

**Real mode (default):** `overall` is `PASS` / `FAIL` based on the five rule-based checks. `checks` contains one record per check.

**Dry-run mode:** `overall = "SKIP"`, `checks = []`.

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
| `audit_id` | string | Deterministic identifier for this audit (`ar-<run_id>`) |
| `run_id` | string | 16-char hex run identifier |
| `classification` | string | `VALID` / `NOOP` / `AMBIGUOUS` / `INVALID` |
| `confidence` | string | `high` / `medium` / `low` |
| `evidence` | array | Evidence items supporting the classification (see §3.1) |
| `reviewer` | object | `{ "type": "deterministic", "name": "<reviewer_id>" }` |

**Real mode (default):** Classification is derived from the Validator verdict:
- `VALID` (`confidence = "medium"`) — mutations applied and Validator passed all checks
- `INVALID` (`confidence = "medium"`) — mutations applied but Validator failed at least one check
- `AMBIGUOUS` (`confidence = "low"`) — mutations applied but Validator skipped (edge case)
- `NOOP` (`confidence = "low"`) — no mutations applied (dry-run or no qualifying targets)

**Dry-run mode:** `classification = "NOOP"`, `confidence = "low"`.

Reviewer is always `{ "type": "deterministic", "name": "auditor_phase6_v1" }` in the current phase.

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

**Current phase:** In real mode, `mutations` contains actual mutation records from the
Patcher and `validation_passed` reflects the Validator verdict.  In dry-run mode,
`mutations = []` and `validation_passed = false`.

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
| `source_hash` | string | 16-char hex SHA-256 of the source file set, or `"no-sources"` if no C/C++ files were found |
| `pipeline_version` | string | insert_me package version |
| `timestamp_utc` | string | ISO 8601 UTC timestamp |
| `validation_verdict` | object | Validator result summary (see §5.1) |

`source_hash` is computed by the Seeder over all discovered C/C++ source files
(sorted relative paths + file byte contents). It is identical to `patch_plan.json`
`source_tree_hash`.

### §5.1 validation_verdict

```json
{
  "passed": true,
  "checks": [
    {"name": "mutation_applied", "status": "pass"},
    {"name": "good_tree_integrity", "status": "pass"},
    {"name": "bad_tree_changed", "status": "pass"},
    {"name": "mutation_scope", "status": "pass"},
    {"name": "simple_syntax_sanity", "status": "pass"}
  ]
}
```

`checks` is an array of `{ "name": string, "status": "pass"|"fail"|"skip"|"error" }` objects.
In **real mode**, `passed` reflects the actual Validator verdict and `checks` lists each of the five
rule-based checks. In **dry-run mode**, `passed = false` and `checks = []`.

---

## §6 labels.json (optional)

Produced only when the LLM adapter is enabled and `auditor.write_labels = true`.
**Absence of this file never indicates a broken run.**

Schema: `schemas/labels.json` — schema file is not yet defined. Consumers must check
`schema_version` before parsing. The LLM enrichment layer is planned for Phase 7.

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

`source_hash` in `audit.json` and `source_tree_hash` in `patch_plan.json` are the
same value, both derived from the Seeder's source scan.

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

## §7 Evaluation artifacts (Phase 7A)

These three artifacts are produced by `insert-me evaluate` and are **never** produced
by the core `insert-me run` pipeline. They are optional: absence of these files never
indicates a broken run bundle.

### §7.1 detector_report_ref

The input to evaluation. A normalized detector report in `detector_report.schema.json` format.
This file is **not written into the bundle** — it is provided by the caller at evaluation time.

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `tool` | string | Detection tool name |
| `findings` | array | List of findings (see schema for per-finding fields) |

Each finding has a required `file` field and optional `line`, `cwe_id`, `severity`, `message`, `rule_id`.

### §7.2 match_result.json

Schema: `schemas/match_result.schema.json` (version 1.0)

Per-mutation match evaluation. One `matches` entry per mutation in `ground_truth.mutations`.

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `run_id` | string | Links to the evaluated bundle |
| `tool` | string | Detection tool name |
| `evaluated_at` | string | ISO 8601 UTC timestamp |
| `mutations_evaluated` | integer | Count of mutations evaluated |
| `matches` | array | Per-mutation match records (see §7.2.1) |

#### §7.2.1 Match record

| Field | Type | Description |
|---|---|---|
| `mutation_index` | integer | Index into `ground_truth.mutations` |
| `mutation_type` | string | Mutation strategy identifier |
| `file` | string | Relative path of mutated file |
| `line` | integer | Mutation line number |
| `cwe_id` | string | CWE of the inserted vulnerability |
| `match_level` | string | `exact` / `family` / `semantic` / `no_match` |
| `matched_finding` | object or null | The finding that matched, or null |
| `rationale` | string | Human-readable explanation |
| `adjudication_pending` | boolean | `true` when semantic match exists but adjudicator was disabled; `false` (field present) when verdict was produced |
| `adjudication` | object | Present when adjudicator ran; see §7.2.2 |

**Match level semantics:**

| Level | Condition |
|---|---|
| `exact` | Same file basename + same CWE ID + finding line within ±2 of mutation line |
| `family` | Mutation CWE and finding CWE share a CWE family group |
| `semantic` | Keyword from mutation's CWE family found in finding message |
| `no_match` | No finding matched at any level |

#### §7.2.2 adjudication block (semantic matches only)

Present in a match record when the adjudicator produced a verdict.

| Field | Type | Description |
|---|---|---|
| `verdict` | string | `match` / `no_match` / `unresolved` |
| `confidence` | number (0–1) | Normalized score from the adjudicator |
| `rationale` | string | Signal-level explanation (e.g. matched signals and weights) |
| `adjudicator` | string | `"heuristic"` · `"llm"` · custom name |

### §7.3 coverage_result.json

Schema: `schemas/coverage_result.schema.json` (version 1.0)

Summary statistics across all mutations.

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `run_id` | string | Links to the evaluated bundle |
| `tool` | string | Detection tool name |
| `evaluated_at` | string | ISO 8601 UTC timestamp |
| `total_mutations` | integer | Total mutations from `ground_truth.json` |
| `matched` | integer | Mutations with level exact/family/semantic |
| `unmatched` | integer | Mutations with level no_match |
| `false_positives` | integer | Findings not linked to any mutation |
| `coverage_rate` | number (0–1) | `matched / total_mutations` |
| `by_level` | object | Per-level counts: `exact`, `family`, `semantic`, `no_match` |
| `adjudication_summary` | object | Present when semantic cases were adjudicated (see below) |

**adjudication_summary** (present only when adjudicator != disabled and semantic matches exist):

| Field | Type | Description |
|---|---|---|
| `adjudicator` | string | Adjudicator identifier, e.g. `"heuristic"` |
| `match` | integer | Semantic cases adjudicated as MATCH |
| `unresolved` | integer | Semantic cases adjudicated as UNRESOLVED |
| `no_match` | integer | Semantic cases adjudicated as NO_MATCH |

### §7.4 adjudication_result.json

Schema: `schemas/adjudication_result.schema.json` (version 1.0)

Written only when the adjudicator produced verdicts (i.e. adjudicator != disabled and semantic
matches exist). Absence is never an error. Written by both `HeuristicAdjudicator` (default)
and any future `LLMAdjudicator`.

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `run_id` | string | Links to the evaluated bundle |
| `tool` | string | Detection tool name |
| `adjudicator` | string | Adjudicator identifier: `"heuristic"` · `"llm"` · custom |
| `cases` | array | Per-case adjudication records |

Each case: `mutation_index`, `finding_id` (string or null), `verdict` (`match`/`no_match`/`unresolved`),
`confidence` (0–1), `rationale`.

**HeuristicAdjudicator scoring signals** (default adjudicator):

| Signal | Weight |
|---|---|
| Same file basename (mutation vs finding) | +0.20 |
| Finding line within ±10 of mutation line | +0.15 |
| Finding CWE maps to same family as mutation CWE | +0.30 |
| CWE-family keyword hits in message (`min(hits × 0.10, 0.20)`) | +0.20 max |
| Strategy-specific keyword in message | +0.15 |

Verdict thresholds: MATCH ≥ 0.65 · UNRESOLVED ≥ 0.30 · NO_MATCH < 0.30

---

## Evaluation Flow

```
[output bundle]          ← existing insert_me run output
    ground_truth.json    ← oracle: what was inserted, where, which CWE
         │
         ▼
insert-me evaluate \
  --bundle output/<run-id>/ \
  --tool-report report.json \    ← normalized detector report (detector_report.schema.json)
  --tool cppcheck \
  [--adjudicator heuristic|disabled]   (default: heuristic)
         │
         ▼
  Evaluator.run()
    For each mutation in ground_truth.mutations:
      Try exact match  → same file basename + same CWE + line ±2
      Try family match → same CWE family group
      Try semantic match → keyword in finding message
      Else: no_match
         │
         ▼
  Adjudicator.adjudicate(pending_cases)     ← HeuristicAdjudicator by default
    For each semantic match:
      Score signals → MATCH / UNRESOLVED / NO_MATCH
         │
         ├── match_result.json      ← per-mutation detail (adjudication block added)
         ├── coverage_result.json   ← summary + adjudication_summary
         └── adjudication_result.json  ← written only when verdicts exist
```

With `--adjudicator disabled`, the adjudication step is skipped: semantic matches are flagged
as `adjudication_pending=True` in `match_result.json` and `adjudication_result.json` is not written.

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
artifacts in a bundle conform to their schemas. Safe to run on any bundle,
including current-phase bundles.

### Corpus indexing

A corpus-level `corpus_index.json` (future, Phase 9) will aggregate `run_id`
values and bundle paths across a directory of runs.
