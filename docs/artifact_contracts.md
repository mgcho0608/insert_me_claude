# Artifact Contracts — insert_me

This document specifies the complete artifact contract for all output files
produced by `insert_me`. Downstream tools (check_me, bench_me, human reviewers)
should treat this as the authoritative schema reference.

---

## Output Bundle Layout

```
output/<run-id>/
├── bad/                    Mutated C/C++ source tree (vulnerability inserted)
├── good/                   Clean C/C++ source tree (byte-identical to original)
├── ground_truth.json       Vulnerability annotation (see §1)
├── audit.json              Provenance record (see §2)
└── labels.json             (optional) LLM-enriched semantic labels (see §3)
```

The `<run-id>` is a 16-character hex string derived deterministically from:
`SHA-256(seed || spec_file_content || source_tree_hash || pipeline_version)[:16]`

---

## §1 ground_truth.json

Schema: `schemas/vuln_spec.json` (version 1.0)

Contains everything needed to understand *what* vulnerability was inserted and *where*.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `run_id` | string | 16-char hex run identifier |
| `cwe_id` | string | CWE identifier, e.g. `"CWE-122"` |
| `spec_id` | string | ID of the spec TOML used |
| `seed` | integer | Integer seed for this run |
| `validation_passed` | boolean | Whether Validator accepted the mutation |
| `mutations` | array | List of applied mutation records (see §1.1) |

### §1.1 Mutation record

Each entry in `mutations`:

| Field | Type | Description |
|---|---|---|
| `file` | string | Relative path from source tree root |
| `line` | integer | 1-based line of primary insertion point |
| `mutation_type` | string | Mutation strategy identifier |
| `original_fragment` | string | Source before mutation |
| `mutated_fragment` | string | Source after mutation (the vulnerability) |
| `extra` | object | Optional mutation-specific metadata |

### Stability guarantee

Once `schema_version = "1.0"` is finalised, no fields will be removed and no
existing field types will change without a version bump to `"2.0"`.

---

## §2 audit.json

Schema: `schemas/audit_record.json` (version 1.0)

Contains everything needed to reproduce or verify a run's provenance.

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version, e.g. `"1.0"` |
| `run_id` | string | 16-char hex run identifier |
| `seed` | integer | Integer seed |
| `spec_path` | string | Path to spec TOML at time of run |
| `spec_hash` | string | SHA-256 hex of spec file contents |
| `source_root` | string | Absolute path of source tree root |
| `source_hash` | string | Content hash of source tree |
| `pipeline_version` | string | insert_me package version |
| `timestamp_utc` | string | ISO 8601 UTC timestamp |
| `validation_verdict` | object | Validator result summary (see §2.1) |

### §2.1 validation_verdict

```json
{
  "passed": true,
  "checks": [
    { "name": "syntax",      "status": "pass", "reason": "" },
    { "name": "non_trivial", "status": "pass", "reason": "" },
    { "name": "scope",       "status": "pass", "reason": "" }
  ]
}
```

`status` is one of: `"pass"`, `"fail"`, `"skip"`.

---

## §3 labels.json (optional)

Produced only when the LLM adapter is enabled and the Auditor's `write_labels`
option is active. **Absence of this file never indicates a broken run.**

### Fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Schema version |
| `run_id` | string | Links to ground_truth.json and audit.json |
| `adapter` | string | LLM adapter name used for enrichment |
| `model` | string | Model identifier (adapter-specific) |
| `enrichments` | array | Per-mutation enrichment records (see §3.1) |

### §3.1 Enrichment record

| Field | Type | Description |
|---|---|---|
| `mutation_index` | integer | Index into ground_truth.json mutations array |
| `description` | string | Natural-language description of the vulnerability |
| `realism_score` | number or null | 0.0–1.0 plausibility estimate |
| `tags` | array of strings | Semantic tags |

### Stability note

`labels.json` schema is versioned separately and may evolve more frequently
than the core artifact schemas. Consumers must check `schema_version`.

---

## Cross-file Linking

All three artifact files share the same `run_id`. This is the stable key for
joining records across files and for referencing a specific run in external
systems (e.g. bug trackers, corpus manifests).

---

## Downstream Compatibility

### check_me

`check_me` should consume `ground_truth.json` to know what to look for, and
`audit.json` to verify provenance. It must not require `labels.json`.

### bench_me

`bench_me` should consume `ground_truth.json` for labelling and `bad/` + `good/`
trees as the analysis targets. `audit.json` provides reproducibility metadata.

### Corpus indexing

A corpus-level `corpus_index.json` (future, Phase 9) will aggregate `run_id`
values and bundle paths across a directory of runs.
