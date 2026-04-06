# insert_me

**Deterministic, project-scale seeded vulnerability generation for C/C++.**

---

## What it is

`insert_me` is a framework that **inserts known vulnerabilities into C/C++ source trees in a
controlled, reproducible, and auditable way**. Given a seed definition and a C/C++ source
tree, it produces:

- **Bad/good source pairs** — the original (good) and the mutated (bad) version side-by-side.
- **Patch plan** — the planned transformations before any source files are modified.
- **Validation artifacts** — evidence that the inserted vulnerability is syntactically and
  semantically plausible.
- **Audit result** — classification of the run (VALID / NOOP / AMBIGUOUS / INVALID).
- **Ground-truth records** — machine-readable annotations of exactly what was inserted, where,
  and why.
- **Audit outputs** — a full provenance log linking every output back to its seed, spec, and
  pipeline version.

The primary use case is generating labelled corpora for vulnerability research, detector
benchmarking, and security tooling evaluation — without relying on manual annotation or scraping
real CVEs.

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

## Core Goals

1. **Reproducibility** — The same seed file + source tree always produces the same output, byte-for-byte.
2. **Auditability** — Every output carries a complete provenance record.
3. **Portability** — Runs in air-gapped / restricted enterprise environments with zero cloud calls.
4. **Composability** — Outputs integrate cleanly with downstream tools (checkers, benchmarks, CI).
5. **LLM-agnosticism** — Any LLM-assisted step can be replaced by a weaker internal model or
   disabled entirely without breaking the core pipeline.

---

## Canonical Interface

```bash
# Primary interface (recommended)
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project

# Validate a completed output bundle
insert-me validate-bundle output/<run-id>/

# Pretty-print an audit record
insert-me audit output/<run-id>/audit.json
```

The `--seed-file` argument takes a seed JSON file (see `seed.schema.json` and `examples/seeds/`).
The seed file encodes the seed integer, CWE class, mutation strategy, and target constraints in
one versioned, schema-validated artifact.

### Legacy interface (backward-compatible)

```bash
insert-me run --seed 42 --spec specs/cwe-122.toml --source /path/to/project
```

The `--seed INT --spec PATH` form is kept for backward compatibility. For new runs,
prefer `--seed-file PATH`. The two forms are mutually exclusive.

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
[seed.json]          ← seed.schema.json (canonical input)
       │
       ▼
  ┌─────────────┐
  │   Seeder    │  Expand seed → PatchTargetList
  └──────┬──────┘
         │  patch_plan.json  ← patch_plan.schema.json
         ▼
  ┌─────────────┐
  │   Patcher   │  Apply AST-level mutations to source tree
  └──────┬──────┘
         │
         ▼
  ┌─────────────────┐
  │    Validator    │  Rule-based plausibility checks
  └──────┬──────────┘
         │  validation_result.json  ← validation_result.schema.json
         ▼
  ┌─────────────┐
  │   Auditor   │  Write ground truth, provenance, and classification
  └──────┬──────┘
         │  ground_truth.json  audit.json  audit_result.json
         ▼
  [output bundle]
    bad/  good/  + all JSON artifacts above
```

An optional LLM adapter may be invoked after the Auditor for label enrichment (`labels.json`).
This is a side-channel — it does not modify any deterministic artifact.

---

## Output Bundle Layout

For each run, `insert_me` produces an **output bundle** under `output/<run-id>/`:

```
output/
└── <run-id>/
    ├── bad/                      Mutated source tree (vulnerability inserted)
    ├── good/                     Original source tree (clean copy)
    ├── patch_plan.json           Planned transformations (schema: patch_plan)
    ├── validation_result.json    Plausibility verdict (schema: validation_result)
    ├── audit_result.json         Classification (schema: audit_result)
    ├── ground_truth.json         Mutation annotation (schema: vuln_spec)
    ├── audit.json                Provenance record (schema: audit_record)
    └── labels.json               (optional) LLM-enriched semantic labels
```

All schemas are bundled and versioned. No network access needed for validation.
Run `insert-me validate-bundle output/<run-id>/` to verify any bundle.

---

## Artifact Schemas

All inputs and outputs are defined by versioned JSON schemas in `schemas/`.
See `docs/artifact_contracts.md` for the full specification.

| Schema file | Artifact | Stage |
|---|---|---|
| `seed.schema.json` | Seed definition | **Input** |
| `patch_plan.schema.json` | Planned transformations | Seeder output |
| `validation_result.schema.json` | Plausibility verdict | Validator output |
| `audit_result.schema.json` | Classification (VALID/NOOP/AMBIGUOUS/INVALID) | Auditor output |
| `vuln_spec.json` | Ground truth annotation | Auditor structural output |
| `audit_record.json` | Provenance record | Auditor provenance output |

---

## Deterministic-First Philosophy

The entire core pipeline — seed expansion, vulnerability selection, AST-level patching, ground
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

## Quick Start

```bash
# Install (editable)
pip install -e .

# Run with a seed file (canonical)
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project

# Run in explicit dry-run mode (emits artifacts, does not modify source)
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project \
              --dry-run

# Validate a completed output bundle
insert-me validate-bundle output/<run-id>/

# Show audit record
insert-me audit output/<run-id>/audit.json
```

The current implementation runs in **dry-run mode** (all artifacts are emitted but no source
tree mutations are applied). Full AST patching is implemented in Phase 4.

---

## Portability

`insert_me` is designed to be dropped into restricted enterprise environments:

- **No mandatory cloud calls.** All LLM calls are behind an optional adapter interface.
- **No mandatory internet access.** All schema validation and rule sets ship with the package.
- **Minimal dependencies.** Core pipeline uses Python stdlib + `jsonschema`. See `pyproject.toml`.
- **Configurable via files.** All behaviour is driven by `config/` TOML files.
- **Self-contained output.** Output bundles carry everything needed for downstream tools.

To deploy in an air-gapped environment: copy the package, its dependencies, and your seed files.
No registration, no keys, no outbound calls required for core operation.

---

## License

TBD — intended for internal/research use pending license decision.
