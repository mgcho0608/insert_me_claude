# insert_me

**Deterministic, project-scale seeded vulnerability generation for C/C++.**

> **Repository:** `insert_me_claude` is the public incubation repository for the `insert_me`
> package. The package name, CLI command (`insert-me`), and all artifact identities are
> `insert_me` throughout. The `_claude` suffix in the repository name reflects its origin as
> a Claude-assisted build and carries no meaning for end users or downstream integrators.
> When this project moves to a production home, the `insert_me` package identity is what carries forward.

---

## Current Status — Phase 9 (corpus generation tooling and multi-sandbox expansion)

| | |
|---|---|
| **Canonical interface** | `insert-me run --seed-file PATH --source PATH` |
| **Default mode** | Real patching + validation + audit |
| **Dry-run mode** | `--dry-run` flag — all artifacts emitted, no source modifications |
| **Artifacts emitted** | All 5 core artifacts, schema-validated on every run |
| **`patch_plan.json` status** | `APPLIED` (mutation applied) · `PLANNED` (dry-run/no compatible target) · `PENDING` (no C/C++ sources found) |
| **`ground_truth.json` mutations** | Real record when mutation applied; `[]` in dry-run |
| **`ground_truth.json` validation_passed** | `true` when Validator passes; `false` in dry-run |
| **`bad/` `good/` source trees** | Written in real mode; empty dirs in dry-run |
| **Mutation strategies** | `alloc_size_undercount` — `malloc(<expr>)` → `malloc((<expr>) - 1)` (CWE-122) · `insert_premature_free` — inserts `free(ptr);` before a pointer dereference (CWE-416) · `insert_double_free` — inserts duplicate `free(ptr);` before an existing free (CWE-415) · `remove_free_call` — replaces `free(ptr);` with a memory-leak comment (CWE-401) |
| **`validation_result.json`** | Real check results (5 checks) in real mode; `overall: SKIP` in dry-run |
| **`audit_result.json`** | `VALID` (validator pass) · `INVALID` (fail) · `AMBIGUOUS` (skip+mutations) · `NOOP` (no mutations) |
| **Evaluation strategy** | `exact` / `family` / `semantic` / `no_match` — per-mutation match against inserted ground truth |
| **Adjudicator** | `HeuristicAdjudicator` (default, offline) · `DisabledAdjudicator` · `LLMAdjudicator` (Phase 7B placeholder) |

---

## What it is

insert_me is a deterministic, Juliet-derived seeded vulnerability insertion and per-project evaluation framework for C/C++ codebases. It inserts auditable bad/good variants into arbitrary target projects and evaluates how well a detector report matches the inserted ground truth. Semantic matches are adjudicated offline by the built-in heuristic adjudicator (no LLM required); a plug-in point for a future internal LLM adjudicator is available but not yet wired.

Given a seed definition and a C/C++ source tree, it produces:

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

## Internal Reuse — Quick Reference

For engineers picking this up for the first time inside an organisation:

| | |
|---|---|
| **What it is** | A Python CLI that inserts one known vulnerability into a C/C++ source tree and produces a fully annotated, schema-validated output bundle. |
| **Current maturity** | Phase 9 complete — all four core pipeline stages + evaluator + deterministic heuristic adjudicator + 4 mutation strategies (CWE-122/416/415/401) + 2 sandbox targets + corpus generation tooling implemented and tested (427 tests). Not production-hardened; alpha-quality. |
| **Install path** | `pip install -e .` from source. No PyPI release exists yet. |
| **Python versions** | 3.11, 3.12 — **CI-tested**. 3.10 — **statically reviewed only** (single shim: `tomllib` → `tomli`). No other version-specific features used. |
| **Dependencies** | `jsonschema>=4.17` + `tomli>=1.2.0` on Python 3.10 only. No other mandatory runtime dependencies. |
| **Network access** | None required for core operation. All schema validation ships with the package. |
| **License** | **Undecided.** See `NOTICE.txt`. Internal/research use only. Do not redistribute without explicit permission. |
| **First command** | `pip install -e . && insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json --source examples/demo/src` |

**What to expect from a run today:**
- One mutation applied to the source tree (`alloc_size_undercount` for CWE-122, `insert_premature_free` for CWE-416, `insert_double_free` for CWE-415, `remove_free_call` for CWE-401)
- Five deterministic rule-based plausibility checks
- Five JSON artifacts: `patch_plan.json`, `validation_result.json`, `audit_result.json`, `ground_truth.json`, `audit.json`

**What is NOT available yet:**
- Additional mutation strategies (CWE-476, CWE-190) — planned; requires multi-line mutation support in Patcher
- AST-based or compiler-backed patching/validation — future phases
- Phase 7B: real LLM adjudicator (placeholder exists; `LLMAdjudicator.adjudicate()` raises `NotImplementedError`)
- `insert-me batch` CLI subcommand — scripts/generate_corpus.py covers batch use until Phase 9 CLI is complete

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

# Evaluate a detector report against the inserted ground truth
# Default: HeuristicAdjudicator runs offline for semantic matches
insert-me evaluate --bundle output/<run-id>/ \
                   --tool-report report.json \
                   --tool cppcheck \
                   [--adjudicator heuristic|disabled]
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
  │   Seeder    │  ✓ Implemented — lexical source scan → ranked PatchTargetList
  └──────┬──────┘
         │  patch_plan.json  ← patch_plan.schema.json
         ▼
  ┌─────────────┐
  │   Patcher   │  ✓ Phase 8 — alloc_size_undercount (CWE-122) · insert_premature_free (CWE-416) · insert_double_free (CWE-415) · remove_free_call (CWE-401)
  └──────┬──────┘
         │  bad/  good/  source trees
         ▼
  ┌─────────────────┐
  │    Validator    │  ✓ Phase 5 — five deterministic rule-based checks
  └──────┬──────────┘
         │  validation_result.json  ← validation_result.schema.json
         ▼
  ┌─────────────┐
  │   Auditor   │  ✓ Phase 6 — ground truth, provenance, classification
  └──────┬──────┘
         │  audit_result.json  ground_truth.json  audit.json
         ▼
  [output bundle]
    bad/  good/  + all JSON artifacts above
         │
         │  (optional, separate step)
         ▼
  ┌─────────────┐
  │  Evaluator  │  ✓ Phase 7A — match detector report against ground truth
  └──────┬──────┘    (insert-me evaluate --bundle ... --tool-report ...)
         │  match_result.json  coverage_result.json
         ▼
  ┌───────────────────┐
  │  Adjudicator      │  ✓ Phase 7B-prep — resolves semantic matches offline
  └──────┬────────────┘    HeuristicAdjudicator (default) · DisabledAdjudicator
         │  adjudication_result.json  (written only when verdicts exist)
         ▼
  [evaluation artifacts]
```

An optional LLM adapter may be invoked after the Auditor for label enrichment (`labels.json`, Phase 7B).
The adjudicator boundary is now hardened: `AdjudicatorBase` ABC accepts `HeuristicAdjudicator` (offline default),
`DisabledAdjudicator`, or a future `LLMAdjudicator`. These are side-channels — they do not modify
any deterministic artifact.

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

**What to expect today (real mode — default):**
- `patch_plan.json` — `status: "APPLIED"`, one target from `heap_buf.c`
- `ground_truth.json` — one mutation record: `malloc(user_len * sizeof(char))` → `malloc((user_len * sizeof(char)) - 1)`, `validation_passed: true`
- `bad/heap_buf.c` — mutated source (the vulnerability inserted)
- `good/heap_buf.c` — byte-identical copy of the original
- `validation_result.json` — `overall: "PASS"`, five rule-based checks all passing
- `audit_result.json` — `classification: "VALID"` (Validator confirmed plausibility)
- `validate-bundle` exits 0 — all artifacts are schema-valid

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

# Run with a seed file against any C/C++ source tree
insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json \
              --source /path/to/c-project

# Validate a completed output bundle
insert-me validate-bundle output/<run-id>/

# Show audit record
insert-me audit output/<run-id>/audit.json
```

---

## Sandbox Corpus and Quality Gate

Two sandbox targets are included with a combined 55-seed accepted corpus:

| Target | Source | Seeds | Accept rate |
|---|---|---|---|
| `sandbox_eval` | `examples/sandbox_eval/src/` (6 files) | 40 (11 CWE-122 · 19 CWE-416 · 5 CWE-415 · 5 CWE-401) | 100% |
| `target_b` | `examples/sandbox_targets/target_b/src/` (3 files) | 15 (4 CWE-122 · 5 CWE-416 · 3 CWE-415 · 3 CWE-401) | 100% |

All 55 seeds reproduce byte-identically across 3 runs each (55/55 PASS).

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

## Portability

`insert_me` is designed to be dropped into restricted enterprise environments:

- **No mandatory cloud calls.** All LLM calls are behind an optional adapter interface.
- **No mandatory internet access.** All schema validation and rule sets ship with the package.
- **Minimal dependencies.** Core pipeline uses Python stdlib + `jsonschema` (+ `tomli` on Python 3.10). See `pyproject.toml`.
- **Python 3.10–3.12.** No Python 3.11-specific features beyond `tomllib`, which is shimmed automatically.
- **Configurable via files.** All behaviour is driven by `config/` TOML files.
- **Self-contained output.** Output bundles carry everything needed for downstream tools.

To deploy in an air-gapped environment: copy the package, its dependencies, and your seed files.
No registration, no keys, no outbound calls required for core operation.

---

## License

**Undecided.** Intended for internal/research use only. Do not redistribute without explicit written permission.

See `NOTICE.txt` at the repository root for the full rights statement and a list of third-party dependency licenses.

A formal license has not yet been chosen. The `pyproject.toml` reflects this as `"Proprietary — license TBD. Internal/research use only."` and `NOTICE.txt` is bundled into any distribution until a decision is made.
