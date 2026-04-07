# Roadmap — insert_me

---

## Guiding Principles

- **Deterministic core first.** Never block the core pipeline on an LLM feature.
- **Focused scope.** `insert_me` = Juliet-derived seeded vulnerability insertion + per-project
  detector evaluation against inserted ground truth. `bench_me` = cross-tool benchmark harness
  on standardized datasets. These responsibilities are separate and must not bleed into each other.
- **Artifact contracts before logic.** Define and freeze output schemas before building the
  generators. Downstream tools depend on stable schemas.
- **Working beats complete.** A pipeline that produces one correct bad/good pair end-to-end
  is more valuable than ten half-built features.

---

## Phase 0 — Foundation ✓ COMPLETE

**Goal:** Repository scaffold, documentation, and skeleton code only.

- [x] Repository structure and directory layout
- [x] README.md — identity, philosophy, portability contract
- [x] ARCHITECTURE.md — pipeline design, module map, LLM boundary
- [x] ROADMAP.md — this document
- [x] Package init, CLI placeholder, config skeleton, schema skeleton
- [x] LLM adapter interface stub (NoOpAdapter only)
- [x] Artifact path helper skeleton
- [x] Pipeline stage stubs (Seeder, Patcher, Validator, Auditor)
- [x] JSON schemas (initial drafts for ground_truth, audit_record)
- [x] Artifact contracts doc

---

## Phase 1 — Artifact Contracts and Schema Freeze ✓ COMPLETE

**Goal:** Lock down the full artifact contract set before building generators.
All schemas are now defined, validated, and tested.

- [x] `seed.schema.json` v1.0 — full seed/case definition schema
- [x] `patch_plan.schema.json` v1.0 — Seeder output: planned transformations
- [x] `validation_result.schema.json` v1.0 — Validator output: plausibility verdict
- [x] `audit_result.schema.json` v1.0 — Auditor classification: VALID/NOOP/AMBIGUOUS/INVALID
- [x] `vuln_spec.json` v1.0 — ground truth mutation annotation (from Phase 0)
- [x] `audit_record.json` v1.0 — provenance record (from Phase 0)
- [x] Example seed files: CWE-122, CWE-416, CWE-190
- [x] Example expected outputs: patch_plan, validation_result (pass+fail), audit_result (valid+ambiguous)
- [x] Implement `schema.py` — full loading, validation, bundle checking, example loading
- [x] 64 schema tests passing (loading, valid examples pass, invalid inputs fail)
- [x] Artifact contracts fully documented in `docs/artifact_contracts.md`

**Exit criterion met:** All example artifacts pass schema validation. All deliberate violations are rejected.

---

## Phase 2 — Contract Reconciliation + Deterministic Dry-Run Pipeline ✓ COMPLETE

**Goal:** Reconcile all input/output contracts into one canonical interface and
implement a minimal deterministic end-to-end dry-run pipeline that produces
schema-valid output bundles without real AST mutation.

### Contract reconciliation

- [x] Establish `--seed-file PATH` as the canonical primary CLI input
      (seed JSON encodes seed integer + CWE spec in one versioned artifact)
- [x] Keep `--seed INT --spec PATH` as a backward-compatible legacy fallback
- [x] Update all docs (README, ARCHITECTURE, ROADMAP, docs/artifact_contracts.md)
      to reflect the canonical interface
- [x] Add `patch_plan.json`, `validation_result.json`, `audit_result.json` to
      `BundlePaths` (they were documented but not covered by path helpers)
- [x] Promote the five core artifacts to `_BUNDLE_ARTIFACT_MAP` in `schema.py`
      (they were in the "optional" map despite being produced by every run)
- [x] Implement `load_config()` and `apply_cli_overrides()` (were stubs)

### Dry-run pipeline

- [x] Implement `run_pipeline()` — deterministic dry-run producing all five artifacts
- [x] Add `derive_run_id_from_seed_data()` — canonical run ID derivation from seed JSON
- [x] Artifact emit order: patch_plan → validation_result → audit_result → ground_truth → audit
- [x] Each artifact is schema-validated immediately after writing
- [x] Implement `_cmd_run()` in CLI — wires config loading → pipeline → output report
- [x] Implement `_cmd_validate_bundle()` in CLI — calls `validate_bundle()` + reports errors
- [x] Implement `_cmd_audit()` in CLI — pretty-prints audit.json

### Tests

- [x] Canonical input loading (seed file)
- [x] Run ID determinism (same inputs → same ID; different inputs → different ID)
- [x] Dry-run bundle creation (all five artifacts emitted, dirs created)
- [x] Artifact field correctness (status, classification, cwe_id, etc.)
- [x] Cross-artifact run_id and plan_id consistency
- [x] Artifact schema validation for every emitted file
- [x] validate-bundle success on a generated dry-run bundle
- [x] validate-bundle failure on a corrupted bundle
- [x] CLI end-to-end (subprocess): run, validate-bundle, error cases
- [x] Legacy input path (--seed + --spec)

**Exit criterion met:** `insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json --source .`
produces a complete, schema-valid output bundle in `output/<run-id>/`. `insert-me validate-bundle output/<run-id>/` exits 0.

---

## Phase 3 — Seeder (Deterministic) ✓ COMPLETE

**Goal:** Given a seed file, produce a deterministic ranked list of patch targets
from a real C/C++ source tree.

- [x] Define `PatchTarget` and `PatchTargetList` dataclasses
- [x] Implement lexical/regex source scanning (no AST parser required for heuristic phase)
- [x] Implement pattern matching for each supported `pattern_type`:
      `malloc_call`, `calloc_call`, `realloc_call`, `free_call`,
      `pointer_deref`, `array_index`, `integer_arithmetic`,
      `string_operation` (strcpy, strncpy, strcat, strncat, sprintf, gets,
      scanf, memcpy, memmove, read, recv, recvfrom),
      `format_string`, `loop_bound`, `custom` (union fallback)
- [x] Strategy-specific additive scoring (base 0.4, capped at 1.0)
- [x] Deterministic ordering: score DESC → (file, line) ASC → seed-RNG shuffle within tiers
- [x] Source tree SHA-256 hash (`source_hash`) committed to `patch_plan.json` and `audit.json`
- [x] `min_candidate_score` and `max_targets` filtering from seed `target_pattern` / `source_constraints`
- [x] Block-comment and single-line comment exclusion
- [x] Enclosing function name extraction (up to 100 lines back)
- [x] File exclude patterns (default: `*test*`, `*mock*`, `*stub*`)
- [x] `patch_plan.json` status `PLANNED` when targets found, `PENDING` when none
- [x] 56 seeder tests passing; fixture C files: `heap_ops.c`, `string_ops.c`, `ptr_ops.c`, `io_ops.c`

**Exit criterion met:** `Seeder.run()` returns a non-empty, byte-identical `PatchTargetList`
across repeated runs for the same seed + source tree. `patch_plan.json` carries real targets.

---

## Phase 4 — Patcher (Deterministic) ✓ COMPLETE (Phase 4b)

**Goal:** Apply mutations from a `PatchTargetList` to produce bad/good source trees.

### Phase 4a — complete

- [x] Define `Mutation` and `PatchResult` dataclasses
- [x] Implement `alloc_size_undercount` strategy: `malloc(<expr>)` → `malloc((<expr>) - 1)`
- [x] Implement bad/good tree copy (`_copy_tree`): good is byte-identical to original
- [x] Wire Patcher into pipeline orchestrator: real mode (default) vs dry-run (`--dry-run`)
- [x] `patch_plan.json` status `APPLIED` when mutation applied, `PLANNED` in dry-run
- [x] `ground_truth.json` populated with real `Mutation` records when applied
- [x] Strategy registry (`_STRATEGY_HANDLERS`) in place for future strategies
- [x] 32 Patcher tests passing; demo fixture produces real bad/good trees

### Phase 4b — complete

- [x] Implement `insert_premature_free` strategy (CWE-416): insert `free(ptr);` before pointer dereference
  - Arrow-operator (`ptr->field`) and star-deref (`*ptr`) pointer name extraction
  - 4-tuple handler result API (adds optional `extra` dict; backward-compatible with 3-tuple)
  - Seeder `pointer_deref` pattern enrichment: +0.25 score for prior malloc in scope, −0.20 if
    intervening free detected
  - Demo fixture: `examples/demo/src/uaf_demo.c`
  - 40 focused tests in `tests/test_patcher_cwe416.py`
- [x] `extra` dict in `Mutation` and `ground_truth.json` (e.g. `freed_pointer`)

### Phase 4c — partial

- [x] Patcher multi-line mutation support — `MultilineMutationResult` dataclass + `_MULTILINE_STRATEGY_HANDLERS` registry + `_register_multiline` decorator
- [x] Implement `remove_null_guard` strategy (CWE-476): replaces preceding null-check guard with comment; guard and dereference are on different lines (multi-line handler)
- [x] Seeder `null_guard` pattern type: matches `if (!ptr) return;` / `if (ptr == NULL) return;` etc., with scoring bonus for single-line return guards and following dereference
- [ ] Implement `integer_size_overflow` strategy (CWE-190) — guard-line removal pattern; feasible with multi-line handler now available
- [ ] Handle multi-file source trees with multiple targets across files
- [ ] Benchmark copy performance on mid-size source trees (~100k LOC)

Note: `source_hash` is already computed by the Seeder and written to
`patch_plan.json` and `audit.json`. No placeholder removal needed.

**Phase 4b exit criterion met:** two strategies implemented (`alloc_size_undercount`,
`insert_premature_free`); good/bad trees are written; 335 tests pass.

**Note:** `insert_double_free` (CWE-415) and `remove_free_call` (CWE-401) were implemented in Phase 8 (CWE Coverage Expansion), not Phase 4c.

**Phase 4c partial exit criterion met:** multi-line handler infrastructure in place; `remove_null_guard` (CWE-476) implemented and tested (30 tests); 468 total tests passing.

---

## Phase 5 — Validator (Rule-Based) ✓ COMPLETE

**Goal:** Automated plausibility checking of patch results.

- [x] Implement five deterministic rule-based checks (no compiler required):
      `mutation_applied`, `good_tree_integrity`, `bad_tree_changed`,
      `mutation_scope`, `simple_syntax_sanity`
- [x] Populate `validation_result.json` with real check results
- [x] Wire Validator into pipeline orchestrator (real mode runs checks; dry-run → SKIP)
- [x] Drive `audit_result.json` classification from Validator verdict:
      VALID (PASS), INVALID (FAIL), AMBIGUOUS (SKIP + mutations), NOOP (no mutations)
- [x] Set `ground_truth.json` `validation_passed` from real verdict
- [x] 29 Validator tests passing

**Exit criterion met:** Validator correctly rejects known-bad mutations and passes known-good ones
in fixture tests. `validation_result.json` carries real check results. `audit_result.json`
classification reflects Validator output.

---

## Phase 6 — Auditor minimal slice ✓ COMPLETE

**Goal:** Real Auditor that writes `ground_truth.json`, `audit.json`, and `audit_result.json`
from actual pipeline state.

- [x] Implement `Auditor.run()` — no longer raises `NotImplementedError`
- [x] Write `ground_truth.json` from real `PatchResult.mutations` + Validator verdict
- [x] Write `audit.json` with full provenance (spec path/hash, source hash, pipeline version, timestamp)
- [x] Write `audit_result.json` with classification derived from Validator verdict:
      `VALID` (PASS), `INVALID` (FAIL), `AMBIGUOUS` (SKIP + mutations), `NOOP` (no mutations)
- [x] Schema-validate all three artifacts before writing
- [x] Honest dry-run: empty mutations, `validation_passed=false`, `NOOP` classification
- [x] `labels.json` deferred to Phase 7 (LLM adapter not invoked; clearly documented)
- [x] 32 Auditor tests passing; 15 hardening tests (cross-artifact coherence, INVALID path, validate-bundle failure); 14 config tests (compatibility shim, dead-field removal); CLI smoke test proves complete demo bundle; 40 CWE-416 tests (335 total)

**Note:** Run ID derivation using full source tree hash was already implemented in
Phase 3 (Seeder computes `source_hash`; orchestrator derives `run_id` from seed JSON +
source path + pipeline version).  No additional work needed.

**Exit criterion met:** `insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json --source examples/demo/src`
produces a complete, schema-valid output bundle with `audit_result.json` classification `VALID`.

**Note:** As of Phase 7A, the overall test count is ~360 (335 existing + ~25 evaluator tests).

---

## Phase 7A — Juliet identity + per-project evaluation foundation ✓ COMPLETE

**Goal:** Document the Juliet design contract governing insert_me mutations and implement
the per-project evaluation framework.

- [x] Juliet design contract documented: `docs/juliet_design_contract.md`
- [x] Target product sentence established and propagated to README and docs
- [x] 4 evaluation JSON schemas (draft-07): `detector_report`, `match_result`, `coverage_result`, `adjudication_result`
- [x] `src/insert_me/pipeline/evaluator.py` — Evaluator class with 3-level match logic (exact/family/semantic/no_match)
- [x] CWE family mapping (18 CWEs across 9 families) + semantic keyword hints
- [x] `emit_match_result()` and `emit_coverage_result()` free functions
- [x] `SCHEMA_DETECTOR_REPORT`, `SCHEMA_MATCH_RESULT`, `SCHEMA_COVERAGE_RESULT`, `SCHEMA_ADJUDICATION_RESULT` constants in `schema.py`
- [x] Evaluation artifact paths added to `BundlePaths` in `artifacts.py`
- [x] `insert-me evaluate` CLI subcommand
- [x] Example evaluation fixtures: `examples/evaluation/` (exact/family/no_match reports)
- [x] `docs/artifact_contracts.md` updated: §7 evaluation artifacts + Evaluation Flow section
- [x] README, ROADMAP, ARCHITECTURE, examples/README updated
- [x] `tests/test_evaluator.py` — 10 test classes covering all match levels, schema validation, CLI, coverage stats
- [x] ~360 tests passing

**Exit criterion met:** `insert-me evaluate --bundle output/<run-id>/ --tool-report examples/evaluation/exact_match_report.json --tool cppcheck-demo`
produces `match_result.json` (match_level=exact) and `coverage_result.json` (coverage_rate=1.0).

---

## Phase 7B-prep — Deterministic Semantic Adjudication Baseline COMPLETE

**Goal:** Make the evaluation pipeline fully usable without an LLM, while preparing a clean
plug-in point for a future internal LLM adjudicator.

- [x] `AdjudicatorBase` ABC with `adjudicator_name` property and `adjudicate(cases)` method
- [x] `DisabledAdjudicator` — no-op, returns `[]`, `adjudication_result.json` not written
- [x] `HeuristicAdjudicator` — deterministic offline scoring (default for `insert-me evaluate`):
      +0.20 same file basename, +0.15 line ±10, +0.30 CWE family, +0.20 keyword density, +0.15 strategy keyword
      MATCH ≥ 0.65 / UNRESOLVED ≥ 0.30 / NO_MATCH < 0.30
- [x] `LLMAdjudicator` — Phase 7B placeholder (raises `NotImplementedError`)
- [x] `Evaluator` accepts optional `adjudicator=` parameter (default `HeuristicAdjudicator()`)
- [x] Adjudication verdicts written into `MatchRecord.adjudication_verdict`
- [x] `match_result.json` includes `adjudication` block and `adjudication_pending=False` when resolved
- [x] `coverage_result.json` includes `adjudication_summary` when semantic cases adjudicated
- [x] `adjudication_result.json` written only when verdicts exist
- [x] `--adjudicator [disabled|heuristic]` flag on `insert-me evaluate` (default: heuristic)
- [x] Example fixtures: `semantic_match_report.json`, `semantic_unresolved_report.json`
- [x] 406 tests passing

**Exit criterion met:** `insert-me evaluate` runs fully offline with deterministic adjudication.
Semantic matches produce `adjudication` blocks in `match_result.json` and `adjudication_summary`
in `coverage_result.json`. `adjudication_result.json` is written when heuristic runs.

---

## Phase 7B — LLM Adjudicator (Semantic Match Resolution) REMAINING

**Goal:** Pluggable LLM adjudicator for semantic match cases and optional label enrichment.

- [ ] Implement one real `LLMAdjudicator` adapter (HTTP endpoint, OpenAI-compatible API)
- [ ] Wire into Auditor as optional enrichment step for `labels.json`
- [ ] Write tests: (a) `DisabledAdjudicator` produces valid output, (b) swapping adjudicators
  does not change `ground_truth.json`, `audit.json`, or `coverage_rate`

**Exit criterion:** `--adjudicator disabled` and `--adjudicator heuristic` both work.
All deterministic artifacts are byte-identical in both modes.

---

## Phase 8 — CWE Coverage Expansion ✓ COMPLETE

**Goal:** Expand the supported vulnerability class set beyond the initial 1–3 CWEs.

- [x] Audit existing mutation strategies for generalizability (free_call quality penalties added to Seeder)
- [x] Implement `insert_double_free` strategy (CWE-415): inserts duplicate `free(ptr);` before existing free
- [x] Implement `remove_free_call` strategy (CWE-401): replaces `free(ptr);` with memory-leak comment
- [x] Seeder free_call quality penalties: −0.20 conditional guard, −0.30 inside loop body, −0.50 complex arg expression
- [x] Add second sandbox target (`examples/sandbox_targets/target_b/src/` — 3 files: dynarray, bstree, strmap)
- [x] Seed files under `examples/seeds/sandbox/` (40 seeds) and `examples/seeds/target_b/` (15 seeds)
- [x] 100% accept rate on both sandbox targets (0 REJECT across all 55 seeds)
- [x] Regression tests for CWE-415 and CWE-401 in `tests/test_patcher_cwe415_cwe401.py`
- [x] `generate_corpus.py` and `check_reproducibility.py` — strategy catalog updated to include all 4 strategies
- [x] 427 tests passing at Phase 8 completion (468 total after Phase 4c partial work in same session)

**Exit criterion met:** 4 corpus-admitted strategies implemented (CWE-122/416/415/401); 55 seeds across 2 sandbox targets all ACCEPT or ACCEPT_WITH_NOTES; 55/55 reproducibility PASS across 3 runs each.

---

## Phase 9 — Corpus Generation Tooling

**Goal:** Tooling to generate large labelled corpora efficiently and support local-target pilot workflows.

- [x] Batch script (`scripts/generate_corpus.py`) — quality-gate review, duplicate detection, corpus manifest
- [x] Reproducibility script (`scripts/check_reproducibility.py`) — verifies byte-identical output across N runs
- [x] Corpus manifest (`examples/corpus_manifest.json`) aggregating all run IDs
- [x] Duplicate detection across runs (implemented in `generate_corpus.py`)
- [x] `insert-me batch` CLI subcommand (`insert-me batch --seed-dir PATH --source PATH`) — implemented in `cli.py`; dry-run mode supported; exit 0 iff all seeds produce VALID (or NOOP in dry-run)
- [x] `insert-me inspect-target` CLI subcommand — deterministic preflight suitability check for any C/C++ source tree; reports candidate counts by strategy, concentration risk, suitability tier (pilot-single / pilot-small-batch / corpus-generation)
- [x] `scripts/inspect_target.py` — standalone script wrapping the same inspection logic
- [x] `docs/local_target_pilot.md` — first-class documentation for local evaluation-only target projects
- [x] Local-target pilot test fixture (`tests/fixtures/local_target/`) and 31 focused tests (`tests/test_inspect_target.py`)
- [x] `src/insert_me/planning/` — TargetInspector, SeedSynthesizer, CorpusPlanner; target-aware seed synthesis; VIABLE/LIMITED/BLOCKED suitability tiers; deterministic allocation
- [x] `insert-me plan-corpus` CLI subcommand — count-driven corpus planning; writes `corpus_plan.json` + `seeds/*.json`; honest shortfall reporting
- [x] `insert-me generate-corpus` CLI subcommand — plan + execute; reports requested/planned/accepted/rejected counts
- [x] `schemas/corpus_plan.schema.json` — JSON Schema for corpus_plan.json artifact
- [x] `tests/test_planning.py` — 41 tests covering TargetInspector, SeedSynthesizer, CorpusPlanner, CLI plan-corpus
- [ ] Parallel execution with deterministic output (process-level parallelism)
- [ ] `corpus_index.json` format distinct from corpus manifest — deferred

---

## Explicitly Deferred (No Timeline)

| Feature | Reason deferred |
|---|---|
| GUI / web interface | Out of scope for core tool |
| Native Windows AST tooling | Linux/macOS first; portability handled via WSL or Docker |
| Automatic CWE discovery | Requires source analysis beyond current scope |
| Differential testing integration | Belongs in `check_me` or `bench_me` |
| CVE-to-spec translation | Research task, deferred to later phase |
| Multi-language support (non C/C++) | Out of scope for v1 |
| Cloud-hosted spec registry | Violates portability constraint |

---

## Minimum Viable Milestone

**MVP = Phase 6 complete. ✓ REACHED.**

An `insert_me` that can take a seed file, and a C source tree, and produce a
schema-valid output bundle (bad/good pair + ground truth + audit log) deterministically,
with no LLM required, is the minimum useful artifact.

The MVP is now complete: `insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json
--source examples/demo/src` produces a full, schema-valid bundle (bad/good pair + ground truth
+ audit log + VALID classification) with no LLM required.

**Phase 7A extends the MVP** with a per-project evaluation layer: `insert-me evaluate` compares
any normalized detector report against the ground truth oracle and produces machine-readable
coverage statistics.
