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
- [ ] Parallel execution with deterministic output (process-level parallelism) — deferred

---

## Phase 10 — CWE-476 Corpus Admission ✓ COMPLETE

**Goal:** Admit `remove_null_guard` (CWE-476) to the corpus-admitted strategy set.

- [x] Dual-mode `_mutate_remove_null_guard` handler: primary mode targets guard lines (Seeder `null_guard` pattern); backward-compat mode targets deref lines
- [x] Multi-line guard body blanking (prevents orphaned `return;` on next line)
- [x] 8 CWE-476 sandbox seeds (`examples/seeds/sandbox/cwe476_sb_001.json` through `cwe476_sb_008.json`), 8/8 VALID quality gate
- [x] `remove_null_guard` promoted to `IMPLEMENTED_AND_CORPUS_ADMITTED` in strategy catalog
- [x] `null_guard` pattern type added to `seed.schema.json` enum
- [x] `corpus_admitted=True` in `PLANNING_STRATEGIES` (inspector.py)
- [x] `_STRATEGY_PASS_RATE["remove_null_guard"]` = 1.00 in corpus_planner.py
- [x] 570 tests passing

---

## Phase 11 — Local-Target Corpus Realization + Shortfall Diagnostics ✓ COMPLETE

**Goal:** Make `generate-corpus` truly count-oriented and execution-complete on local targets.

- [x] `SeedSynthesizer.to_seed_dict()` — added missing `vulnerability_class` field (blocked all generate-corpus on non-sandbox targets)
- [x] `SweepConstraints.verify_patcher: bool = True` — filters NOOP candidates at planning time via `_verify_patcher_will_mutate()`
- [x] `_write_shortfall_report()` → `shortfall_report.json` — unified plan + execution shortfall view
- [x] `acceptance_summary.json` schema v1.1: `requested_count_met`, `shortfall_amount`, honest `honest` field
- [x] `generation_diagnostics.json` — execution failure category attribution
- [x] `examples/local_targets/moderate/src/` — 4-file moderate fixture; 10/10 VALID at count=10
- [x] `examples/local_targets/minimal/src/` — 1-file minimal fixture; tests honest shortfall
- [x] `TestGenerateCorpusLocalE2E` — 8 E2E tests on moderate/minimal fixtures
- [x] 582 tests passing

---

## Phase 12 — Replayable Corpus Runs ✓ COMPLETE

**Goal:** `generate-corpus --from-plan PATH` replay path + `corpus_index.json` manifest.

- [x] `--from-plan PATH` argument on `generate-corpus` (PATH = dir or corpus_plan.json file)
- [x] `--source` and `--count` now optional (required only for fresh generate, not replay)
- [x] `CorpusPlan.from_dict()` classmethod for JSON deserialization
- [x] `_execute_plan_cases()` shared execution loop (generate + replay)
- [x] `_finish_generate_corpus()` shared artifact writing
- [x] `corpus_index.json` schema v1.0: run_mode, source_hash, plan_hash, counts, per_strategy, per_file, artifacts, reproducibility.replay_command
- [x] `_cmd_generate_corpus_replay()` — dedicated replay entry point
- [x] CWE-476 validated VIABLE on target_b (bstree/dynarray/strmap), 5/5 VALID
- [x] `TestReplayFromPlan` (5 tests) + `TestCorpusPlanFromDict` (3 tests)
- [x] 591 tests passing

---

## Phase 13 — Fresh-Plan Reproducibility + Plan Stability Closure ✓ COMPLETE

**Goal:** Prove and document that plan-corpus is reproducible across fresh runs (not just replay).

- [x] `scripts/check_plan_stability.py` — runs plan-corpus N times, compares corpus_plan.json, writes `plan_repro_report.json`; drift categories: source_hash_mismatch, planned_count_mismatch, strategy_allocation_drift, case_set_drift, case_content_drift, case_ordering_drift
- [x] `plan_repro_report.json` schema v1.0: verdict (STABLE/PLAN_UNSTABLE), plan_stable, all_identical, plan_fingerprints, plan_diff, run_details
- [x] `corpus_index.json` schema v1.1: added `fingerprints` block — plan_fingerprint, synthesized_seed_fingerprint, acceptance_fingerprint, adjudicator_mode
- [x] `tests/test_reproducibility.py` — 18 official reproducibility tests:
  - `TestFreshPlanReproducibility` (5): byte-identical plans on moderate/minimal/sandbox_eval
  - `TestFreshGenerateReproducibility` (3): stable accepted counts + fingerprints
  - `TestReplayVsFreshReproducibility` (3): replay matches fresh run
  - `TestCheckPlanStabilityScript` (5): script smoke tests
  - `TestCorpusIndexFingerprints` (2): fingerprints schema
- [x] README.md, ARCHITECTURE.md, ROADMAP.md truth-synced to Phase 13
- [x] `docs/repro_runbook.md` §14 updated + §15 added (replay vs fresh-plan distinction)
- [x] `docs/repro_matrix.md` updated with fresh-plan repro check results
- [x] 609 tests passing

---

## Phase 14 — Strategy Breadth Expansion + Corpus Artifact Hardening ✓ COMPLETE

**Goal:** Add CWE-190 as a 6th corpus-capable strategy, register target_b CWE-476 seeds,
add `malloc_size_cast` pattern type to seeder/schema, and truth-sync all docs.

- [x] `remove_size_cast` strategy (CWE-190): single-line handler in `patcher.py`; removes `(size_t)` cast from `malloc((size_t)EXPR * sizeof(T))` → `malloc(EXPR * sizeof(T))` enabling integer overflow in size arithmetic
- [x] Conservative constraints: exactly one `(size_t)` cast, at start of arg expression; double-cast lines (graph.c:186) correctly skipped
- [x] `malloc_size_cast` pattern type added to `seeder.py` `PATTERN_REGEXES`; scoring: +0.35 → score 0.75 for all `(size_t)`-cast malloc lines
- [x] `seed.schema.json` updated: `malloc_size_cast` added to `pattern_type` enum
- [x] `inspector.py` `PLANNING_STRATEGIES` extended with `remove_size_cast` (CWE-190, corpus_admitted=True)
- [x] `seed_synthesis.py` `_CWE_VULNERABILITY_CLASS` extended with CWE-190
- [x] 8 sandbox seed files: `examples/seeds/sandbox/cwe190_sb_001.json` – `cwe190_sb_008.json` (seeds 1–8)
- [x] Quality gate: 7/8 VALID (87.5%); 1 NOOP (seed 5 → graph.c:186, double-cast, correctly skipped)
- [x] Unique VALID targets: htable.c:176, htable.c:148, graph.c:90, list.c:193
- [x] 5 target_b CWE-476 seed files: `examples/seeds/target_b/cwe476_tb_001.json` – `cwe476_tb_005.json`
- [x] target_b CWE-476 quality gate: 5/5 VALID (dynarray.c:154, strmap.c:76, dynarray.c:32, bstree.c:195, strmap.c:92)
- [x] `config/strategy_catalog.json` updated: catalog_version → phase-14, CWE-190 entry promoted to IMPLEMENTED_AND_CORPUS_ADMITTED (7 admitted entries now 6 + 1 CWE-190)
- [x] `tests/test_patcher_cwe190.py` (28 tests): handler unit tests, Patcher.run() end-to-end, seeder pattern/scoring, inspector registration
- [x] `tests/test_planning.py` count updated: `test_catalog_has_5_corpus_admitted` → `test_catalog_has_6_corpus_admitted`
- [x] README.md, ARCHITECTURE.md, ROADMAP.md truth-synced to Phase 14
- [x] `docs/repro_matrix.md` updated with CWE-190 and target_b CWE-476 quality gate results
- [x] 637 tests passing

**Key design decisions:**
- Used new `malloc_size_cast` pattern type (not reusing `malloc_call`) to avoid changing scoring for existing strategies
- Conservative handler: skips multi-cast lines; only matches cast at arg start
- corpus_admitted=True justified by 87.5% VALID rate; NOOP is expected/correct behavior on double-cast lines
- target_b CWE-476 seeds added as registered files (not just validated pilots)

---

## Phase 15 — Multi-Target Corpus Orchestration + Canonical Interface Truth Sync ✓ COMPLETE

**Goal:** Add a portfolio planning layer that allocates a global case count across multiple
evaluation-only targets, with deterministic proportional allocation, global diversity
constraints, and machine-readable shortfall diagnostics.

- [x] `src/insert_me/planning/portfolio.py` — `PortfolioPlanner`, `PortfolioPlan`, `PortfolioConstraints`, `PortfolioTarget`, `PortfolioEntry`, `PortfolioTargetSummary`, `load_targets_file`
- [x] `CorpusPlanner.__init__` — new `case_id_prefix` parameter for globally unique case IDs
- [x] `corpus_planner.py` `_STRATEGY_PATTERN_TYPE` + `_STRATEGY_PASS_RATE` include `remove_size_cast`
- [x] Shortfall category constants: `CAT_TARGET_CAPACITY`, `CAT_STRATEGY_BLOCKED`, `CAT_DIVERSITY_TARGET`, `CAT_DIVERSITY_STRATEGY`, `CAT_NO_VIABLE_TARGETS`, `CAT_EXPERIMENTAL`, `CAT_SWEEP_EXHAUSTED`
- [x] Proportional allocation: floor-integer distribution, remainder by highest fractional part (deterministic)
- [x] Global greedy selection: sorted by (suitability_weight DESC, score DESC, target_name ASC, strategy ASC, seed_integer ASC)
- [x] Portfolio fingerprint: sha256[:16] of canonical sorted entries
- [x] `PortfolioPlan.write(output_dir, per_target_plans)` — writes portfolio_plan.json + per-target sub-plans under targets/<name>/_plan/
- [x] CLI `plan-portfolio` subcommand: `--targets-file`, `--count`, `--output-dir`, portfolio constraint flags
- [x] CLI `generate-portfolio` subcommand: fresh mode + `--from-plan` replay mode; writes all portfolio artifacts
- [x] Portfolio artifacts: `portfolio_plan.json`, `portfolio_index.json`, `portfolio_acceptance_summary.json`, `portfolio_shortfall_report.json`
- [x] Per-target artifacts: reuses `_finish_generate_corpus` per target (corpus_index.json, acceptance_summary.json, shortfall_report.json)
- [x] `schemas/targets.schema.json` — JSON schema for targets files
- [x] `examples/targets/sandbox_targets.json` — bundled two-target example
- [x] `src/insert_me/planning/__init__.py` — exports portfolio public API
- [x] `tests/test_portfolio.py` — 51 tests covering constraints, determinism, allocation, shortfall, diversity limits, roundtrip, CLI smoke
- [x] CLI docstring and module-level comments truth-synced
- [x] 688 tests passing (637 + 51 new)

**Allocation algorithm:**
- VIABLE strategies: full file-capped capacity; LIMITED: 0.5x ceil; BLOCKED: 0
- Sub-allocations: floor-proportional + remainder by highest fractional part, then highest capacity, then name
- Global limits: `max_per_target` (hard), `max_per_strategy_global` (hard), fraction warnings (soft)
- Case IDs: globally unique across targets (prefix = sanitised target name)

**Reproducibility:**
- Same targets-file + same count + same constraints => byte-identical portfolio_plan.json
- `--from-plan` replay re-executes same cases in same order

---

## Phase 15.7 — Public Truth Closure + Canonical UX Closure + Documentation Drift Guardrails ✓ COMPLETE

**Goal:** Make the repo's public truth, user experience, and documentation drift protections
match the actually implemented product. No new features; no new mutation families.

- [x] CLI module docstring: `"Canonical interface (primary)"` → `"Expert/manual seed-driven interface (single-case)"`
- [x] CLI `_build_parser()` epilog: replaced single `"Canonical usage"` with three-pattern summary (recommended single-target, recommended portfolio, expert/manual)
- [x] README phase marker: Phase 15 → Phase 15.7
- [x] README test count: 711 → 712
- [x] README internal Quick Reference: maturity text updated to Phase 15.7
- [x] README "Try It Now": restructured — recommended single-target path first (`inspect-target` → `generate-corpus`), then portfolio, then expert/manual seed-file demo
- [x] README Quick Start: Pattern order inverted — Pattern 2/3 (recommended) shown before Pattern 1 (expert/manual); labels added
- [x] README "What is NOT available yet": added parallel execution gap, portfolio stability script gap, production codebase scope clarification, real LLM adjudicator status
- [x] ARCHITECTURE.md: Phase 15.5 → Phase 15.7 in current status header; test count updated; `test_doc_drift.py` noted
- [x] `tests/test_doc_drift.py`: 20 deterministic documentation drift checks — phase marker sync (README/ARCHITECTURE/ROADMAP), strategy count + admitted ID sync, CLI subcommand presence, recommended workflow presence, bundled example file existence, sandbox_targets.json path resolution
- [x] 731 tests passing (712 pre-phase + 20 new doc-drift tests, 1 skipped unchanged)

**Canonical workflow positions established:**
- `run --seed-file` / `batch --seed-dir` → **expert/manual seed-driven**
- `inspect-target` / `plan-corpus` / `generate-corpus` → **single-target target-aware**
- `plan-portfolio` / `generate-portfolio` → **multi-target portfolio**

---

## Phase 15.8 — Single Source of Truth + Auto-Synced Docs ✓ COMPLETE

**Goal:** Introduce a single machine-readable product status manifest so public-facing
docs cannot silently lag behind the implementation again.

- [x] `config/project_status.json` — single authoritative manifest; captures phase, maturity label, admitted strategy count/IDs, canonical workflow labels, recommended first commands per path, not-yet-available items, stability policy (STABLE vs VOLATILE metrics)
- [x] `stability_policy` in manifest encodes which metrics belong in README (phase, strategy count/IDs, workflow labels) vs manifest only (test count, corpus seed counts)
- [x] README status table: removed volatile test count; added reference to manifest + `check_public_status.py`
- [x] README internal Quick Reference: removed hard-coded test count; references manifest
- [x] README phase: 15.7 → 15.8
- [x] ARCHITECTURE.md: Phase 15.7 → Phase 15.8; removed test count; manifest and check script noted
- [x] Remaining stale docs updated: `docs/repro_runbook.md`, `docs/local_target_pilot.md`, `docs/corpus_quality_gate.md`, `docs/strategy_catalog.md` all updated from Phase 15 → Phase 15.8
- [x] `cli.py` arg help line 118: `"canonical primary input"` → `"Expert/manual seed-driven path"`
- [x] `tests/test_doc_drift.py` refactored — all stable checks now derive expected values from manifest (no literal expected strings in test bodies)
- [x] 7 test classes: `TestManifestIntegrity`, `TestPhaseMarkerSync`, `TestStrategyCatalogSync`, `TestCanonicalWorkflowLabels`, `TestCliCommandPresence`, `TestNotYetAvailableSync`, `TestExampleArtifactExistence`
- [x] `scripts/check_public_status.py` — manifest-driven validation script; prints per-check pass/fail; exit 0 iff all pass

**Stability policy (encoded in manifest):**
- STABLE in README: phase, admitted strategy count, admitted strategy IDs, canonical workflow labels, not-yet-available items
- VOLATILE (manifest only): test count, corpus seed counts
- Any future doc edit that deviates from the manifest now fails `tests/test_doc_drift.py`

---

## Phase 16 — Workload Characterization + Support Envelope ✓ COMPLETE

**Goal:** Measure and document the practical operating envelope of insert_me on evaluation-only
C/C++ targets; produce machine-readable support artifacts.

- [x] `config/workload_classes.json` -- machine-readable workload taxonomy: tiny/small/medium/large_phase16 classes with LOC/file thresholds, support levels, recommended max counts, known target assignments, and stage timing benchmarks
- [x] `scripts/profile_pipeline_stage.py` -- times each pipeline stage (Seeder/Patcher/Validator/Auditor) individually using the Python API; produces `stage_timing_report.json`
- [x] `scripts/characterize_workloads.py` -- runs inspect/plan/(optionally) generate on all 5 bundled fixtures; produces `workload_report.json`, `support_matrix.json`, `target_classification.json`
- [x] `docs/support_envelope.md` -- workload class table, 5 target profiles, stage bottleneck analysis, per-class recommendations, parallelisation assessment
- [x] `tests/test_characterization.py` -- 21 lightweight regression checks (manifest integrity, classification algorithm, profile_pipeline_stage artifact structure, characterize_workloads artifact structure); timing values NOT asserted
- [x] Phase marker updated to 16 throughout: README, ARCHITECTURE.md, ROADMAP.md, docs/corpus_quality_gate.md, config/project_status.json
- [x] `config/project_status.json` phase_label: "workload characterization + support envelope"

**Key finding:** Validator (file I/O for bad/good tree comparison) is the dominant pipeline stage
for small/medium targets (56-60% of per-case time). Parallelisation at the process level is the
recommended next step for throughput scaling.

**Phase 16.1 -- Public Truth Closure + Characterization Artifact Sync ✓ COMPLETE**
- [x] All stale Phase 15.8 headers updated to Phase 16 across all public docs
- [x] `config/project_status.json` -- added `workload_classes_manifest` and `support_envelope_doc` reference fields; stability_policy updated with STABLE entries for both
- [x] README Internal Quick Reference: maturity row updated to Phase 16 + workload characterization; target sizing quick reference table added; workload class guidance visible to new users
- [x] `docs/local_target_pilot.md` -- new section 1.4: workload class table with recommended counts and workflow guidance per class; cross-reference to `docs/support_envelope.md`
- [x] `scripts/check_public_status.py` -- 4 new required-file checks (workload_classes.json, support_envelope.md, characterize_workloads.py, profile_pipeline_stage.py); now 37 checks total
- [x] `tests/test_doc_drift.py` -- 4 new paths in REQUIRED_PATHS; new `TestPhase16ArtifactIntegrity` class (5 checks: workload manifest valid JSON, manifest references both Phase 16 files, support_envelope cross-referenced from local_target_pilot and README)

**Next evidence-based decision after Phase 16:**

The workload characterization data gives a concrete basis for the next architectural
question: **is process-level parallelism justified?**

Evidence from Phase 16 measurements:
- Validator consumes 56-60% of per-case pipeline time for small/medium targets
- A 50-case medium corpus (~229ms/case) takes ~11.5 seconds single-threaded
- Validator is embarrassingly parallel (no shared state across cases)
- Auditor I/O is also per-case with no contention

The data supports: process-level parallelism in `generate-corpus` / `generate-portfolio`
would yield ~55-60% throughput improvement for small/medium targets at the cost of
added complexity and non-deterministic ordering of output bundles.

**This is the leading candidate for Phase 17 unless a correctness or feature gap is
identified as higher priority.**

---

## Phase 17 — Process-Level Parallelism + Portfolio Stability Proof ✓ COMPLETE

**Goal:** Add `--jobs N` parallelism to `generate-corpus` and `generate-portfolio` using
`ProcessPoolExecutor`; add `check_portfolio_stability.py` for multi-target reproducibility
verification; prove sequential-vs-parallel parity with dedicated tests.

- [x] `--jobs N` argument on `generate-corpus` and `generate-portfolio` (default: all CPU cores; `--jobs 1` = sequential)
- [x] `_execute_single_case_worker(task: dict)` — module-level picklable worker function for process-pool dispatch (Windows `spawn` compatible)
- [x] `_execute_plan_cases()` rewritten to support both sequential (`jobs <= 1`) and parallel (`jobs > 1`) modes
- [x] Parallel mode: dispatches all cases via `ProcessPoolExecutor`; collects results into `case_outcomes` dict; prints + writes results in canonical plan order after all futures complete
- [x] Deterministic artifact output: fingerprints sort their inputs; `case_outcomes` keyed by `case_id` (order-independent); `--jobs 1` and `--jobs N` produce byte-identical `acceptance_summary.json`, `corpus_index.json`, `portfolio_index.json`
- [x] `scripts/check_portfolio_stability.py` — three-check verification script: fresh-plan stability, replay stability, sequential-vs-parallel parity; writes `portfolio_repro_report.json`; exit 0/1/2
- [x] `tests/test_parallel.py` — `TestCorpusParallelParity` (3 tests), `TestPortfolioParallelParity` (3 tests), `TestPortfolioStabilityScript` (3 tests)
- [x] `config/project_status.json`: phase → 17; removed "Parallel execution" and "Portfolio reproducibility check script" from `not_yet_available`
- [x] README, ARCHITECTURE.md, ROADMAP.md, `docs/support_envelope.md`, `docs/repro_runbook.md` truth-synced to Phase 17

**Parity guarantee (enforced by tests):**
`--jobs 1` (sequential) and `--jobs N` (parallel) produce identical `accepted_count`,
`rejected_count`, `planned_count`, and `acceptance_fingerprint` for both corpus and portfolio
generation. Replay (`--from-plan`) with parallel execution matches fresh sequential fingerprint.

**Not changed:**
- Planning layer remains single-threaded and deterministic
- No new mutation strategies
- No LLM integration

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
