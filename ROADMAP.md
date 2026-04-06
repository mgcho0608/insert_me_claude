# Roadmap — insert_me

---

## Guiding Principles

- **Deterministic core first.** Never block the core pipeline on an LLM feature.
- **Narrow scope.** `insert_me` does one thing: insert vulnerabilities. It does not verify,
  benchmark, or classify.
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

## Phase 4 — Patcher (Deterministic) ⚡ PARTIALLY COMPLETE (Phase 4a)

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

### Phase 4b — remaining

- [ ] Implement additional mutation strategies for Phase 1 CWE set:
      `insert_premature_free` (CWE-416), `integer_size_overflow` (CWE-190)
- [ ] Handle multi-file source trees with multiple targets across files
- [ ] Confirm determinism: same seed + spec → same diff across runs
- [ ] Benchmark copy performance on mid-size source trees (~100k LOC)

Note: `source_hash` is already computed by the Seeder and written to
`patch_plan.json` and `audit.json`. No placeholder removal needed.

**Phase 4a exit criterion met:** `Patcher.run()` produces a real `PatchResult`
for `alloc_size_undercount` targets; good/bad trees are written; 265 tests pass.

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
- [x] 32 Auditor tests passing; 15 hardening tests (cross-artifact coherence, INVALID path, validate-bundle failure); CLI smoke test proves complete demo bundle (280 total)

**Note:** Run ID derivation using full source tree hash was already implemented in
Phase 3 (Seeder computes `source_hash`; orchestrator derives `run_id` from seed JSON +
source path + pipeline version).  No additional work needed.

**Exit criterion met:** `insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json --source examples/demo/src`
produces a complete, schema-valid output bundle with `audit_result.json` classification `VALID`.

---

## Phase 7 — LLM Adapter (Optional Enrichment)

**Goal:** Pluggable LLM enrichment layer that does not break core pipeline if absent.

- [ ] Finalize `LLMAdapter` ABC interface
- [ ] Implement one real adapter (HTTP endpoint, OpenAI-compatible API)
- [ ] Wire into Auditor as optional enrichment step
- [ ] Write `labels.json` when enabled
- [ ] Write tests: (a) NoOpAdapter produces valid output, (b) swapping adapters
  does not change `ground_truth.json` or `audit.json`

**Exit criterion:** `--no-llm` and `--llm-adapter=noop` both work. `ground_truth.json` and
`audit.json` are byte-identical in both modes.

---

## Phase 8 — CWE Coverage Expansion

**Goal:** Expand the supported vulnerability class set beyond the initial 1–3 CWEs.

- [ ] Audit existing mutation strategies for generalizability
- [ ] Add mutation strategies for priority CWEs (to be defined based on use case)
- [ ] Add corresponding seed file templates under `examples/seeds/`
- [ ] Regression test suite for each new CWE

**Deferred until Phase 6 is stable.**

---

## Phase 9 — Corpus Generation Tooling

**Goal:** Tooling to generate large labelled corpora efficiently.

- [ ] Batch run support (`insert-me batch --seed-dir examples/seeds/ --source /project`)
- [ ] Parallel execution with deterministic output (process-level parallelism)
- [ ] Corpus manifest (`corpus_index.json`) aggregating all run IDs in a directory
- [ ] Deduplication check across runs

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
