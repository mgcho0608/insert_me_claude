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

## Phase 3 — Seeder (Deterministic)

**Goal:** Given a seed file, produce a deterministic ranked list of patch targets
from a real C/C++ source tree.

- [ ] Define `PatchTarget` and `PatchTargetList` dataclasses
- [ ] Implement AST walking for C/C++ (decide: tree-sitter vs libclang vs regex fallback)
- [ ] Implement pattern matching for each supported CWE class
- [ ] Implement seed-based deterministic ranking/ordering of candidates
- [ ] Write tests with fixture C source files covering edge cases
- [ ] Populate `patch_plan.json` with real targets (status → PLANNED)
- [ ] Benchmark seeder performance on a mid-size project (~100k LOC)

**Exit criterion:** `Seeder.run(seed_data, source=fixture_tree)` returns a
non-empty `PatchTargetList` and is byte-identical across multiple runs.

---

## Phase 4 — Patcher (Deterministic)

**Goal:** Apply mutations from a `PatchTargetList` to produce bad/good source trees.

- [ ] Define `Mutation` and `PatchResult` dataclasses
- [ ] Implement mutation strategies for Phase 1 CWE set (start narrow: 1–3 CWEs)
- [ ] Implement bad/good tree copy + apply
- [ ] Verify round-trip: good tree is byte-identical to original
- [ ] Write tests for each mutation strategy on fixture sources
- [ ] Confirm determinism: same seed + spec → same diff
- [ ] Remove dry-run source_hash placeholder; compute real source tree hash

**Exit criterion:** `Patcher.run(targets, source_path)` produces a `PatchResult` with a
reproducible diff that compiles (at least syntactically) in the fixture environment.

---

## Phase 5 — Validator (Rule-Based)

**Goal:** Automated plausibility checking of patch results.

- [ ] Implement rule checks: syntactic well-formedness, mutation non-triviality,
  file scope sanity, no obvious compile-break patterns
- [ ] Populate `validation_result.json` with real check results
- [ ] Integrate with a lightweight C/C++ syntax check (clang-format dry-run or similar)
- [ ] Write tests for pass/fail cases

**Exit criterion:** Validator correctly rejects known-bad mutations and passes known-good ones
in fixture tests.

---

## Phase 6 — Auditor and Full Output Bundle (MVP)

**Goal:** Complete end-to-end pipeline producing a valid, schema-conformant output bundle
with real mutations.

- [ ] Implement Auditor — classify mutation as VALID/NOOP/AMBIGUOUS/INVALID from pipeline state
- [ ] Populate `audit_result.json` with real classification and evidence
- [ ] Populate `ground_truth.json` with real mutation records
- [ ] Implement run ID derivation using full source tree hash
- [ ] Wire up the full pipeline orchestrator in `pipeline/__init__.py`
- [ ] Write end-to-end integration test: seed → real mutation → schema-valid bundle

**Exit criterion:** `insert-me run --seed-file specs/cwe-122.json --source fixture/`
produces a schema-valid output bundle with real mutations in `output/<run-id>/`.

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

**MVP = Phase 6 complete.**

An `insert_me` that can take a seed file, and a C source tree, and produce a
schema-valid output bundle (bad/good pair + ground truth + audit log) deterministically,
with no LLM required, is the minimum useful artifact.

The dry-run pipeline from Phase 2 is a working skeleton of this MVP — all artifact
contracts are exercised end-to-end; only real AST mutation is deferred.
