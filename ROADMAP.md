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

## Phase 2 — Config and Spec Loading

**Goal:** A complete, tested config and spec loading layer so pipeline stages have clean inputs.

- [ ] Finalize `config/default.toml` with all supported keys
- [ ] Implement `config.py` — load, validate, merge with defaults, expose typed dataclass
- [ ] Define vulnerability spec format (TOML) — CWE, mutation strategy, target patterns
- [ ] Implement spec loader + validator
- [ ] Write tests for config and spec loading (malformed inputs, missing keys, overrides)

**Exit criterion:** `insert-me run --seed 42 --spec specs/cwe-122.toml --dry-run` loads
without error and prints the resolved config.

---

## Phase 3 — Seeder (Deterministic)

**Goal:** Given a seed and a spec, produce a deterministic ranked list of patch targets
from a real C/C++ source tree.

- [ ] Define `PatchTarget` and `PatchTargetList` dataclasses
- [ ] Implement AST walking for C/C++ (decide: tree-sitter vs libclang vs regex fallback)
- [ ] Implement pattern matching for each supported CWE class
- [ ] Implement seed-based deterministic ranking/ordering of candidates
- [ ] Write tests with fixture C source files covering edge cases
- [ ] Benchmark seeder performance on a mid-size project (~100k LOC)

**Exit criterion:** `Seeder.run(seed=42, spec=cwe_122_spec, source=fixture_tree)` returns a
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

**Exit criterion:** `Patcher.run(targets, source_path)` produces a `PatchResult` with a
reproducible diff that compiles (at least syntactically) in the fixture environment.

---

## Phase 5 — Validator (Rule-Based)

**Goal:** Automated plausibility checking of patch results.

- [ ] Define `ValidationVerdict` dataclass and reason code enum
- [ ] Implement rule checks: syntactic well-formedness, mutation non-triviality,
  file scope sanity, no obvious compile-break patterns
- [ ] Integrate with a lightweight C/C++ syntax check (clang-format dry-run or similar)
- [ ] Write tests for pass/fail cases
- [ ] Document which checks are enabled by default vs opt-in

**Exit criterion:** Validator correctly rejects known-bad mutations and passes known-good ones
in fixture tests.

---

## Phase 6 — Auditor and Full Output Bundle

**Goal:** Complete end-to-end pipeline producing a valid, schema-conformant output bundle.

- [ ] Implement `AuditRecord` and `GroundTruthRecord` dataclasses
- [ ] Implement Auditor — write both JSON files from pipeline state
- [ ] Implement run ID derivation (hash of seed + spec hash + source tree hash)
- [ ] Implement `artifacts.py` output path layout
- [ ] Wire up the full pipeline orchestrator in `pipeline/__init__.py`
- [ ] Write end-to-end integration test: seed → bundle, validate bundle schema

**Exit criterion:** `insert-me run --seed 42 --spec specs/cwe-122.toml --source fixture/`
produces a complete, schema-valid output bundle in `output/<run-id>/`.

---

## Phase 7 — LLM Adapter (Optional Enrichment)

**Goal:** Pluggable LLM enrichment layer that does not break core pipeline if absent.

- [ ] Finalize `LLMAdapter` ABC interface
- [ ] Implement `NoOpAdapter` (always active, returns stubs)
- [ ] Implement one real adapter (internal-LLM-compatible, HTTP endpoint, OpenAI-compatible API)
- [ ] Wire into Auditor as optional enrichment step
- [ ] Write tests confirming: (a) NoOpAdapter produces valid output, (b) swapping adapters
  does not change `ground_truth.json` or `audit.json`
- [ ] Document adapter configuration in `config/default.toml`

**Exit criterion:** `--no-llm` and `--llm-adapter=noop` both work. `ground_truth.json` and
`audit.json` are byte-identical in both modes.

---

## Phase 8 — CWE Coverage Expansion

**Goal:** Expand the supported vulnerability class set beyond the initial 1–3 CWEs.

- [ ] Audit existing mutation strategies for generalizability
- [ ] Add mutation strategies for priority CWEs (to be defined based on use case)
- [ ] Add corresponding spec templates under `specs/`
- [ ] Regression test suite for each new CWE

**Deferred until Phase 6 is stable.**

---

## Phase 9 — Corpus Generation Tooling

**Goal:** Tooling to generate large labelled corpora efficiently.

- [ ] Batch run support (`insert-me batch --spec-dir specs/ --seeds seeds.txt`)
- [ ] Parallel execution with deterministic output (process-level parallelism, not thread)
- [ ] Corpus manifest (`corpus_index.json`) aggregating all run IDs in a directory
- [ ] Deduplication check across runs (same patch target, different seeds)

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

An `insert_me` that can take a seed, a CWE spec, and a C source tree, and produce a
schema-valid output bundle (bad/good pair + ground truth + audit log) deterministically,
with no LLM required, is the minimum useful artefact.

Everything before Phase 6 is infrastructure. Everything after Phase 6 is enhancement.
