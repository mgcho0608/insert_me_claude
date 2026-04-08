# insert_me Support Envelope and Workload Characterization

> **Phase:** 17 -- process-level parallelism + portfolio stability proof  
> **Machine-readable form:** `config/workload_classes.json`  
> **Measurement scripts:** `scripts/characterize_workloads.py`, `scripts/profile_pipeline_stage.py`  
> **Audience:** Engineers choosing evaluation-only targets and corpus sizes for insert_me

---

## 1. Purpose

This document states clearly which evaluation-only C/C++ targets insert_me handles well,
which are supported as pilots only, and which are currently out of scope.
It is grounded in actual measurements against the bundled fixtures.

---

## 2. Workload Classes

insert_me classifies evaluation-only targets into four workload classes based on
source file count and approximate LOC. These thresholds are advisory; the authoritative
per-target verdict comes from `inspect-target`.

| Class | Files | LOC | Inspect tier | Effective capacity | Recommended max | Support level |
|---|---|---|---|---|---|---|
| **tiny** | 1-2 | <150 | pilot-single (maybe small-batch) | 0-8 | 5 | PILOT ONLY |
| **small** | 2-6 | 150-699 | corpus-generation | 8-30 | 20 | SUPPORTED -- pilot to corpus-starter |
| **medium** | 4-15 | 700-3000 | corpus-generation | 30-160 | 60 | RECOMMENDED -- primary corpus target |
| **large** | 15+ | >3000 | corpus-generation (projected) | 160+ | TBD | OUT OF SCOPE -- phase 16 |

**Always run `insert-me inspect-target` first.** The class table above provides a quick
pre-check; the inspection result is the authoritative suitability verdict for a specific
source tree.

---

## 3. Known Target Profiles

All five bundled evaluation-only fixtures have been characterized. No new fixtures were
needed to cover the taxonomy; existing fixtures span tiny, small, and medium classes.

### 3.1 Tiny: `minimal` (1 file, ~44 LOC)

| | |
|---|---|
| **Path** | `examples/local_targets/minimal/src/counter.c` |
| **Workload class** | tiny |
| **Inspect tier** | pilot-single only |
| **Viable strategies** | 0 (all LIMITED due to single-file concentration) |
| **Max supportable** | 17 (TargetInspector estimate) |
| **Recommended max count** | 3 |
| **Concentration risk** | HIGH -- 100% in one file |
| **Primary use** | Single-case manual experiment; tests honest shortfall behaviour |
| **Notes** | Reference "too-small" target. Requesting count > 3 triggers expected honest shortfall. Not suitable for batch corpus generation. |

### 3.2 Tiny: `demo` (2 files, ~80 LOC)

| | |
|---|---|
| **Path** | `examples/demo/src/` |
| **Workload class** | tiny |
| **Inspect tier** | pilot-small-batch |
| **Viable strategies** | 0 (all LIMITED) |
| **Max supportable** | 15 |
| **Recommended max count** | 5 |
| **Concentration risk** | OK (balanced across 2 files) |
| **Primary use** | Expert/manual `run --seed-file` demo; onboarding smoke test |
| **Notes** | Primary quickstart fixture. Works for single-case and small-batch demos. Not suitable for corpus generation. |

### 3.3 Small: `moderate` (4 files, ~339 LOC)

| | |
|---|---|
| **Path** | `examples/local_targets/moderate/src/` |
| **Workload class** | small |
| **Inspect tier** | corpus-generation |
| **Viable strategies** | 5 (CWE-122/416/415/401/476) |
| **Max supportable** | 83 |
| **Recommended max count** | 20 |
| **Concentration risk** | OK |
| **Primary use** | First corpus target for new users; fast iteration (~191ms/case) |
| **Notes** | Recommended "first real target" for users new to insert_me. All admitted strategies viable. count=10 runs in under 2 seconds. |

### 3.4 Small: `target_b` (3 files, ~666 LOC)

| | |
|---|---|
| **Path** | `examples/sandbox_targets/target_b/src/` |
| **Workload class** | small |
| **Inspect tier** | corpus-generation |
| **Viable strategies** | 5 (CWE-122/416/415/401/476) |
| **Max supportable** | 75 |
| **Recommended max count** | 20 |
| **Concentration risk** | OK (borderline on bstree.c for null_guard) |
| **Primary use** | Portfolio component; registered sandbox corpus |
| **Notes** | Dense small target. Higher LOC/file than moderate. All 20 registered seeds pass quality gate. |

### 3.5 Medium: `sandbox_eval` (6 files, ~1402 LOC)

| | |
|---|---|
| **Path** | `examples/sandbox_eval/src/` |
| **Workload class** | medium |
| **Inspect tier** | corpus-generation |
| **Viable strategies** | 6 (all admitted including CWE-190 remove_size_cast) |
| **Max supportable** | 160 |
| **Recommended max count** | 60 |
| **Concentration risk** | LOW (well-distributed across 6 files) |
| **Primary use** | Primary reference corpus target; all 6 admitted strategies viable |
| **Notes** | Only target where remove_size_cast (CWE-190, requires (size_t) cast pattern) is viable. 56 registered seeds, 100% reproducible. |

---

## 4. Stage-Level Bottleneck Analysis

All timing measurements are approximate medians over 5 runs on a single-threaded
development machine. The dominant pattern holds across hardware.

### 4.1 Per-case pipeline timing

| Stage | tiny/minimal | small/moderate | medium/sandbox_eval |
|---|---|---|---|
| **Seeder** (source scan) | 1.3ms (2%) | 8.8ms (8%) | 37.3ms (16%) |
| **Patcher** (apply mutation) | 9.7ms (13%) | 14.3ms (14%) | 24.4ms (11%) |
| **Validator** (file I/O checks) | 12.3ms (16%) | 58.1ms (56%) | 138.4ms (60%) |
| **Auditor** (schema + JSON write) | 53.2ms (69%) | 22.9ms (22%) | 29.3ms (13%) |
| **Pipeline total** | 76.6ms | 104.1ms | 229.4ms |

### 4.2 Key bottleneck findings

**Finding 1: Validator dominates for small and medium targets (56-60% of pipeline).**

The Validator runs 5 file-level checks, including byte-identical tree comparison and
content scanning. It scales with source tree size (LOC and file count). For medium
targets (~1400 LOC), this is 138ms out of 229ms total per case.

Implication: parallelising pipeline cases would yield ~55-60% throughput improvement
for small-to-medium targets, since the Validator is not shared across cases.

**Finding 2: Auditor overhead dominates for tiny targets (69% of pipeline).**

For a 1-file, 44-LOC target, schema validation and JSON writing (Auditor) costs
53ms vs only 13ms of actual source-tree work. This is a fixed per-case overhead.

Implication: tiny targets are not a good parallelisation target -- they are bottlenecked
by per-case overhead, not source-tree work.

**Finding 3: Planning can be slower than generation for tiny targets.**

For `minimal` with count=5, `plan-corpus` takes ~454ms despite the target having
only 1 file. The SeedSynthesizer performs an exhaustive sweep to find distinct
candidates, and for tiny targets with few distinct sites it hits shortfall early
and reports it honestly. This is correct behaviour, not a bug.

Implication: do not use count >> max_supportable on tiny targets.

**Finding 4: Seeder scales with candidate pool, not just file count.**

`sandbox_eval` (523 insert_premature_free candidates) has a 37ms seeder time vs
8.8ms for moderate (137 candidates). The Seeder is O(candidate_count) for the
target inspection step.

### 4.3 Workflow timing (subprocess wall-clock including Python startup)

| Workflow | tiny | small | medium |
|---|---|---|---|
| `inspect-target` | ~155ms | ~174ms | ~231ms |
| `plan-corpus` (10 cases) | ~454ms | ~258ms | ~650ms |
| `generate-corpus` per case | ~573ms | ~191ms | ~261ms |
| 50-case corpus (projected) | ~29s | ~9.6s | ~13s |

Note: subprocess startup overhead (~120ms) is significant for single-case runs. For
`generate-corpus`, startup amortises across all planned cases.

---

## 5. Recommended vs Pilot vs Out-of-Scope Profiles

### 5.1 Recommended targets (medium class)

Characteristics:
- 5-15 C/C++ source files
- 700-3000 LOC
- 3+ admitted strategies VIABLE (not just LIMITED)
- File concentration risk LOW (<30% in any one file per strategy)
- `inspect-target` reports `corpus_generation: YES`

Use: generate-corpus count=10-60; generate-portfolio across 2-4 targets.

Example: `examples/sandbox_eval/src`

### 5.2 Supported pilot targets (small class)

Characteristics:
- 2-6 C/C++ source files
- 150-700 LOC
- 2+ admitted strategies VIABLE
- `inspect-target` reports `corpus_generation: YES`

Use: generate-corpus count=5-20; good portfolio component alongside a medium target.
Count above 20 may produce honest shortfall.

Examples: `examples/local_targets/moderate/src`, `examples/sandbox_targets/target_b/src`

### 5.3 Pilot-only targets (tiny class)

Characteristics:
- 1-2 C/C++ source files
- <150 LOC
- All admitted strategies LIMITED (concentration risk HIGH or few candidates)
- `inspect-target` reports `corpus_generation: NO` or `pilot_single_only`

Use: single-case `run --seed-file` experiments only. `generate-corpus` will produce
honest shortfall at any count above the max_supportable estimate.

Examples: `examples/local_targets/minimal/src`, `examples/demo/src`

### 5.4 Out-of-scope targets (large class, phase 16)

Characteristics:
- 15+ C/C++ source files
- >3000 LOC

Status: not validated in phase 16. The Validator bottleneck (scales with LOC) is
expected to dominate further at this scale. Sequential execution of large-class targets
is projected to be feasible but slow. Parallelisation is the recommended prerequisite
before committing to large-class targets.

---

## 6. Shortfall Attribution Summary

Common shortfall causes observed across fixtures:

| Cause | Target class | Shortfall type |
|---|---|---|
| Too few candidates (tiny, 1-file) | tiny | `target_capacity_limit` |
| Strategy BLOCKED (no viable sites) | tiny/small (CWE-190) | `strategy_blocked_no_candidates` |
| High file concentration (>50%) | small/medium | `target_capacity_limit` (diversity-constrained) |
| Requested count > max_supportable | any | `sweep_exhausted` |
| Portfolio global diversity limit hit | portfolio | `global_diversity_constraint_per_strategy` |

---

## 7. Portfolio Mode Assessment

Portfolio mode (`generate-portfolio`) does materially improve case-count attainment
when:
- At least one target is medium-class (contributes 30-60+ cases)
- Targets have complementary strategy strengths (e.g., sandbox_eval adds CWE-190; target_b adds extra CWE-476 sites)
- Global count is <=60% of total combined capacity

Portfolio mode does NOT help when:
- All targets are tiny (low combined capacity)
- Requested global count exceeds combined `max_supportable` across all targets

---

## 8. Parallelisation

**Phase 17 implemented process-level parallelism** for `generate-corpus` and
`generate-portfolio` using `ProcessPoolExecutor`.

### 8.1 Phase 16 evidence (motivating the decision)

- Validator consumes 56-60% of per-case pipeline time for small/medium targets
- Validator is not shared across cases (pure per-case file I/O)
- 50-case medium corpus: ~13s sequential; projected ~3-4s with 4-way parallelism
- No architectural blocker: each case is independent; determinism is preserved if worker
  assignment is deterministic

### 8.2 Phase 17 implementation

Use `--jobs N` on any `generate-corpus` or `generate-portfolio` invocation:

```bash
# Use all available CPU cores (default):
insert-me generate-corpus --source examples/sandbox_eval/src --count 30 \
    --output-root corpus_out/

# Use exactly 4 worker processes:
insert-me generate-corpus --source examples/sandbox_eval/src --count 30 \
    --output-root corpus_out/ --jobs 4

# Sequential mode (equivalent to --jobs 1, useful for debugging):
insert-me generate-corpus --source examples/sandbox_eval/src --count 30 \
    --output-root corpus_out/ --jobs 1
```

### 8.3 Determinism guarantee

`--jobs 1` and `--jobs N` produce **identical** `acceptance_summary.json`,
`corpus_index.json`, and `portfolio_index.json` artifacts. The `acceptance_fingerprint`
is identical regardless of job count. This is enforced by `tests/test_parallel.py`.

### 8.4 Workload class suitability for parallelism

| Class | Parallel benefit | Notes |
|---|---|---|
| tiny | Low | Overhead-bound (Auditor JSON I/O dominates); not a good parallelism target |
| small | Moderate | Validator 56% of pipeline; useful at count >= 10 |
| medium | High | Validator 60% of pipeline; ~4x speedup with 4 workers on a 30+ case corpus |
| large | Projected high | Not validated in Phase 16/17; parallelism expected to scale further |

**Not justified for tiny targets** (overhead-bound, not throughput-bound). Use `--jobs 1`
or omit `--jobs` for tiny targets with count <= 5.

### 8.5 Portfolio stability verification

Use `scripts/check_portfolio_stability.py` to verify that your portfolio setup is
reproducible across runs and that parallel execution produces the same results as sequential:

```bash
python scripts/check_portfolio_stability.py \
    --targets-file examples/targets/sandbox_targets.json \
    --count 20
```

Checks: fresh-plan stability (2 independent runs match), replay stability (replay matches
fresh), sequential-vs-parallel parity (`--jobs 1` vs `--jobs 2` produce same fingerprint).
Writes `portfolio_repro_report.json`. Exit 0 = all passed.
