# Local Target Pilot Guide — insert_me

> **Phase:** 17 -- process-level parallelism + portfolio stability proof
> **Audience:** Engineers who want to use insert_me on a local, user-provided
> evaluation-only C/C++ project rather than the bundled sandbox targets, or
> across a portfolio of multiple targets.
>
> This guide covers the full workflow: preflight inspection, count-driven corpus
> generation, honest shortfall diagnostics, multi-target portfolio generation,
> and the criteria for a "good" target.

---

## 1. Target Types

### 1.1 Supported: local evaluation-only toy / lab projects

insert_me is designed to work with **any** C/C++ source tree via:

```bash
insert-me run --seed-file PATH --source /path/to/local/project
insert-me batch --seed-dir PATH --source /path/to/local/project
```

The following target types are well-suited and explicitly supported:

| Target type | Examples | Notes |
|---|---|---|
| Toy / lab projects | Small hand-written C programs, teaching examples | Best starting point |
| Small open-source utilities | Single-purpose tools with clear ownership of allocations | Run `inspect-target` first |
| Private evaluation sandboxes | Purpose-built C files similar to `examples/sandbox_eval/src/` | Ideal |
| Ported or modified sandbox files | User-extended versions of bundled sandbox targets | Fully supported |

### 1.2 Not recommended: real production or widely-deployed projects

Do **not** use insert_me's corpus-generation workflow (many seeds, reproducibility
verification) against real production codebases in this phase.  Reasons:

| Problem | Why it matters |
|---|---|
| Files may change between runs (build artifacts, generated code) | Breaks reproducibility guarantee |
| Macro-heavy or template-heavy patterns | Lexical seeder cannot resolve expansions |
| Test / mock / stub files intermixed | Seeder default exclude patterns remove these; real coverage may be lower than it appears |
| Large LOC count | No specific problem, but quality gate concentration rules will be harder to satisfy |
| License / distribution restrictions | insert_me copies source files into bad/good trees; ensure you have rights to do this |

This restriction is **not permanent**.  Once the quality gate is extended with
better concentration analysis and the seeder gains partial macro awareness, real
projects become practical.  For now, stick to evaluation-only targets.

### 1.3 Not supported: non-C/C++ targets

insert_me's Seeder and Patcher are tuned for C/C++ (`malloc`, `free`, pointer
dereferences, null guards).  Other languages are outside scope for this phase.

---

### 1.4 Workload classes — know your target size before you start

insert_me classifies targets by source file count and approximate LOC into four
workload classes. The class determines which workflow to use and what corpus counts
are realistic. These thresholds are advisory; `inspect-target` gives the authoritative
suitability verdict for a specific source tree.

| Class | Files | LOC | Support level | Recommended max `--count` | Best workflow |
|---|---|---|---|---|---|
| **tiny** | 1-2 | <150 | PILOT ONLY | 5 | `run --seed-file` or `batch`; skip `generate-corpus` |
| **small** | 2-6 | 150-699 | SUPPORTED (pilot to corpus-starter) | 20 | `generate-corpus --count 10-20` |
| **medium** | 4-15 | 700-3000 | RECOMMENDED (primary corpus target) | 60 | `generate-corpus --count 20-60`; portfolio for multiple |
| **large** | 15+ | >3000 | OUT OF SCOPE -- Phase 16 | n/a | Not supported in this phase |

**When to prefer portfolio mode over single-target mode:**
Use `generate-portfolio` when you have two or more small or medium targets.
Portfolio mode applies global diversity constraints and gives you a unified shortfall
report across all targets in a single command.

**Requesting more cases than the class supports will not fail** — it triggers honest
shortfall: insert_me plans what it can and reports the gap. Still, staying within the
recommended max avoids concentration warnings and produces cleaner corpora.

Full target profiles for all five bundled fixtures (including measured per-case timing)
are in `docs/support_envelope.md`.

---

## 2. Preflight: Inspect the Target

Before writing any seed files, run the preflight inspection:

```bash
insert-me inspect-target --source /path/to/local/project
```

Or write the machine-readable report to a file:

```bash
insert-me inspect-target \
  --source /path/to/local/project \
  --output inspect_out/
# Writes: inspect_out/target_suitability.json
```

Alternatively, use the script directly:

```bash
python scripts/inspect_target.py --source /path/to/local/project
```

### 2.1 What the inspection reports

| Signal | Meaning |
|---|---|
| **File count** | How many C/C++ source files were found (after exclude-pattern filtering) |
| **Candidate sites by strategy** | Raw regex-hit count per strategy — a proxy for seeder candidate density |
| **Concentration risk** | Fraction of all candidates from one pattern type that are in a single file |
| **pilot_single_case** | YES if any admitted strategy has >= 1 candidate |
| **pilot_small_batch** | YES if >= 1 strategy has >= 5 candidates across >= 2 files |
| **corpus_generation** | YES if >= 2 strategies have >= 10 candidates each across >= 3 files |
| **Blockers** | Hard stops — no usable candidate sites or no source files found |
| **Warnings** | Soft concerns — low diversity, concentration risk, too few files |

### 2.2 Suitability tiers

| Tier | Threshold | What to do |
|---|---|---|
| `pilot_single_case` | >= 1 candidate in any admitted strategy | Run one seed; inspect the bundle |
| `pilot_small_batch` | >= 1 strategy with >= 5 candidates, >= 2 files | Run 2–5 seeds; apply informal quality review |
| `corpus_generation` | >= 2 strategies with >= 10 candidates, >= 3 files, low concentration | Run the full quality gate via `generate_corpus.py` |

### 2.3 Reading blockers and warnings

**Blocker: "No C/C++ source files found"**  
Check that `--source` points at a directory with `.c`, `.cpp`, `.h` files.  
Confirm the files are not matched by exclude patterns (`*test*`, `*mock*`, `*stub*`).

**Blocker: "No candidate sites found for any corpus-admitted strategy"**  
The source files do not contain `malloc`, `free`, or pointer-dereference patterns
that the seeder can score.  The target may be too abstract (wrapper-only) or too
heavily macro-expanded for lexical analysis.

**Warning: "Only N file(s) found"**  
Not a blocker for piloting, but corpus generation needs >= 3 files for adequate
diversity across cases.

**Warning: "High concentration risk"**  
More than 80% of all candidates for a given pattern type are in one file.  A corpus
built from this target will be dominated by cases from one file — the quality gate
`ACCEPT_WITH_NOTES` threshold will trigger frequently.

---

## 3. Writing a Pilot Seed File

A seed file tells insert_me which vulnerability class and mutation strategy to use.
For a local target pilot, copy an existing seed and adjust the `seed` integer:

```bash
cp examples/seeds/sandbox/cwe416_sb_001.json my_seeds/cwe416_local_001.json
```

Edit `my_seeds/cwe416_local_001.json`:

```json
{
  "schema_version": "1.0",
  "seed_id": "cwe416_local_001",
  "cwe_id": "CWE-416",
  "mutation_strategy": "insert_premature_free",
  "seed": 1,
  "notes": "Pilot seed for local project — first candidate site",
  "target_pattern": {
    "pattern_type": "pointer_deref",
    "min_candidate_score": 0.0
  }
}
```

Key fields:

| Field | What to set |
|---|---|
| `seed_id` | Unique identifier string (no spaces) |
| `cwe_id` | `CWE-122`, `CWE-416`, `CWE-415`, `CWE-401`, `CWE-476`, or `CWE-190` (all corpus-admitted) |
| `mutation_strategy` | `alloc_size_undercount`, `insert_premature_free`, `insert_double_free`, `remove_free_call`, `remove_null_guard`, or `remove_size_cast` |
| `seed` | Integer — controls which candidate is selected; change this to explore different sites |
| `target_pattern.pattern_type` | `malloc_call` (CWE-122), `pointer_deref` (CWE-416), `free_call` (CWE-415/401), `null_guard` (CWE-476), `malloc_size_cast` (CWE-190) |

---

## 4. Single-Case Pilot

### Step 1: Run one seed

```bash
insert-me run \
  --seed-file my_seeds/cwe416_local_001.json \
  --source /path/to/local/project
```

Expected output (real mode):
```
[insert-me] starting pipeline
  seed-file : my_seeds/cwe416_local_001.json
  source    : /path/to/local/project
  output    : output
[insert-me] bundle written to: output/<run-id>/
```

### Step 2: Validate the bundle

```bash
insert-me validate-bundle output/<run-id>/
```

Exit 0 = bundle is schema-valid.

### Step 3: Inspect the audit result

```bash
python -c "
import json, pathlib
bundle = sorted(pathlib.Path('output').iterdir())[-1]
ar = json.loads((bundle / 'audit_result.json').read_text())
gt = json.loads((bundle / 'ground_truth.json').read_text())
print('Classification:', ar['classification'])
if gt['mutations']:
    m = gt['mutations'][0]
    print('File:', m['file'], 'line', m['line'])
    print('Original:', m['original_fragment'].strip())
    print('Mutated: ', m['mutated_fragment'].strip())
else:
    print('No mutation applied (NOOP). Change the seed integer.')
"
```

### Step 4: Review the diff

```bash
# On Linux/macOS/WSL
diff -r output/<run-id>/good output/<run-id>/bad
```

**If the result is NOOP:** The seed integer landed on a candidate that the patcher
could not apply a mutation to.  Change the `seed` integer in the seed file (try 2, 3,
10, 42, etc.) and re-run.

**If the result is VALID:** The mutation was applied and validated.  Inspect the diff
and confirm:
- Exactly one change between `good/` and `bad/`
- The change is in the expected location
- The surrounding code makes the inserted vulnerability plausible

---

## 5. Small Batch Pilot (2–5 seeds)

Once the single-case pilot looks good, try a small batch.

### Step 1: Create a seeds directory

```bash
mkdir my_seeds/
# Copy and adjust 2–5 seed files with different seed integers
cp examples/seeds/sandbox/cwe416_sb_001.json my_seeds/cwe416_local_001.json
cp examples/seeds/sandbox/cwe416_sb_002.json my_seeds/cwe416_local_002.json
# Edit each: change seed_id and seed integer
```

### Step 2: Run the batch

```bash
insert-me batch \
  --seed-dir my_seeds/ \
  --source /path/to/local/project
```

Exit 0 = all seeds produced VALID bundles.  
Exit 1 = at least one seed produced NOOP or INVALID.

### Step 3: Review each bundle

For each bundle in `output/`:
- Check `audit_result.json` → `classification == "VALID"`
- Check `validation_result.json` → `overall == "pass"`
- Inspect the diff (`good/` vs `bad/`)

### Step 4: Informal quality check

Before running the full quality gate, review each bundle against the criteria in
`docs/corpus_quality_gate.md`:

| Check | Quick test |
|---|---|
| C1 — Single flaw | diff shows exactly one changed region |
| C2 — Bad/good discipline | `validation_result.json` overall == pass |
| C3 — Minimal delta | `ground_truth.json` original != mutated fragment |
| C6 — Plausible context | mutation is in realistic allocating code, not test stub |
| No duplicates | No two bundles target the same `file:line` |

---

## 6. Target-Aware Corpus Planning (`plan-corpus`)

`insert-me plan-corpus` automates seed synthesis: given a source tree and a
requested case count, it inspects the target, determines which strategies are
viable, and produces a deterministic corpus plan with synthesised seed files.

### Step 1: Generate a corpus plan

```bash
insert-me plan-corpus \
  --source  /path/to/local/project \
  --count   30 \
  --output-dir  corpus_plan/
```

Output:
- `corpus_plan/corpus_plan.json` — full plan artifact (schema-validated)
- `corpus_plan/seeds/*.json` — one seed file per planned case

The command prints a summary:

```
  requested : 30
  planned   : 28
  projected : 25 (after quality gate)

  allocation by strategy:
    alloc_size_undercount          14  [VIABLE]
    insert_premature_free           8  [VIABLE]
    insert_double_free              6  [LIMITED]
```

Exit 0 = no blockers.  Exit 1 = target has blockers (see printed BLOCKER messages).

### Step 2: Inspect the plan

```bash
python -c "
import json
d = json.load(open('corpus_plan/corpus_plan.json'))
print('planned:', d['planned_count'], '/', d['requested_count'])
for c in d['cases'][:3]:
    print(' ', c['case_id'], c['target_file'], c['target_line'], c['confidence'])
"
```

### Step 3: Tune constraints if needed

```bash
# Restrict to one strategy
insert-me plan-corpus --source /path/to/project --count 10 \
  --allow-strategies alloc_size_undercount --output-dir plan_cwe122/

# Reduce concentration per file
insert-me plan-corpus --source /path/to/project --count 20 \
  --max-per-file 2 --output-dir plan_diverse/

# Only VIABLE strategies (skip LIMITED)
insert-me plan-corpus --source /path/to/project --count 20 \
  --strict-quality --output-dir plan_strict/
```

### Step 4: Execute the plan with `generate-corpus`

Once the plan looks reasonable, execute it in one step:

```bash
insert-me generate-corpus \
  --source  /path/to/local/project \
  --count   30 \
  --output-root  corpus_out/
```

This runs plan-corpus internally, then executes the full pipeline for each
planned case and reports:

```
  requested  : 30
  planned    : 28
  executed   : 28
  accepted   : 25
  rejected   : 3
```

### Step 5: Interpret the output artifacts

Three diagnostic files are written to `corpus_out/`:

| File | Purpose |
|---|---|
| `acceptance_summary.json` | Full per-strategy and per-file breakdown; `requested_count_met`, `shortfall_amount` |
| `shortfall_report.json` | Unified plan + execution shortfall with attributed categories and explanation |
| `generation_diagnostics.json` | Execution failure categories: `patcher_noop`, `validator_fail`, etc. |
| `_plan/corpus_plan.json` | Complete deterministic plan — saved for reruns |
| `_plan/seeds/*.json` | One synthesised seed JSON per planned case |

**Reading `shortfall_report.json`:**

```json
{
  "requested_count": 30,
  "planned_count": 28,
  "accepted_count": 25,
  "requested_count_met": false,
  "shortfall_amount": 5,
  "plan_shortfall": {
    "amount": 2,
    "categories": { "strategy_limited_few_candidates": 3 }
  },
  "execution_shortfall": {
    "amount": 3,
    "categories": { "patcher_noop": 2, "validator_fail": 1 }
  },
  "shortfall_explanation": "Plan shortfall: 2 case(s) not planned ..."
}
```

**Shortfall categories:**

| Category | What it means |
|---|---|
| `strategy_blocked_no_candidates` | No valid sites found for this strategy |
| `strategy_limited_few_candidates` | Strategy found candidates, but fewer than requested (single file, small target) |
| `concentration_limits` | Per-file or per-function concentration cap hit — too many cases from one location |
| `target_too_small` | Target has too few candidate sites overall |
| `sweep_exhausted` | Seed sweep reached max without finding enough unique diverse candidates |
| `patcher_noop` | Pipeline ran but patcher could not apply a mutation (Seeder picked a site patcher can't handle) |
| `validator_fail` | Patcher applied a mutation but Validator checks failed |
| `audit_invalid` | Auditor classified the mutation as INVALID |
| `pipeline_error` | Exception during pipeline execution |

### Step 6: Replay from a saved plan

Phase 12 introduced first-class replay: re-execute the exact same cases in the same order
without re-running the planning phase.

```bash
# Replay using --from-plan (directory form):
insert-me generate-corpus \
  --from-plan corpus_out/_plan/ \
  --output-root corpus_out_replay/ \
  --no-llm

# Or point directly at the plan file:
insert-me generate-corpus \
  --from-plan corpus_out/_plan/corpus_plan.json \
  --output-root corpus_out_replay/ \
  --no-llm

# If the source tree has moved, override --source:
insert-me generate-corpus \
  --from-plan corpus_out/_plan/ \
  --source /new/path/to/project \
  --output-root corpus_out_replay/ \
  --no-llm
```

The replay run writes the same set of artifacts as a generate run
(`acceptance_summary.json`, `generation_diagnostics.json`, `shortfall_report.json`,
`corpus_index.json`), but `corpus_index.json` will show `"run_mode": "replay"`.

The `corpus_index.json` artifact written by every run includes a `replay_command` field
with the exact command needed to reproduce that run.

---

## 7. Scaling to Corpus Generation (Manual Workflow)

When using manually authored seeds rather than the planning layer, you can
scale with the existing batch tools.

### Step 1: Run the quality gate

```bash
python scripts/generate_corpus.py \
  --seeds-dir   my_seeds/ \
  --source-root /path/to/local/project \
  --output-dir  output/local_corpus \
  --manifest    my_corpus_manifest.json
```

### Step 2: Verify reproducibility

```bash
python scripts/check_reproducibility.py \
  --seeds-dir   my_seeds/ \
  --source-root /path/to/local/project
```

Exit 0 = all seeds reproduce byte-identically.

### Step 3: Evaluate generated cases against a detector report

```bash
insert-me evaluate \
  --bundle output/local_corpus/<run-id>/ \
  --tool-report my_tool_report.json \
  --tool my_tool_name \
  --adjudicator heuristic
```

---

## 8. Full Pilot Decision Tree

```
inspect-target
    |
    |-- BLOCKER?  -->  Target unusable.  Fix source files or choose a different target.
    |
    |-- pilot_single_case YES?
    |       |
    |       v
    |   Run 1 seed.  NOOP? --> Change seed integer and retry.
    |   VALID?
    |       |
    |       |-- Review diff.  Plausible? --> YES
    |       |
    |       v
    |   pilot_small_batch YES?
    |       |
    |       v
    |   Run 2-5 seeds (batch).
    |   All VALID?  No duplicates?  Diffs plausible?
    |       |
    |       |-- corpus_generation YES?
    |       |       |
    |       |       v
    |       |   Run generate_corpus.py (full quality gate).
    |       |   Run check_reproducibility.py.
    |       |   --> Accepted corpus.
    |       |
    |       |-- corpus_generation NO?
    |               |
    |               v
    |           Add more source files to the target
    |           or accept limited pilot-only corpus.
    |
    |-- pilot_small_batch NO?
            |
            v
        Single-case pilot only.  Target has insufficient candidate diversity.
        Consider enriching the source files.
```

---

## 9. Supported vs. Reference Environment

| Aspect | Bundled sandbox targets | User-provided local targets |
|---|---|---|
| Reproducibility verification | Formally verified (55/55 PASS, 3 runs each) | User's responsibility via `check_reproducibility.py` |
| Quality gate | Full quality gate run, documented | User applies same gate; results are local |
| Corpus admission | Formally corpus-admitted (6 strategies, 76 seeds) | Not part of the bundled accepted corpus |
| Seed files | Committed in `examples/seeds/` | User-managed; not committed to this repo |
| Suitability confirmation | Pre-verified | Run `inspect-target` before each new target |

The bundled sandbox targets (`examples/sandbox_eval/src/`, `examples/sandbox_targets/target_b/src/`)
remain the **reproducibility reference environment**.  Local target results are
reproducible given the same source tree, but they are not included in the official
55-seed accepted corpus.

---

## 10. What Makes a Good Local Target

### 10.1 Target size and diversity requirements

| Capability | Minimum requirement | Recommended |
|---|---|---|
| **pilot_single_case** | 1 file, 1+ candidate | Any non-trivial C file |
| **pilot_small_batch** | 1 file, 5+ candidates in >= 2 functions | 1-3 files, ~100 LOC each |
| **corpus_generation (10-20 cases)** | 3+ files, each strategy VIABLE | 4-6 files, 300-800 LOC total |
| **corpus_generation (30+ cases)** | 5+ files, multiple VIABLE strategies | 8+ files, 1000+ LOC |

The **examples/local_targets/moderate/** fixture (4 files, ~340 LOC) demonstrates
corpus_generation at count=20 reliably: all 5 strategies VIABLE, 10/10 VALID on first run.

The **examples/local_targets/minimal/** fixture (1 file, ~44 LOC) demonstrates honest
shortfall: all strategies LIMITED, can only plan 8-9 cases at count=15.

### 10.2 Source patterns the seeder needs

| Strategy | Required source pattern |
|---|---|
| `alloc_size_undercount` (CWE-122) | `malloc(expr)` with arithmetic in size expression |
| `insert_premature_free` (CWE-416) | `ptr->field` dereferences with a prior malloc in scope |
| `insert_double_free` (CWE-415) | `free(ptr)` calls with simple pointer arguments |
| `remove_free_call` (CWE-401) | `free(ptr)` calls (same as CWE-415 sites) |
| `remove_null_guard` (CWE-476) | `if (!ptr)` or `if (ptr == NULL)` guards followed by `ptr->field` within 4 lines |
| `remove_size_cast` (CWE-190) | `malloc((size_t)EXPR * sizeof(T))` patterns — requires explicit `(size_t)` cast at arg start |

### 10.3 Predictors of NOOP at execution time

Even after planning, execution NOOPs are rare on well-structured targets because
`generate-corpus` uses **patcher verification** during planning: each synthesized
candidate is checked against the actual mutation handler before being included in
the plan.  Execution NOOP remaining causes:

- Guard followed by function call (not `->` dereference) within the lookahead window
- Complex expressions not matched by the patcher's single-line regex
- Source encoding issues (BOM, non-UTF-8 bytes)

If NOOPs occur, check `generation_diagnostics.json → execution_failure_categories.patcher_noop`.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| All results NOOP | No compatible target for this strategy + seed integer; or source pattern not matching | Run `inspect-target` to confirm candidate density; change seed or strategy |
| High NOOP rate in batch | Strategy pattern does not match source style | Run `inspect-target` to confirm candidate density |
| INVALID audit result | Patcher applied a mutation that failed Validator checks | Check the diff; may be a complex macro or inline pattern |
| Duplicate `file:line` in batch | Two seeds landed on the same site | Change one seed's integer |
| Reproducibility FAIL | Source tree changed between runs | Run from a clean, stable source directory |
| `pilot_single_case NO` | No C/C++ patterns found | Verify source files have `malloc`, `free`, pointer dereferences |
| Only ACCEPT_WITH_NOTES | Low candidate score or function concentration | Normal for small targets; acceptable for pilot use |
