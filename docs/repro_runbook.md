# Reproducibility Runbook — insert_me Corpus Generation

> **Phase:** 9 — planning layer complete  
> **Audience:** Engineers reproducing or extending the sandbox corpus, or using the
> planning layer on a local evaluation-only target project.
>
> This runbook is self-contained. Follow it from a clean clone to produce a verified,
> quality-gated corpus. No Claude-level judgment is required.

---

## Prerequisites

| Requirement | Version / Notes |
|---|---|
| Python | ≥ 3.10 |
| Git | Any recent version |
| No LLM / API key | All steps work fully offline |
| No compiler | insert_me uses lexical/regex analysis only |

---

## 1. Setup from a Fresh Clone

```bash
git clone <repo_url> insert_me
cd insert_me

# Install in editable mode (sets up the insert-me CLI)
pip install -e .

# Verify installation
insert-me --version
```

Expected output: `insert-me x.y.z` (version string).

---

## 2. Directory Structure

After cloning, the relevant directories are:

```
insert_me/
├── examples/
│   ├── sandbox_eval/src/            ← evaluation-only C source files (Sandbox Target A, 6 files)
│   ├── sandbox_targets/target_b/src/ ← Sandbox Target B (3 files)
│   └── seeds/
│       ├── sandbox/                 ← 40 seed files for Sandbox Target A
│       └── target_b/                ← 15 seed files for Sandbox Target B
├── docs/
│   ├── corpus_quality_gate.md  ← acceptance rubric
│   ├── issue_fix_log.md        ← issues found and fixed during hardening
│   ├── sandbox_target_guide.md ← guide for sandbox targets
│   └── repro_runbook.md        ← this document
├── scripts/
│   ├── generate_corpus.py      ← batch generation + quality gate
│   └── check_reproducibility.py ← determinism verification
└── output/                     ← generated bundles (created on first run)
```

---

## 3. Running a Single Case

To run one seed and inspect the output:

```bash
insert-me run \
  --seed-file examples/seeds/sandbox/cwe416_sb_001.json \
  --source    examples/sandbox_eval/src \
  --output    output/single_case
```

This writes a bundle directory under `output/single_case/<run_id>/` containing:
- `patch_plan.json` — candidate selection
- `ground_truth.json` — mutation oracle
- `audit_result.json` — VALID/INVALID/AMBIGUOUS/NOOP classification
- `validation_result.json` — 5 deterministic checks
- `bad/` — mutated source tree
- `good/` — original source tree (byte-identical)

To inspect the diff between bad and good trees:

```bash
# On Linux/macOS
diff -r output/single_case/*/good output/single_case/*/bad

# Using Python (cross-platform)
python - << 'EOF'
import subprocess, pathlib
bundles = list(pathlib.Path("output/single_case").iterdir())
b = bundles[-1]
print(f"Bundle: {b.name}")
import json
gt = json.loads((b / "ground_truth.json").read_text())
m = gt["mutations"][0]
print(f"CWE: {gt['cwe_id']}")
print(f"File: {m['file']}:{m['line']}")
print(f"Original: {m['original_fragment'].strip()}")
print(f"Mutated:  {m['mutated_fragment'].strip()}")
EOF
```

---

## 4. Running the Full Corpus Batch

### 4.1 Run all 40 seeds (Sandbox Target A) with quality gate

```bash
python scripts/generate_corpus.py \
  --seeds-dir  examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --output-dir  output/corpus \
  --manifest    examples/corpus_manifest.json
```

To run Sandbox Target B (15 seeds):

```bash
python scripts/generate_corpus.py \
  --seeds-dir  examples/seeds/target_b \
  --source-root examples/sandbox_targets/target_b/src \
  --output-dir  output/corpus_target_b \
  --manifest    examples/corpus_manifest_target_b.json
```

Expected output:
- Per-case quality gate classification (ACCEPT / ACCEPT_WITH_NOTES / REVISE / REJECT)
- Batch summaries
- Final corpus health metrics
- `examples/corpus_manifest.json` written

**Exit codes:**
- `0` — all cases ACCEPT or ACCEPT_WITH_NOTES
- `1` — one or more cases REVISE or REJECT (fix the issue, re-run)
- `2` — configuration error (wrong path, etc.)

### 4.2 Run in controlled batches (recommended for new targets)

```bash
python scripts/generate_corpus.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --output-dir  output/corpus \
  --manifest    examples/corpus_manifest.json \
  --batch-sizes 2,5,10,20,30,40
```

This pauses after each cumulative checkpoint (2, then 5, then 10, etc.) and prints
a quality gate summary. Inspect each batch before proceeding.

### 4.3 Dry run (plan only, no pipeline execution)

```bash
python scripts/generate_corpus.py \
  --seeds-dir examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --dry-run
```

---

## 5. Running the Reproducibility Check

```bash
python scripts/check_reproducibility.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --runs        2
```

This runs each seed twice and compares the deterministic artifact fields across runs.

**Expected output:** `RESULT: All seeds reproduce identically.`  
**Exit code:** `0` on success, `1` on any divergence.

To keep the run directories for debugging:
```bash
python scripts/check_reproducibility.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --keep-outputs \
  --verbose
```

---

## 6. Evaluating a Case Against a Detector Report

If you have a detector tool report (in the insert_me detector report schema), evaluate
one bundle:

```bash
insert-me evaluate \
  --bundle      output/corpus/<run_id> \
  --tool-report my_tool_report.json \
  --tool        my_tool_name \
  --adjudicator heuristic
```

This writes:
- `output/corpus/<run_id>/match_result.json`
- `output/corpus/<run_id>/coverage_result.json`
- `output/corpus/<run_id>/adjudication_result.json` (if semantic matches found)

The `--adjudicator heuristic` flag uses the deterministic offline heuristic adjudicator.
No LLM or API key is required.

See `docs/artifact_contracts.md §7` for the evaluation artifact schema details.

---

## 7. Reading the Corpus Manifest

After running `generate_corpus.py`, inspect the manifest:

```bash
python -c "
import json
m = json.load(open('examples/corpus_manifest.json'))
print(f'Total cases: {m[\"total_cases\"]}')
print(f'Accepted: {m[\"accepted\"]}')
print(f'Accepted with notes: {m[\"accepted_with_notes\"]}')
print(f'Revised: {m[\"revised\"]}')
print(f'Rejected: {m[\"rejected\"]}')
print()
for c in m['cases']:
    print(f\"  {c['classification']:<20} {c['cwe_id']:<8} {c['target_file']}:{c['target_line']}\")
"
```

---

## 8. Interpreting Quality Gate Results

See `docs/corpus_quality_gate.md` for the full rubric. Quick guide:

| Result | Meaning | What to do |
|---|---|---|
| `ACCEPT` | All automated criteria pass | Case is accepted in corpus |
| `ACCEPT_WITH_NOTES` | Minor concern noted | Accepted; review the note; may improve with target diversity |
| `REVISE` | Fixable issue (audit AMBIGUOUS, validation fail) | Read the reason; fix seed or seeder; re-run |
| `REJECT` | Unfixable (INVALID audit, duplicate, no mutation) | Exclude from corpus; document in issue_fix_log.md |

---

## 9. What to Do If a Case REVISEs or REJECTs

1. **Read the reason** printed by `generate_corpus.py --verbose`
2. **Identify the root cause:**
   - `NOOP` audit → no mutation was applied (patcher found no compatible target)
   - `INVALID` audit → mutation site does not match expected pattern
   - Validation fail → bad/good trees don't meet discipline checks
   - Duplicate target → change the seed integer in the seed file
3. **Fix the seed file** (change the `seed` integer to select a different candidate)
4. **Re-run** the single seed to verify: `insert-me run --seed-file ...`
5. **Re-run** the full batch to confirm no regression
6. **Document** the issue and fix in `docs/issue_fix_log.md` (follow the IFL-NNN format)

---

## 10. Adding New Cases to the Corpus

1. Choose an unused seed integer that produces a unique target:
   ```bash
   # Check what targets are already taken
   python -c "
   import json, pathlib
   m = json.load(open('examples/corpus_manifest.json'))
   for c in m['cases']:
       print(f\"{c['target_file']}:{c['target_line']}\")
   "
   ```

2. Find a new target with a different seed integer:
   ```bash
   python - << 'EOF'
   from insert_me.pipeline.seeder import Seeder
   import json, pathlib
   spec = json.loads(pathlib.Path("examples/seeds/sandbox/cwe416_sb_001.json").read_text())
   for try_seed in range(50, 200):
       spec["seed"] = try_seed
       ptl = Seeder(try_seed, spec, pathlib.Path("examples/sandbox_eval/src")).run()
       if ptl.targets:
           t = ptl.targets[0]
           print(f"seed={try_seed}: {t.file}:{t.line}  {t.context.get('expression','')[:50]}")
           break
   EOF
   ```

3. Create a new seed file: copy an existing one, update `seed_id`, `seed`, and `notes`.

4. Run and classify the new case:
   ```bash
   insert-me run \
     --seed-file examples/seeds/sandbox/cwe416_sb_020.json \
     --source    examples/sandbox_eval/src \
     --output    output/corpus
   ```

5. Re-run `generate_corpus.py` to update the manifest.

---

## 11. Running the Test Suite

```bash
python -m pytest tests/ -q
```

Expected: all tests pass (no failures). The test suite does not require a real LLM.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No module named insert_me` | Package not installed | Run `pip install -e .` from repo root |
| `bundle written to: <empty>` | Pipeline error (wrong path, bad seed) | Check `--source` path exists; validate seed with `insert-me validate-bundle` |
| `NOOP` audit result | No compatible mutation target found | Change the `seed` integer in the seed file |
| Reproducibility FAIL | Non-determinism introduced | Run with `--verbose` to see which field differs; check for timestamp injection in pipeline |
| Duplicate target in corpus | Two seeds produce same file:line | Change one seed's integer; re-run |
| All scores 0.0 | Source tree empty or no pattern matches | Verify `--source` points at a directory with .c files |

---

## 13. Clean Re-run from Scratch

To reproduce the exact accepted corpus from scratch:

```bash
# 1. Start from a clean output directory
rm -rf output/corpus output/corpus_target_b output/repro_check

# 2a. Run Sandbox Target A (40 seeds)
python scripts/generate_corpus.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src \
  --output-dir  output/corpus \
  --manifest    examples/corpus_manifest.json

# 2b. Run Sandbox Target B (15 seeds)
python scripts/generate_corpus.py \
  --seeds-dir   examples/seeds/target_b \
  --source-root examples/sandbox_targets/target_b/src \
  --output-dir  output/corpus_target_b \
  --manifest    examples/corpus_manifest_target_b.json

# 3a. Verify reproducibility for Target A
python scripts/check_reproducibility.py \
  --seeds-dir   examples/seeds/sandbox \
  --source-root examples/sandbox_eval/src

# 3b. Verify reproducibility for Target B
python scripts/check_reproducibility.py \
  --seeds-dir   examples/seeds/target_b \
  --source-root examples/sandbox_targets/target_b/src

# 4. Run tests to confirm nothing regressed
python -m pytest tests/ -q
```

All commands should succeed with exit code 0. Combined accepted corpus: 55 cases
(40 Target A + 15 Target B), 100% ACCEPT or ACCEPT_WITH_NOTES, 55/55 reproducibility PASS.

---

## 14. Planning Layer Reproducibility

The planning layer (`plan-corpus`, `generate-corpus`) is also deterministic.

### Guarantee

Given the same inputs:
- same source tree (files + content)
- same `--count` N
- same `PlanConstraints` (max-per-file, max-per-function, allow-strategies, etc.)

insert_me will always produce:
- the same `source_hash` in `corpus_plan.json`
- the same set of planned cases (same `case_id`, `seed_integer`, `target_file`, `target_line`)
- the same `seeds/*.json` files (byte-for-byte identical)

This follows from: TargetInspector uses `seed=1` (fixed) for enumeration;
SeedSynthesizer sweeps seed integers 1, 2, 3, ... in fixed order; allocation
uses `int()` floor + sorted leftover top-up (deterministic given candidate counts).

### Verification

```bash
# Run plan-corpus twice on the same source; compare corpus_plan.json
insert-me plan-corpus --source examples/sandbox_eval/src --count 20 --output-dir /tmp/plan_run1/
insert-me plan-corpus --source examples/sandbox_eval/src --count 20 --output-dir /tmp/plan_run2/

# Both corpus_plan.json files must be byte-identical
python -c "
a = open('/tmp/plan_run1/corpus_plan.json').read()
b = open('/tmp/plan_run2/corpus_plan.json').read()
assert a == b, 'FAIL: plans differ'
print('PASS: plans are identical')
"
```

### What can break reproducibility

| Change | Effect |
|---|---|
| Source file added, removed, or modified | `source_hash` changes; plan changes |
| `--count` changed | Allocation changes |
| Any `PlanConstraints` argument changed | Plan changes |
| Different Python version | Unlikely; no floating-point or hash randomness used |
| `PYTHONHASHSEED` | Not used by the planning layer |

The planning layer does NOT use Python's `random`, `uuid`, or time-dependent functions.
All randomness is seeded through the explicit `seed_integer` parameter passed to the Seeder.

### Planning reproducibility vs. generation reproducibility

| Layer | Guaranteed reproducible? | Artifact |
|---|---|---|
| Planning (`plan-corpus`) | YES — byte-identical on identical inputs | `corpus_plan.json`, `seeds/*.json` |
| Generation (`generate-corpus` pipeline) | YES — given same seed JSON + same source tree | `bad/`, `good/`, all 5 pipeline artifacts |
| Quality gate classification | YES — HeuristicAdjudicator is fully offline and deterministic | `audit_result.json` ACCEPT/REJECT |
| LLM adjudication | NO — disabled by default; use `--adjudicator heuristic` | N/A |
