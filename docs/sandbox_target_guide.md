# Sandbox Target Guide — insert_me

> **Phase:** 8 — Reliability, Reproducibility, and Corpus-Quality Hardening  
> **Audience:** Engineers adding new sandbox targets or verifying existing ones

---

## 1. What Is a Sandbox Target?

A **sandbox target** is a small, self-contained, evaluation-only C or C++ source tree
that is used exclusively for testing insert_me's corpus generation capabilities.

It is:
- **evaluation-only** — not a production library, not a widely-deployed open-source project
- **synthetic** — written or curated for the purpose of providing rich mutation candidate sites
- **deterministic** — the same source tree content always produces the same candidates
- **isolated** — no external dependencies; can be pointed at with `--source` without setup

It is NOT:
- a real production codebase
- a maintained open-source library with real users
- a benchmark harness or test suite

---

## 2. Current Sandbox Targets

### Target A — `examples/sandbox_eval/src/`

**Status:** Primary sandbox (Phase 7C–8)  
**Files:** 6 C source files, ~1,450 lines total  
**CWE-416 candidate sites:** 66+  
**CWE-122 candidate sites:** 14+  

| File | Purpose | CWE patterns |
|---|---|---|
| `list.c` | Doubly-linked list with node operations | CWE-416 (pointer_deref), CWE-122 (malloc with expr) |
| `strbuf.c` | String buffer with clone/concat operations | CWE-416, CWE-122 |
| `cache.c` | LRU cache with bucket chaining | CWE-416, CWE-122 |
| `queue.c` | Priority queue and ring-queue structures | CWE-416, CWE-122 |
| `htable.c` | Open-addressing hash table | CWE-416, CWE-122 |
| `graph.c` | Directed graph with adjacency lists | CWE-416, CWE-122 |

**Accepted corpus (as of Phase 8):** 30 cases (19 CWE-416, 11 CWE-122)  
**Unique target functions:** 16 across 6 files  
**Reproducibility:** 100% verified (`scripts/check_reproducibility.py`)

---

## 3. What Makes a Good Sandbox Target?

A sandbox target should satisfy the following properties before being used for corpus
generation:

### 3.1 Structural Requirements

| Property | Why it matters |
|---|---|
| Multiple source files (≥ 3) | Reduces concentration of cases in one file |
| Multiple functions per file (≥ 3 per file) | Ensures function-level diversity |
| Real allocation patterns (`malloc`, `calloc`, `realloc`) | Seeder requires allocation calls for CWE-122 and CWE-416 targets |
| Struct field writes after allocation | Required for `insert_premature_free` to produce clean UAF sites |
| Deep-copy functions (key copying, label copying) | High-value alloc_size_undercount targets |
| No test functions, no stub functions | Seeder excludes `*test*` and `*mock*` patterns; include explicitly ensures quality |

### 3.2 Quality Requirements

| Property | Why it matters |
|---|---|
| No global allocations at file scope | Avoids targets outside function scope |
| Consistent error-handling idiom | `if (!ptr) { free(...); return NULL; }` pattern enables clean seeder scoring |
| No compiler-generated or macro-heavy patterns | Lexical seeder relies on readable source |
| UTF-8 encoding, Unix line endings | Required by source scanner |
| Standard C89/C99/C11 style | Regex patterns tuned for standard C |

### 3.3 Capacity Requirements

Before declaring a target suitable for N cases, verify:

```bash
python scripts/generate_corpus.py \
  --seeds-dir examples/seeds/sandbox \
  --source-root <target_dir> \
  --output-dir output/verify \
  --dry-run
```

A target can support N accepted cases if:
- Automated quality gate ACCEPT rate ≥ 80% for those N cases
- No more than 5 cases per source file (to avoid over-concentration)
- No more than 3 cases per source function
- 0 duplicate targets

---

## 4. Creating a New Sandbox Target

Follow these steps to add a new evaluation-only sandbox target.

### Step 1 — Design the source files

Write 3–6 C source files with realistic memory management patterns. Aim for:
- 100–300 lines per file
- At least 4–6 allocating functions per file
- Multi-field struct initialisation after malloc (rich CWE-416 sites)
- `n * sizeof(T)` allocation patterns (rich CWE-122 sites)
- Deep-copy functions that allocate and copy string/buffer fields

Label each file with an evaluation-only header comment:

```c
/*
 * <filename>.c -- <brief description> for insert_me sandbox evaluation.
 *
 * EVALUATION ONLY: not production code.
 */
```

### Step 2 — Place files under `examples/sandbox_targets/<target_name>/src/`

Example:
```
examples/sandbox_targets/target_b/src/
    pool.c
    arena.c
    ring_buf.c
```

### Step 3 — Verify candidate site density

```bash
# Dry-run a sample seed against the new target to check candidate count
python -m insert_me.cli run \
  --seed-file examples/seeds/sandbox/cwe416_sb_001.json \
  --source examples/sandbox_targets/target_b/src \
  --output output/verify \
  --dry-run
```

Check `patch_plan.json → skipped_count` — a high skipped count means many candidates
are scoring below the min_candidate_score threshold. If `targets` is empty, the source
tree has too few suitable patterns for the configured seed.

### Step 4 — Create seed files

Copy an existing seed file and adjust `seed_id`, `seed` integer, and `notes`:

```bash
cp examples/seeds/sandbox/cwe416_sb_001.json examples/seeds/target_b/cwe416_tb_001.json
# Edit seed integer and notes
```

Run the seed against the new target and verify the selected target is clean:
```bash
python -m insert_me.cli run \
  --seed-file examples/seeds/target_b/cwe416_tb_001.json \
  --source examples/sandbox_targets/target_b/src \
  --output output/target_b
```

### Step 5 — Run the full quality gate

```bash
python scripts/generate_corpus.py \
  --seeds-dir examples/seeds/target_b \
  --source-root examples/sandbox_targets/target_b/src \
  --output-dir output/target_b \
  --manifest examples/corpus_target_b.json
```

Review the quality gate report. Fix any REVISE or REJECT cases before declaring the
target ready.

### Step 6 — Run reproducibility check

```bash
python scripts/check_reproducibility.py \
  --seeds-dir examples/seeds/target_b \
  --source-root examples/sandbox_targets/target_b/src
```

All seeds must pass reproducibility before the target is added to the accepted suite.

---

## 5. When to Add a New Target

Add a new sandbox target when:

| Condition | Action |
|---|---|
| A single file contributes > 40% of all accepted cases | Add target with richer file diversity |
| A single function contributes > 15% of all accepted cases | Add target or new files to existing target |
| Accepted case count stagnates (REVISE/REJECT rate > 20%) | Investigate seeder or add richer target |
| Need to test a new mutation strategy | Create purpose-built target with relevant patterns |

Do NOT add a new target purely to inflate case count. Quality comes before quantity.

---

## 6. Sandbox Target Anti-Patterns

Avoid these patterns in sandbox source files:

| Anti-pattern | Why |
|---|---|
| `malloc(sizeof(T))` without subsequent field writes | alloc_size_undercount leaves no downstream overflow; CWE-416 has no dereference to mutate |
| `ptr = malloc(...); if (!ptr) abort();` | abort() after null-check means no error handling — valid but seeder avoids abort paths |
| Allocations in loops | Loop-body penalty in seeder will reject many candidates from loop-heavy files |
| Inline allocations that immediately return | Seeder cannot find prior malloc context in scope |
| Header-only code | No .c files to scan |
| Deeply macro-expanded patterns | Lexical seeder cannot resolve macro expansions |
| C++ templates | Template instantiation not visible at lexical scan level |
