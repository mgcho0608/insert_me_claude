# Local Target Examples

These directories simulate user-provided local evaluation-only target projects
of different richness levels. They are used to test insert_me's planning layer —
specifically honest count-shortfall reporting and diversity allocation.

## minimal/

A single-file C utility (`counter.c`) with a small number of heap operations.

- **Expected suitability**: `pilot_single_case=YES`, `pilot_small_batch=NO`, `corpus_generation=NO`
- **Use**: Tests that insert_me honestly reports it cannot reach a high requested
  count (e.g., 20) on a target with few diverse candidates.
- **Try it**:
  ```bash
  insert-me inspect-target --source examples/local_targets/minimal/src --output /tmp/minimal_inspect/
  insert-me plan-corpus    --source examples/local_targets/minimal/src --count 20
  ```

## moderate/

Four C source files: an arena allocator, a ring buffer, a key-value store, and a
string vector. Provides a realistic variety of `malloc_call`, `free_call`, and
`pointer_deref` patterns across multiple files and functions.

- **Expected suitability**: `pilot_small_batch=YES`, `corpus_generation=YES` (for admitted strategies)
- **Use**: Tests that insert_me can plan a meaningful corpus across strategies,
  allocate proportionally, and fill up to the requested count.
- **Try it**:
  ```bash
  insert-me inspect-target --source examples/local_targets/moderate/src --output /tmp/moderate_inspect/
  insert-me plan-corpus    --source examples/local_targets/moderate/src --count 15 --output-dir /tmp/moderate_plan/
  ```

## How these differ from sandbox targets

| | sandbox_eval / target_b | minimal | moderate |
|---|---|---|---|
| Purpose | Reference corpus (reproducibility-verified) | Poor-target test | Pilot/planning test |
| Files | 6 / 3 | 1 | 4 |
| Accepted seeds | 40 / 15 | 0 (not yet seeded) | 0 (not yet seeded) |
| Quality gate | Formally run | N/A | N/A |
| Reproducibility | 100% (55/55) | N/A | N/A |

These local targets are NOT quality-gate verified. They exist solely to test
inspect-target, plan-corpus, and count-driven allocation logic.
