# sandbox_eval — insert_me Evaluation-Only Sandbox Target

> **WARNING: This is an intentionally simplified, evaluation-only codebase.**
> It is NOT a production library, NOT a real application, and must NOT be deployed.
> It exists solely as a rich seeded-vulnerability insertion target for validating
> and improving the `insert_me` framework.

## Purpose

`sandbox_eval` is a small C "data structures and utilities" project created to:

1. Provide enough candidate mutation sites (malloc calls, pointer dereferences,
   integer arithmetic expressions) to support ~30 seeded vulnerability insertions.
2. Represent realistic memory-management patterns found in real C codebases.
3. Allow systematic quality review of `insert_me`-generated bad/good pairs.

## Safety contract

- This code is **never compiled or executed in any production environment**.
- All inserted vulnerabilities remain inside `output/<run-id>/bad/` bundles.
- The source tree under `src/` is the **clean** reference; mutations produce
  independent bad-tree copies and never touch this directory.
- Do not use any file in `src/` as a dependency in any real project.

## Source files

| File | Domain | Key patterns |
|---|---|---|
| `list.c` | Doubly-linked list | Node alloc, arrow dereference chains |
| `strbuf.c` | Dynamic string buffer | malloc(n * sizeof), realloc, struct fields |
| `cache.c` | LRU entry cache | Entry alloc, key/value dereferences |
| `queue.c` | FIFO / priority queue | Node alloc, data pointer dereference |
| `htable.c` | Hash table | Bucket alloc, entry chains, string copy |
| `graph.c` | Directed graph | Vertex/edge alloc, adjacency lists |

## Seed files

Seed files for this sandbox are in `examples/seeds/sandbox/`.
Each seed targets one specific mutation site via a unique seed integer.

## Running experiments

```bash
# Single insertion (CWE-416, targeting list.c)
insert-me run \
  --seed-file examples/seeds/sandbox/cwe416_list_001.json \
  --source examples/sandbox_eval/src

# Evaluate with heuristic adjudicator
insert-me evaluate \
  --bundle output/<run-id>/ \
  --tool-report examples/evaluation/semantic_match_report.json \
  --tool manual-review
```
