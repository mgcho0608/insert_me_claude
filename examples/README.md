# Examples — insert_me

This directory will contain end-to-end usage examples once the core pipeline
is implemented (Phase 6+).

---

## Planned examples

### `basic_cwe122/`
A minimal example: insert a CWE-122 (heap-based buffer overflow) into a
small, self-contained C program.

Files (to be added in Phase 6):
- `source/` — the original C source tree
- `run.sh` — shell script invoking `insert-me run`
- `expected_output/` — reference output bundle for diff/comparison

### `multi_target/`
Demonstrate running against a larger source tree with multiple candidate targets,
showing how the seeder ranks and selects among them.

### `no_llm/`
Demonstrate a full run with `--no-llm`, confirming that output bundles are
complete and valid without any LLM calls.

### `custom_adapter/`
Demonstrate wiring a custom LLM adapter (stub/local model) by implementing
`LLMAdapter` and registering it in `ADAPTER_REGISTRY`.

---

*Examples are intentionally absent in Phase 0 (skeleton). See ROADMAP.md.*
