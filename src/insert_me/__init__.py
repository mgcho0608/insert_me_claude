"""
insert_me — Juliet-derived seeded vulnerability insertion and per-project
evaluation framework for C/C++ codebases.

Insertion pipeline:
    Seeder → Patcher → Validator → Auditor → output bundle

Evaluation (separate, post-run step):
    insert-me evaluate --bundle PATH --tool-report PATH --tool NAME
    → evaluation.Evaluator → match_result.json + coverage_result.json

LLM assistance is optional and accessed only through the adapter layer
in insert_me.llm.adapter. Disabling it does not affect any deterministic
artifact.
"""

__version__ = "0.1.0.dev0"

# Schema version embedded in every output artifact.
ARTIFACT_SCHEMA_VERSION = "1.0"
