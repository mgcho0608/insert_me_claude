"""
insert_me — Deterministic seeded vulnerability generation for C/C++.

Core pipeline:
    Seeder → Patcher → Validator → Auditor → output bundle

LLM assistance is optional and accessed only through the adapter layer
in insert_me.llm.adapter. Disabling it does not affect core outputs.
"""

__version__ = "0.1.0.dev0"

# Schema version embedded in every output artifact.
ARTIFACT_SCHEMA_VERSION = "1.0"
