"""
Pipeline orchestrator for insert_me.

Canonical pipeline stages:
    Seeder → Patcher → Validator → Auditor (→ optional LLM enrichment)

Current implementation status
------------------------------
This module implements a **deterministic dry-run pipeline** that produces
all expected output artifacts without applying any real source mutations.
All emitted artifacts are schema-validated before the function returns.

Full AST patching (Seeder, Patcher, Validator, Auditor with real mutations)
is deferred to Phases 3–6. The dry-run pipeline exercises the complete
artifact contract so downstream tools can integrate immediately.

Usage
-----
    from insert_me.pipeline import run_pipeline
    from insert_me.config import Config, load_config, apply_cli_overrides
    from pathlib import Path

    config = load_config()
    config = apply_cli_overrides(
        config,
        seed_file=Path("examples/seeds/cwe122_heap_overflow.json"),
        source_path=Path("/path/to/project"),
    )
    bundle = run_pipeline(config, dry_run=True)
    print(bundle.root)
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import (
    BundlePaths,
    derive_run_id,
    derive_run_id_from_seed_data,
    write_json_artifact,
)
from insert_me.config import Config
from insert_me.schema import (
    SCHEMA_AUDIT_RECORD,
    SCHEMA_AUDIT_RESULT,
    SCHEMA_GROUND_TRUTH,
    SCHEMA_PATCH_PLAN,
    SCHEMA_SEED,
    SCHEMA_VALIDATION_RESULT,
    validate_artifact,
)


def run_pipeline(config: Config, *, dry_run: bool = False) -> BundlePaths:
    """
    Execute the insert_me pipeline.

    In the current implementation this is always a dry-run: all output
    artifacts are emitted and schema-validated, but no source tree mutation
    is applied. Pass ``dry_run=True`` explicitly to document intent;
    omitting it produces the same behaviour until the Patcher is implemented.

    Parameters
    ----------
    config:
        Fully-resolved Config dataclass. Must have at least one of:
        - ``config.pipeline.seed_file`` (canonical path to a seed JSON file)
        - ``config.pipeline.seed`` + ``config.pipeline.spec_path`` (legacy)
        And ``config.pipeline.source_path`` (path to C/C++ source root).

    dry_run:
        When True, no source files are modified. Currently always True
        regardless of this flag; the flag is preserved for interface
        compatibility when the Patcher is added in Phase 4.

    Returns
    -------
    BundlePaths
        Resolved paths to all artifacts in the completed output bundle.

    Raises
    ------
    ValueError
        If required config fields are missing or contradictory.
    FileNotFoundError
        If the seed file does not exist.
    jsonschema.ValidationError
        If a required seed artifact fails schema validation.
    """
    from insert_me import __version__

    # ------------------------------------------------------------------
    # 1. Resolve and load seed input
    # ------------------------------------------------------------------
    seed_data, input_path = _resolve_seed_input(config)

    # Validate canonical seed input against schema (legacy path skips this)
    if config.pipeline.seed_file is not None:
        validate_artifact(seed_data, SCHEMA_SEED)

    seed_int: int = seed_data["seed"]

    # ------------------------------------------------------------------
    # 2. Derive deterministic run_id
    # ------------------------------------------------------------------
    if config.pipeline.run_id:
        run_id = config.pipeline.run_id
    elif config.pipeline.seed_file is not None:
        run_id = derive_run_id_from_seed_data(
            seed_data=seed_data,
            source_path=config.pipeline.source_path or Path("."),
            pipeline_version=__version__,
        )
    else:
        # Legacy path: derive from int seed + spec file content
        run_id = derive_run_id(
            seed=seed_int,
            spec_path=config.pipeline.spec_path or Path(""),
            source_path=config.pipeline.source_path or Path("."),
            pipeline_version=__version__,
        )

    # ------------------------------------------------------------------
    # 3. Create output bundle directories
    # ------------------------------------------------------------------
    bundle = BundlePaths.from_run_id(config.pipeline.output_root, run_id)
    bundle.create_dirs()

    # ------------------------------------------------------------------
    # 4. Shared values
    # ------------------------------------------------------------------
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    plan_id = f"plan-{run_id}"
    source_root_str = str(config.pipeline.source_path or Path("."))
    spec_hash = _sha256_file(input_path) if input_path and input_path.exists() else "dry-run"

    # ------------------------------------------------------------------
    # 5. Emit patch_plan.json
    # ------------------------------------------------------------------
    patch_plan: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "plan_id": plan_id,
        "run_id": run_id,
        "seed_id": seed_data.get("seed_id", ""),
        "seed": seed_int,
        "status": "PENDING",
        "created_at": now_utc,
        "targets": [],
    }
    write_json_artifact(bundle.patch_plan, patch_plan)
    validate_artifact(patch_plan, SCHEMA_PATCH_PLAN)

    # ------------------------------------------------------------------
    # 6. Emit validation_result.json
    # ------------------------------------------------------------------
    validation_result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "result_id": f"vr-{run_id}",
        "run_id": run_id,
        "plan_id": plan_id,
        "overall": "SKIP",
        "checks": [],
    }
    write_json_artifact(bundle.validation_result, validation_result)
    validate_artifact(validation_result, SCHEMA_VALIDATION_RESULT)

    # ------------------------------------------------------------------
    # 7. Emit audit_result.json
    # ------------------------------------------------------------------
    audit_result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "audit_id": f"ar-{run_id}",
        "run_id": run_id,
        "classification": "NOOP",
        "confidence": "low",
        "evidence": [
            {
                "source": "rule_engine",
                "observation": "Dry-run mode: no mutations applied.",
                "weight": "neutral",
            }
        ],
        "reviewer": {
            "type": "deterministic",
            "name": "dry_run_v1",
        },
    }
    write_json_artifact(bundle.audit_result, audit_result)
    validate_artifact(audit_result, SCHEMA_AUDIT_RESULT)

    # ------------------------------------------------------------------
    # 8. Emit ground_truth.json
    # ------------------------------------------------------------------
    ground_truth: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "cwe_id": seed_data.get("cwe_id", "CWE-0"),
        "spec_id": seed_data.get("seed_id", ""),
        "seed": seed_int,
        "mutations": [],
        "validation_passed": False,
    }
    write_json_artifact(bundle.ground_truth, ground_truth)
    validate_artifact(ground_truth, SCHEMA_GROUND_TRUTH)

    # ------------------------------------------------------------------
    # 9. Emit audit.json
    # ------------------------------------------------------------------
    audit_record: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "seed": seed_int,
        "spec_path": str(input_path) if input_path else "",
        "spec_hash": spec_hash,
        "source_root": source_root_str,
        "source_hash": "dry-run",
        "pipeline_version": __version__,
        "timestamp_utc": now_utc,
        "validation_verdict": {
            "passed": False,
            "checks": [],
        },
    }
    write_json_artifact(bundle.audit, audit_record)
    validate_artifact(audit_record, SCHEMA_AUDIT_RECORD)

    return bundle


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_seed_input(
    config: Config,
) -> tuple[dict[str, Any], Path | None]:
    """
    Resolve the seed input to a seed_data dict and its source path.

    Canonical path: config.pipeline.seed_file → load and return JSON.
    Legacy path:    config.pipeline.seed + config.pipeline.spec_path
                    → construct a minimal seed_data dict.

    Returns
    -------
    (seed_data, input_path)
        seed_data: parsed dict ready for pipeline use
        input_path: path to the seed/spec file (for hashing), or None
    """
    if config.pipeline.seed_file is not None:
        seed_file = config.pipeline.seed_file
        if not seed_file.exists():
            raise FileNotFoundError(f"Seed file not found: {seed_file}")
        with open(seed_file, encoding="utf-8") as fh:
            seed_data: dict[str, Any] = json.load(fh)
        return seed_data, seed_file

    if config.pipeline.seed is not None:
        # Legacy: reconstruct minimal seed_data from int seed + spec path
        spec_path = config.pipeline.spec_path
        seed_id = spec_path.stem if spec_path else "legacy"
        seed_data = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "seed_id": seed_id,
            "seed": config.pipeline.seed,
            "cwe_id": "CWE-0",
            "vulnerability_class": "unknown",
            "mutation_strategy": "unknown",
            "target_pattern": {"pattern_type": "custom"},
        }
        return seed_data, spec_path

    raise ValueError(
        "No seed input configured. Provide --seed-file PATH "
        "(canonical) or --seed INT --spec PATH (legacy)."
    )


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file's contents."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()
