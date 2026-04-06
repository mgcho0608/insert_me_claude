"""
Pipeline orchestrator for insert_me.

Canonical pipeline stages:
    Seeder → Patcher → Validator → Auditor (→ optional LLM enrichment)

Current implementation status
------------------------------
Phase 3 (Seeder) is now implemented: the pipeline performs real deterministic
source discovery and candidate target generation. All output artifacts are
emitted and schema-validated. No source files are modified.

Patcher (Phase 4), Validator (Phase 5), and Auditor with real mutations (Phase 6)
are deferred. The dry-run pipeline is the only execution mode for now.

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
from insert_me.pipeline.seeder import PatchTarget, PatchTargetList, Seeder
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

    The pipeline now includes a real Seeder pass: it discovers C/C++ source
    files under source_path and extracts deterministic candidate targets using
    lexical heuristics. No source files are modified.

    Parameters
    ----------
    config:
        Fully-resolved Config dataclass. Must have at least one of:
        - ``config.pipeline.seed_file`` (canonical path to a seed JSON file)
        - ``config.pipeline.seed`` + ``config.pipeline.spec_path`` (legacy)
        And ``config.pipeline.source_path`` (path to C/C++ source root).
        If source_path does not exist, the Seeder returns no candidates and
        patch_plan.json is emitted with status=PENDING and empty targets.

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
    source_root = config.pipeline.source_path or Path(".")

    # ------------------------------------------------------------------
    # 2. Run Seeder — deterministic source discovery + candidate extraction
    # ------------------------------------------------------------------
    seeder = Seeder(seed=seed_int, spec=seed_data, source_root=source_root)
    target_list: PatchTargetList = seeder.run()

    # ------------------------------------------------------------------
    # 3. Derive deterministic run_id
    # ------------------------------------------------------------------
    if config.pipeline.run_id:
        run_id = config.pipeline.run_id
    elif config.pipeline.seed_file is not None:
        run_id = derive_run_id_from_seed_data(
            seed_data=seed_data,
            source_path=source_root,
            pipeline_version=__version__,
        )
    else:
        run_id = derive_run_id(
            seed=seed_int,
            spec_path=config.pipeline.spec_path or Path(""),
            source_path=source_root,
            pipeline_version=__version__,
        )

    # ------------------------------------------------------------------
    # 4. Create output bundle directories
    # ------------------------------------------------------------------
    bundle = BundlePaths.from_run_id(config.pipeline.output_root, run_id)
    bundle.create_dirs()

    # ------------------------------------------------------------------
    # 5. Shared values
    # ------------------------------------------------------------------
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    plan_id = f"plan-{run_id}"
    spec_hash = _sha256_file(input_path) if input_path and input_path.exists() else "dry-run"
    n_targets = len(target_list.targets)

    # ------------------------------------------------------------------
    # 6. Emit patch_plan.json
    # ------------------------------------------------------------------
    plan_status = "PLANNED" if n_targets > 0 else "PENDING"
    patch_plan: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "plan_id": plan_id,
        "run_id": run_id,
        "seed_id": seed_data.get("seed_id", ""),
        "seed": seed_int,
        "status": plan_status,
        "created_at": now_utc,
        "targets": [
            _target_to_dict(t, idx) for idx, t in enumerate(target_list.targets)
        ],
        "skipped_candidates": target_list.skipped_count,
        "source_tree_hash": target_list.source_hash,
    }
    write_json_artifact(bundle.patch_plan, patch_plan)
    validate_artifact(patch_plan, SCHEMA_PATCH_PLAN)

    # ------------------------------------------------------------------
    # 7. Emit validation_result.json
    # ------------------------------------------------------------------
    validation_result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "result_id": f"vr-{run_id}",
        "run_id": run_id,
        "plan_id": plan_id,
        "overall": "SKIP",
        "checks": [],
        "notes": "Validation skipped: Patcher not yet implemented (Phase 4).",
    }
    write_json_artifact(bundle.validation_result, validation_result)
    validate_artifact(validation_result, SCHEMA_VALIDATION_RESULT)

    # ------------------------------------------------------------------
    # 8. Emit audit_result.json
    # ------------------------------------------------------------------
    if n_targets > 0:
        evidence_obs = (
            f"Seeder identified {n_targets} candidate target(s) "
            f"(pattern_type={seed_data.get('target_pattern', {}).get('pattern_type', 'unknown')}, "
            f"skipped={target_list.skipped_count}). "
            f"No mutations applied — Patcher not yet implemented (Phase 4)."
        )
    else:
        evidence_obs = (
            "Seeder found no candidate targets matching the pattern "
            f"(pattern_type={seed_data.get('target_pattern', {}).get('pattern_type', 'unknown')}) "
            "in the source tree. No mutations applied."
        )

    audit_result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "audit_id": f"ar-{run_id}",
        "run_id": run_id,
        "classification": "NOOP",
        "confidence": "low",
        "evidence": [
            {
                "source": "rule_engine",
                "observation": evidence_obs,
                "weight": "neutral",
            }
        ],
        "reviewer": {
            "type": "deterministic",
            "name": "seeder_dry_run_v1",
        },
    }
    write_json_artifact(bundle.audit_result, audit_result)
    validate_artifact(audit_result, SCHEMA_AUDIT_RESULT)

    # ------------------------------------------------------------------
    # 9. Emit ground_truth.json
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
    # 10. Emit audit.json
    # ------------------------------------------------------------------
    audit_record: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "seed": seed_int,
        "spec_path": str(input_path) if input_path else "",
        "spec_hash": spec_hash,
        "source_root": str(source_root),
        "source_hash": target_list.source_hash,
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


def _target_to_dict(target: PatchTarget, idx: int) -> dict[str, Any]:
    """Convert a PatchTarget to a patch_plan target dict (schema-compliant)."""
    return {
        "target_id": f"t{idx + 1:04d}",
        "file": str(target.file),
        "line": target.line,
        "mutation_strategy": target.mutation_strategy,
        "candidate_score": round(target.score, 4),
        "context": target.context,
    }


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
