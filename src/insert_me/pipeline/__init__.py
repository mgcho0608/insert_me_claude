"""
Pipeline orchestrator for insert_me.

Canonical pipeline stages:
    Seeder → Patcher → Validator → Auditor (→ optional LLM enrichment)

Current implementation status
------------------------------
Phase 3 (Seeder), Phase 4b (Patcher — alloc_size_undercount and
insert_premature_free strategies), Phase 5 (Validator — five deterministic
checks), and Phase 6 (Auditor — ground truth + provenance + audit result)
are implemented.

The pipeline produces real bad/good source trees, validates the mutation,
and writes a complete, schema-valid output bundle in real mode.

Run modes
---------
Real mode (default):
    insert-me run --seed-file PATH --source PATH

    Seeder discovers candidates; Patcher applies one mutation; Validator runs
    five plausibility checks; Auditor writes ground_truth.json, audit.json,
    and audit_result.json.  patch_plan.json status is APPLIED when a mutation
    is made, PLANNED when no compatible target was found.

Dry-run mode:
    insert-me run --seed-file PATH --source PATH --dry-run

    All five artifacts are emitted and schema-validated, but no source files
    are modified (bad/ and good/ remain empty), Validator returns SKIP, and
    Auditor records an honest NOOP classification.

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
    bundle = run_pipeline(config, dry_run=False)
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
from insert_me.pipeline.auditor import Auditor
from insert_me.pipeline.patcher import Mutation, Patcher, PatchResult
from insert_me.pipeline.seeder import PatchTarget, PatchTargetList, Seeder
from insert_me.pipeline.validator import Validator, ValidationVerdict
from insert_me.schema import (
    SCHEMA_PATCH_PLAN,
    SCHEMA_SEED,
    SCHEMA_VALIDATION_RESULT,
    validate_artifact,
)


def run_pipeline(config: Config, *, dry_run: bool = False) -> BundlePaths:
    """
    Execute the insert_me pipeline.

    Parameters
    ----------
    config:
        Fully-resolved Config dataclass.
    dry_run:
        When True, all artifacts are emitted and schema-validated but no
        source files are modified and bad/good trees remain empty.  The
        Validator returns SKIP and the Auditor records NOOP.
        When False (default), the Patcher is invoked and Validator runs
        five plausibility checks.

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
    spec_hash = (
        _sha256_file(input_path)
        if input_path and input_path.exists()
        else "dry-run"
    )
    n_targets = len(target_list.targets)

    # ------------------------------------------------------------------
    # 6. Run Patcher (real mode only)
    # ------------------------------------------------------------------
    patch_result: PatchResult | None = None
    applied_mutations: list[Mutation] = []

    if not dry_run and n_targets > 0:
        patcher = Patcher(
            targets=target_list,
            bad_root=bundle.bad_dir,
            good_root=bundle.good_dir,
        )
        patch_result = patcher.run()
        applied_mutations = patch_result.mutations

    # Derive plan status from patcher outcome
    if not dry_run and applied_mutations:
        plan_status = "APPLIED"
    elif n_targets > 0:
        plan_status = "PLANNED"
    else:
        plan_status = "PENDING"

    # ------------------------------------------------------------------
    # 6b. Run Validator
    # ------------------------------------------------------------------
    validator = Validator(
        patch_result=patch_result,
        source_root=source_root,
        dry_run=dry_run,
    )
    verdict: ValidationVerdict = validator.run()

    # ------------------------------------------------------------------
    # 7. Emit patch_plan.json  (Seeder output — orchestrator owns this)
    # ------------------------------------------------------------------
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
    # 8. Emit validation_result.json  (Validator output — orchestrator owns this)
    # ------------------------------------------------------------------
    validation_result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "result_id": f"vr-{run_id}",
        "run_id": run_id,
        "plan_id": plan_id,
        "overall": verdict.overall,
        "checks": [
            {"name": c.name, "status": c.status.value, "reason": c.reason}
            for c in verdict.checks
        ],
    }
    if verdict.notes:
        validation_result["notes"] = verdict.notes
    write_json_artifact(bundle.validation_result, validation_result)
    validate_artifact(validation_result, SCHEMA_VALIDATION_RESULT)

    # ------------------------------------------------------------------
    # 9. Run Auditor — writes ground_truth.json, audit.json, audit_result.json
    # ------------------------------------------------------------------
    auditor = Auditor(
        patch_result=patch_result,
        verdict=verdict,
        bundle=bundle,
        run_id=run_id,
        seed=seed_int,
        seed_data=seed_data,
        pipeline_version=__version__,
        spec_path=input_path,
        spec_hash=spec_hash,
        source_root=source_root,
        source_hash=target_list.source_hash,
    )
    auditor.run()

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
