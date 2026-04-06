"""
Artifact path helpers and run ID derivation for insert_me.

All output is written under a single run directory identified by a run ID.
The run ID is derived deterministically from the seed data, the source tree
path, and the pipeline version, so the same inputs always produce the same
run ID.

Output bundle layout
--------------------
output/<run-id>/
    bad/                    Mutated source tree
    good/                   Clean (original) source tree, byte-identical to input
    patch_plan.json         Seeder output: planned transformations
    validation_result.json  Validator output: plausibility verdict
    audit_result.json       Auditor classification (VALID/NOOP/AMBIGUOUS/INVALID)
    ground_truth.json       Vulnerability annotation
    audit.json              Provenance record
    labels.json             (optional) LLM-enriched semantic labels
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Run ID derivation
# ---------------------------------------------------------------------------

def derive_run_id_from_seed_data(
    seed_data: dict[str, Any],
    source_path: Path,
    pipeline_version: str,
) -> str:
    """
    Derive a deterministic run ID from a seed JSON artifact.

    The run ID is a 16-character hex string derived from a SHA-256 hash of:
        canonicalized seed JSON + source tree path + pipeline version

    This is the canonical run ID derivation function. Use it whenever a
    seed file (seed.schema.json) is the primary input.

    Parameters
    ----------
    seed_data:
        Parsed seed artifact dict (must include at minimum ``seed`` integer).
    source_path:
        Root of the source tree.
    pipeline_version:
        insert_me package version string.

    Returns
    -------
    str
        16-character hex run ID.
    """
    h = hashlib.sha256()
    canonical = json.dumps(seed_data, sort_keys=True, ensure_ascii=True)
    h.update(canonical.encode("utf-8"))
    h.update(str(source_path).encode("utf-8"))
    h.update(pipeline_version.encode("utf-8"))
    return h.hexdigest()[:16]


def derive_run_id(
    seed: int,
    spec_path: Path,
    source_path: Path,
    pipeline_version: str,
) -> str:
    """
    Derive a deterministic run ID from legacy int-seed + spec-file inputs.

    .. deprecated::
        Prefer :func:`derive_run_id_from_seed_data` with a seed JSON file.
        This function is kept for backward compatibility with the legacy
        ``--seed INT --spec PATH`` interface.

    The run ID is a 16-character hex string derived from a SHA-256 hash of:
        seed (decimal string) + spec file content + source tree path + pipeline version

    Parameters
    ----------
    seed:
        Integer seed used for the run.
    spec_path:
        Path to the spec TOML file. If it does not exist, only the path
        string is hashed.
    source_path:
        Root of the source tree.
    pipeline_version:
        insert_me package version string.

    Returns
    -------
    str
        16-character hex run ID.
    """
    h = hashlib.sha256()
    h.update(str(seed).encode("utf-8"))
    if spec_path.exists():
        h.update(spec_path.read_bytes())
    h.update(str(source_path).encode("utf-8"))
    h.update(pipeline_version.encode("utf-8"))
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# Bundle paths
# ---------------------------------------------------------------------------

@dataclass
class BundlePaths:
    """
    Resolved paths for all artifacts in a single output bundle.

    All paths are under ``root = output_root / run_id``.
    """

    root: Path
    bad_dir: Path
    good_dir: Path
    patch_plan: Path
    validation_result: Path
    audit_result: Path
    ground_truth: Path
    audit: Path
    labels: Optional[Path]

    @classmethod
    def from_run_id(cls, output_root: Path, run_id: str) -> "BundlePaths":
        """Construct a BundlePaths rooted at ``output_root / run_id``."""
        root = output_root / run_id
        return cls(
            root=root,
            bad_dir=root / "bad",
            good_dir=root / "good",
            patch_plan=root / "patch_plan.json",
            validation_result=root / "validation_result.json",
            audit_result=root / "audit_result.json",
            ground_truth=root / "ground_truth.json",
            audit=root / "audit.json",
            labels=root / "labels.json",
        )

    def create_dirs(self) -> None:
        """Create all bundle subdirectories."""
        self.bad_dir.mkdir(parents=True, exist_ok=True)
        self.good_dir.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Artifact writers
# ---------------------------------------------------------------------------

def write_json_artifact(path: Path, data: dict[str, Any], *, indent: int = 2) -> None:
    """
    Write a dict as a formatted JSON artifact file.

    Parameters
    ----------
    path:
        Destination file path.
    data:
        Serialisable dict.
    indent:
        JSON indentation level.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, ensure_ascii=False)
        fh.write("\n")
