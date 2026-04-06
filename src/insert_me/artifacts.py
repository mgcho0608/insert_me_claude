"""
Artifact path helpers and run ID derivation for insert_me.

All output is written under a single run directory identified by a run ID.
The run ID is derived deterministically from the seed, the spec file hash,
and the source tree hash, so the same inputs always produce the same run ID.

Output bundle layout
--------------------
output/<run-id>/
    bad/                  Mutated source tree
    good/                 Clean (original) source tree
    ground_truth.json     Machine-readable vulnerability annotation
    audit.json            Provenance record
    labels.json           (optional) LLM-enriched semantic labels
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Run ID derivation
# ---------------------------------------------------------------------------

def derive_run_id(
    seed: int,
    spec_path: Path,
    source_path: Path,
    pipeline_version: str,
) -> str:
    """
    Derive a deterministic run ID from pipeline inputs.

    The run ID is a 16-character hex string derived from a SHA-256 hash of:
        seed (as decimal string) + spec file content + source tree hash + pipeline version

    Parameters
    ----------
    seed:
        Integer seed used for the run.
    spec_path:
        Path to the spec TOML file.
    source_path:
        Root of the source tree.
    pipeline_version:
        insert_me package version string.

    Returns
    -------
    str
        16-character hex run ID.
    """
    # TODO(phase6): implement source tree hashing (hash of all .c/.h/.cpp files)
    h = hashlib.sha256()
    h.update(str(seed).encode())
    if spec_path.exists():
        h.update(spec_path.read_bytes())
    h.update(str(source_path).encode())  # placeholder: full tree hash in phase 6
    h.update(pipeline_version.encode())
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# Bundle paths
# ---------------------------------------------------------------------------

@dataclass
class BundlePaths:
    """Resolved paths for all artifacts in a single output bundle."""

    root: Path
    bad_dir: Path
    good_dir: Path
    ground_truth: Path
    audit: Path
    labels: Optional[Path]

    @classmethod
    def from_run_id(cls, output_root: Path, run_id: str) -> "BundlePaths":
        root = output_root / run_id
        return cls(
            root=root,
            bad_dir=root / "bad",
            good_dir=root / "good",
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

def write_json_artifact(path: Path, data: dict, *, indent: int = 2) -> None:
    """
    Write a dict as a JSON artifact file.

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
