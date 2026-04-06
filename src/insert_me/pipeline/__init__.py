"""
Pipeline orchestrator for insert_me.

Wires together: Seeder → Patcher → Validator → Auditor (→ optional LLM enrichment)
and returns a completed BundlePaths pointing to all output artifacts.

Usage
-----
    from insert_me.pipeline import run_pipeline
    from insert_me.config import Config

    config = Config(...)
    bundle = run_pipeline(config)
"""

from __future__ import annotations

from insert_me.artifacts import BundlePaths
from insert_me.config import Config


def run_pipeline(config: Config) -> BundlePaths:
    """
    Execute the full insert_me pipeline.

    Stages
    ------
    1. Seeder  — expand seed → PatchTargetList
    2. Patcher — apply mutations → PatchResult (bad/good trees)
    3. Validator — check plausibility → ValidationVerdict
    4. Auditor — write ground_truth.json + audit.json
    5. LLM adapter (optional) — write labels.json

    Parameters
    ----------
    config:
        Fully-resolved Config dataclass.

    Returns
    -------
    BundlePaths
        Resolved paths to all artifacts in the completed output bundle.

    Raises
    ------
    NotImplementedError
        Until full implementation is in place (Phases 3–7).
    """
    # TODO(phase3): instantiate and run Seeder
    # TODO(phase4): instantiate and run Patcher
    # TODO(phase5): instantiate and run Validator
    # TODO(phase6): instantiate and run Auditor
    # TODO(phase7): conditionally invoke LLM adapter
    raise NotImplementedError(
        "run_pipeline is not yet implemented. See ROADMAP.md Phases 3–7."
    )
