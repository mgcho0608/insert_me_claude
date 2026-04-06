"""
Coverage computation for per-project evaluation.

Aggregates per-mutation match records into summary statistics that describe
how well a detector found what insert_me inserted.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import write_json_artifact

if TYPE_CHECKING:
    from insert_me.evaluation.evaluator import EvaluationResult


def emit_coverage_result(
    result: "EvaluationResult",
    output_dir: Path,
    evaluated_at: str,
) -> dict[str, Any]:
    """
    Compute coverage statistics, write coverage_result.json, return the dict.

    Parameters
    ----------
    result:
        EvaluationResult from Evaluator.run().
    output_dir:
        Directory where coverage_result.json will be written.
    evaluated_at:
        ISO 8601 UTC timestamp string.

    Returns
    -------
    dict
        The serialized coverage_result artifact.
    """
    by_level: dict[str, int] = {"exact": 0, "family": 0, "semantic": 0, "no_match": 0}
    for rec in result.match_records:
        if rec.match_level in by_level:
            by_level[rec.match_level] += 1

    total = len(result.match_records)
    matched = by_level["exact"] + by_level["family"] + by_level["semantic"]
    unmatched = by_level["no_match"]
    coverage_rate = (matched / total) if total > 0 else 0.0

    artifact: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": result.run_id,
        "tool": result.tool,
        "evaluated_at": evaluated_at,
        "total_mutations": total,
        "matched": matched,
        "unmatched": unmatched,
        "false_positives": result.false_positive_count,
        "coverage_rate": coverage_rate,
        "by_level": by_level,
    }

    write_json_artifact(output_dir / "coverage_result.json", artifact)
    return artifact
