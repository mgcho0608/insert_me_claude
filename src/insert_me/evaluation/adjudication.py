"""
Adjudication for ambiguous semantic match cases.

When the Evaluator produces semantic matches (match_level=="semantic"),
those matches carry ``adjudication_pending=True``.  This module defines:

  - the AdjudicationCase dataclass (one per pending case)
  - emit_adjudication_result(): writes adjudication_result.json ONLY when
    cases exist — i.e. only when an adjudicator ran and produced verdicts

LLM-driven adjudication is Phase 7B.  In Phase 7A:
  - collect_pending_cases() identifies cases that need adjudication
  - try_adjudicate() accepts an optional LLM adapter; returns an empty list
    when no adapter is provided (deterministic fallback)
  - emit_adjudication_result() is only called when there are actual verdicts;
    it does NOT write the file for an empty case list

Design constraint:
    Adjudication NEVER fails the evaluation pipeline.  Missing adjudicator
    → honest UNRESOLVED state, not a pipeline error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import write_json_artifact

if TYPE_CHECKING:
    from insert_me.evaluation.evaluator import MatchRecord


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AdjudicationCase:
    """A single pending semantic match submitted for adjudication."""

    mutation_index: int
    finding_id: Optional[str]
    verdict: str          # "match" | "no_match" | "ambiguous"
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    adjudicator: str = "heuristic"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def collect_pending_cases(match_records: list["MatchRecord"]) -> list["MatchRecord"]:
    """Return the subset of match records that have adjudication_pending=True."""
    return [r for r in match_records if r.adjudication_pending]


def try_adjudicate(
    pending: list["MatchRecord"],
    llm_adapter: Any = None,
) -> list[AdjudicationCase]:
    """
    Attempt to adjudicate pending semantic matches.

    Phase 7A: no LLM adapter is wired.  This function always returns an
    empty list, leaving all pending cases as UNRESOLVED in match_result.json.

    Phase 7B will accept a real LLMAdapter, call it for each pending case,
    and return populated AdjudicationCase records.

    Parameters
    ----------
    pending:
        Match records with adjudication_pending=True.
    llm_adapter:
        Optional LLM adapter.  When None (default), returns empty list.

    Returns
    -------
    list[AdjudicationCase]
        Adjudicated cases.  Empty list when no adapter is available.
    """
    if llm_adapter is None or not pending:
        return []
    # Phase 7B: call adapter and return results
    # For now this path is unreachable — LLM adapter integration is deferred.
    raise NotImplementedError(  # pragma: no cover
        "LLM-driven adjudication is not yet implemented (Phase 7B)."
    )


# ---------------------------------------------------------------------------
# Emit function
# ---------------------------------------------------------------------------

def emit_adjudication_result(
    cases: list[AdjudicationCase],
    run_id: str,
    tool: str,
    adjudicator: str,
    output_dir: Path,
) -> Optional[dict[str, Any]]:
    """
    Write adjudication_result.json ONLY if ``cases`` is non-empty.

    Returns the artifact dict when written, or None when skipped.

    Parameters
    ----------
    cases:
        List of adjudicated cases (from try_adjudicate).
    run_id:
        Run ID linking to the insert_me bundle.
    tool:
        Tool name string.
    adjudicator:
        Identifier for the adjudicator, e.g. "heuristic" or "claude-3-5-sonnet".
    output_dir:
        Directory where adjudication_result.json will be written.
    """
    if not cases:
        return None

    cases_list: list[dict[str, Any]] = []
    for c in cases:
        item: dict[str, Any] = {
            "mutation_index": c.mutation_index,
            "finding_id": c.finding_id,
            "verdict": c.verdict,
        }
        if c.confidence is not None:
            item["confidence"] = c.confidence
        if c.rationale is not None:
            item["rationale"] = c.rationale
        cases_list.append(item)

    artifact: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "tool": tool,
        "adjudicator": adjudicator,
        "cases": cases_list,
    }

    write_json_artifact(output_dir / "adjudication_result.json", artifact)
    return artifact
