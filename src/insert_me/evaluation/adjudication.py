"""
Adjudication module for semantic match cases.

Defines the adjudicator interface and three plug-in implementations:

    DisabledAdjudicator
        Returns no verdicts (empty list).  Semantic cases stay unresolved.
        adjudication_result.json is NOT written.  Safe default when no
        adjudication is desired.

    HeuristicAdjudicator   ← default for ``insert-me evaluate``
        Deterministic, offline scoring adjudicator.  Produces one of:
            MATCH       — score ≥ MATCH_THRESHOLD (0.65)
            UNRESOLVED  — UNRESOLVED_THRESHOLD (0.30) ≤ score < MATCH_THRESHOLD
            NO_MATCH    — score < UNRESOLVED_THRESHOLD
        Scoring signals (total possible score = 1.0):
            +0.20  same file basename as mutation file
            +0.15  finding line within ±10 of mutation insertion line
            +0.30  finding CWE maps to same CWE family as mutation CWE
            +0.20  keyword density: min(hits × 0.10, 0.20)
                   (keywords from the mutation's CWE family message list)
            +0.15  strategy-specific keyword in finding message
                   (e.g. "freed", "use after" for insert_premature_free)

    LLMAdjudicator  ← Phase 7B placeholder
        Raises NotImplementedError with a clear message.
        Not wired to any real service.  Plug-in point for future internal
        LLM integration.

Behavior summary:

    | Adjudicator  | Produces verdicts | Writes adj_result.json |
    |--------------|-------------------|------------------------|
    | disabled     | no                | no                     |
    | heuristic    | yes               | yes (if semantic cases)|
    | llm          | Phase 7B          | Phase 7B               |

emit_adjudication_result() writes adjudication_result.json only when
verdicts is non-empty.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import write_json_artifact


# ---------------------------------------------------------------------------
# Strategy-specific keyword signals
# ---------------------------------------------------------------------------

# Maps mutation_strategy → keywords that strongly suggest a matching finding.
# Used as a bonus signal in the heuristic scorer.
_STRATEGY_KEYWORDS: dict[str, list[str]] = {
    "insert_premature_free": [
        "freed", "use after", "after free", "dangling", "use-after-free",
        "released", "double free",
    ],
    "alloc_size_undercount": [
        "heap overflow", "heap buffer", "overrun", "underallocate",
        "allocation size", "size undercount", "heap corruption",
    ],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PendingCase:
    """One semantic match case submitted for adjudication."""

    mutation_index: int
    """Zero-based mutation index (into ground_truth.mutations)."""

    finding_id: Optional[str]
    """Tool-assigned finding identifier, or None."""

    mutation: dict[str, Any]
    """Raw mutation dict from ground_truth.json."""

    finding: dict[str, Any]
    """Raw finding dict from the detector report."""

    mutation_cwe: Optional[str]
    """CWE ID from ground_truth.cwe_id (top-level, not per-mutation)."""

    mutation_type: str
    """Strategy name, e.g. 'insert_premature_free'."""


@dataclass
class AdjudicationVerdict:
    """Adjudicator verdict for one semantic match case."""

    mutation_index: int
    finding_id: Optional[str]
    verdict: str         # "match" | "no_match" | "unresolved"
    confidence: float    # 0.0..1.0
    rationale: str       # signal-level explanation
    adjudicator: str     # "heuristic" | "llm" | custom name


# ---------------------------------------------------------------------------
# Adjudicator interface
# ---------------------------------------------------------------------------

class AdjudicatorBase(abc.ABC):
    """Abstract base for adjudication strategies."""

    @property
    @abc.abstractmethod
    def adjudicator_name(self) -> str:
        """Identifier written into adjudication_result.json."""

    @abc.abstractmethod
    def adjudicate(self, cases: list[PendingCase]) -> list[AdjudicationVerdict]:
        """
        Produce one AdjudicationVerdict per case.

        Parameters
        ----------
        cases:
            PendingCase list from collect_pending_cases().

        Returns
        -------
        list[AdjudicationVerdict]
            One verdict per case.  Empty list = no adjudication performed.
        """


# ---------------------------------------------------------------------------
# DisabledAdjudicator
# ---------------------------------------------------------------------------

class DisabledAdjudicator(AdjudicatorBase):
    """
    No-op adjudicator.

    Returns an empty list — semantic cases remain adjudication_pending=True
    in match_result.json and adjudication_result.json is not written.
    Use this when you want evaluation results without any adjudication.
    """

    @property
    def adjudicator_name(self) -> str:
        return "disabled"

    def adjudicate(self, cases: list[PendingCase]) -> list[AdjudicationVerdict]:
        return []


# ---------------------------------------------------------------------------
# HeuristicAdjudicator
# ---------------------------------------------------------------------------

class HeuristicAdjudicator(AdjudicatorBase):
    """
    Deterministic scoring-based adjudicator.

    Default for ``insert-me evaluate``.  Works fully offline with no
    external service calls.  All scores are computed from static rules
    applied to the finding message, file, line, and CWE.

    Scoring signals
    ---------------
    +0.20  Same file basename (mutation.file vs finding.file).
    +0.15  Finding line within ±10 lines of mutation.line.
    +0.30  Finding CWE maps to same family as mutation CWE
           (see matching._CWE_FAMILIES).
    +0.20  Keyword density: min(hits × 0.10, 0.20) where hits = number of
           CWE-family keywords found in finding.message (case-insensitive).
    +0.15  At least one strategy-specific keyword found in finding.message.

    Verdict thresholds
    ------------------
    ≥ 0.65  MATCH       — strong evidence the finding describes the flaw
    ≥ 0.30  UNRESOLVED  — moderate evidence; insufficient to confirm or deny
    < 0.30  NO_MATCH    — weak evidence; likely unrelated finding
    """

    MATCH_THRESHOLD = 0.65
    UNRESOLVED_THRESHOLD = 0.30

    @property
    def adjudicator_name(self) -> str:
        return "heuristic"

    def adjudicate(self, cases: list[PendingCase]) -> list[AdjudicationVerdict]:
        return [self._adjudicate_one(c) for c in cases]

    def _adjudicate_one(self, case: PendingCase) -> AdjudicationVerdict:
        score, signals = self._score(case)
        score = round(min(score, 1.0), 4)

        if score >= self.MATCH_THRESHOLD:
            verdict = "match"
        elif score >= self.UNRESOLVED_THRESHOLD:
            verdict = "unresolved"
        else:
            verdict = "no_match"

        rationale = "; ".join(signals) if signals else "no matching signals found"
        return AdjudicationVerdict(
            mutation_index=case.mutation_index,
            finding_id=case.finding_id,
            verdict=verdict,
            confidence=score,
            rationale=rationale,
            adjudicator=self.adjudicator_name,
        )

    def _score(self, case: PendingCase) -> tuple[float, list[str]]:
        from pathlib import Path as _Path
        from insert_me.evaluation.matching import _CWE_FAMILIES, _SEMANTIC_KEYWORDS

        score = 0.0
        signals: list[str] = []
        mutation = case.mutation
        finding = case.finding
        mutation_cwe = case.mutation_cwe
        mutation_type = case.mutation_type
        message = finding.get("message", "").lower()

        # 1. Same file basename (+0.20)
        mut_base = _Path(mutation.get("file", "")).name
        find_base = _Path(finding.get("file", "")).name
        if mut_base and find_base and mut_base == find_base:
            score += 0.20
            signals.append(f"same file '{mut_base}' (+0.20)")

        # 2. Line proximity ±10 (+0.15)
        mut_line: int = mutation.get("line", -9999)
        find_line: int = finding.get("line", -9999)
        if mut_line > 0 and find_line > 0:
            dist = abs(find_line - mut_line)
            if dist <= 10:
                score += 0.15
                signals.append(f"line proximity dist={dist} (+0.15)")

        # 3. CWE family match (+0.30)
        if mutation_cwe:
            find_cwe: Optional[str] = finding.get("cwe_id")
            if find_cwe:
                mut_family = _CWE_FAMILIES.get(mutation_cwe)
                find_family = _CWE_FAMILIES.get(find_cwe)
                if mut_family and find_family and mut_family == find_family:
                    score += 0.30
                    signals.append(
                        f"CWE family '{mut_family}' ({mutation_cwe} ↔ {find_cwe}) (+0.30)"
                    )

        # 4. Keyword density (+0.10 per hit, capped at +0.20)
        if mutation_cwe:
            family = _CWE_FAMILIES.get(mutation_cwe)
            if family:
                keywords = _SEMANTIC_KEYWORDS.get(family, [])
                hits = sum(1 for kw in keywords if kw in message)
                kw_bonus = min(hits * 0.10, 0.20)
                if kw_bonus > 0:
                    score += kw_bonus
                    signals.append(f"{hits} CWE-family keyword(s) (+{kw_bonus:.2f})")

        # 5. Strategy-specific keyword (+0.15, once)
        strat_keywords = _STRATEGY_KEYWORDS.get(mutation_type, [])
        strat_hits = sum(1 for kw in strat_keywords if kw in message)
        if strat_hits > 0:
            score += 0.15
            signals.append(f"{strat_hits} strategy keyword(s) for '{mutation_type}' (+0.15)")

        return score, signals


# ---------------------------------------------------------------------------
# LLMAdjudicator — Phase 7B placeholder
# ---------------------------------------------------------------------------

class LLMAdjudicator(AdjudicatorBase):
    """
    Placeholder for future internal-LLM adjudication (Phase 7B).

    Raises NotImplementedError when instantiated via adjudicate().
    The constructor accepts configuration kwargs for future use.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._config = kwargs

    @property
    def adjudicator_name(self) -> str:
        return "llm"

    def adjudicate(self, cases: list[PendingCase]) -> list[AdjudicationVerdict]:
        raise NotImplementedError(
            "LLMAdjudicator is a Phase 7B placeholder. "
            "Real LLM adjudication requires internal model access that is "
            "not yet wired. Use HeuristicAdjudicator for offline use."
        )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def collect_pending_cases(
    match_records: list[Any],   # list[MatchRecord], typed loosely to avoid circular import
    mutations: list[dict[str, Any]],
) -> list[PendingCase]:
    """
    Build PendingCase objects for all match records that need adjudication.

    Parameters
    ----------
    match_records:
        MatchRecord list from EvaluationResult.match_records.
    mutations:
        Raw mutation dicts from ground_truth.json["mutations"].

    Returns
    -------
    list[PendingCase]
        One PendingCase per semantic match with adjudication_pending=True
        that has a matched_finding attached.
    """
    pending: list[PendingCase] = []
    for rec in match_records:
        if rec.adjudication_pending and rec.matched_finding is not None:
            idx = rec.mutation_index
            mutation = mutations[idx] if idx < len(mutations) else {}
            pending.append(
                PendingCase(
                    mutation_index=idx,
                    finding_id=rec.matched_finding.get("finding_id"),
                    mutation=mutation,
                    finding=rec.matched_finding,
                    mutation_cwe=rec.cwe_id,
                    mutation_type=rec.mutation_type,
                )
            )
    return pending


# ---------------------------------------------------------------------------
# Emit function
# ---------------------------------------------------------------------------

def emit_adjudication_result(
    match_records: list[Any],   # list[MatchRecord]
    run_id: str,
    tool: str,
    adjudicator_name: str,
    output_dir: Path,
) -> Optional[dict[str, Any]]:
    """
    Write adjudication_result.json from adjudicated MatchRecords.

    Only writes the file when at least one MatchRecord has a non-None
    adjudication_verdict (i.e. the adjudicator actually ran and produced
    verdicts).  Returns None and skips the file otherwise.

    Parameters
    ----------
    match_records:
        EvaluationResult.match_records, after Evaluator.run() has applied
        adjudication verdicts to the records.
    run_id:
        Bundle run identifier.
    tool:
        Tool name string.
    adjudicator_name:
        Identifier of the adjudicator that ran (e.g. "heuristic").
    output_dir:
        Directory where adjudication_result.json will be written.
    """
    adjudicated = [r for r in match_records if r.adjudication_verdict is not None]
    if not adjudicated:
        return None

    cases_list: list[dict[str, Any]] = []
    for rec in adjudicated:
        v = rec.adjudication_verdict
        item: dict[str, Any] = {
            "mutation_index": rec.mutation_index,
            "finding_id": rec.matched_finding.get("finding_id") if rec.matched_finding else None,
            "verdict": v.verdict,
            "confidence": v.confidence,
            "rationale": v.rationale,
        }
        cases_list.append(item)

    artifact: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "tool": tool,
        "adjudicator": adjudicator_name,
        "cases": cases_list,
    }

    write_json_artifact(output_dir / "adjudication_result.json", artifact)
    return artifact
