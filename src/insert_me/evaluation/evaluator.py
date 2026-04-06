"""
Evaluator — per-project detector report evaluation against inserted ground truth.

Orchestrates the three-level match hierarchy (exact → family → semantic → no_match)
by delegating to the matching module.  Returns an EvaluationResult that can be
serialized by emit_match_result and emit_coverage_result.

Invocation path:
    insert-me evaluate --bundle PATH --tool-report PATH --tool NAME
    → cli._cmd_evaluate
    → Evaluator(bundle_dir, tool_report, tool_name).run()
    → emit_match_result(result, ...)
    → emit_coverage_result(result, ...)
    → (optional) adjudication.try_adjudicate + emit_adjudication_result
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from insert_me.evaluation.matching import (
    exact_match,
    family_match,
    semantic_match,
    build_rationale,
)
from insert_me.evaluation.adjudication import (
    AdjudicatorBase,
    AdjudicationVerdict,
    HeuristicAdjudicator,
    collect_pending_cases,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MatchRecord:
    """Result of matching one inserted mutation against all detector findings."""

    mutation_index: int
    """Zero-based index into ground_truth.mutations."""

    mutation_type: str
    """Strategy name, e.g. 'insert_premature_free'."""

    file: str
    """Relative file path from ground_truth.mutations[i].file."""

    line: int
    """1-based line number from ground_truth.mutations[i].line."""

    cwe_id: Optional[str]
    """CWE identifier from ground_truth.cwe_id (top-level field)."""

    match_level: str
    """One of: 'exact' | 'family' | 'semantic' | 'no_match'."""

    matched_finding: Optional[dict[str, Any]]
    """The matched finding dict, or None for no_match."""

    rationale: str
    """Human-readable explanation of the match decision."""

    adjudication_pending: bool = False
    """True for semantic matches that have not yet been adjudicated."""

    adjudication_verdict: Optional[AdjudicationVerdict] = None
    """Set after the adjudicator runs; None if not adjudicated."""


@dataclass
class EvaluationResult:
    """Aggregate result of evaluating one detector report against one bundle."""

    match_records: list[MatchRecord]
    """One MatchRecord per mutation in ground_truth.mutations."""

    false_positive_count: int
    """Count of findings not matched to any mutation."""

    tool: str
    """Tool name string from the detector report."""

    run_id: str
    """16-char hex run ID from the bundle's ground_truth.json."""

    adjudicator_name: str = "disabled"
    """Name of the adjudicator that ran (e.g. 'heuristic', 'disabled')."""


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class Evaluator:
    """
    Evaluate a normalized detector report against an insert_me output bundle.

    Parameters
    ----------
    bundle_dir:
        Path to the insert_me output bundle directory (the run-id subdirectory).
        Must contain ground_truth.json.
    tool_report:
        Parsed detector report dict (conforming to detector_report.schema.json).
    tool_name:
        Human-readable tool name string, e.g. "cppcheck", "coverity".
    """

    def __init__(
        self,
        bundle_dir: Path,
        tool_report: dict[str, Any],
        tool_name: str,
        adjudicator: Optional[AdjudicatorBase] = None,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.tool_report = tool_report
        self.tool_name = tool_name
        self.adjudicator: AdjudicatorBase = adjudicator if adjudicator is not None else HeuristicAdjudicator()

    def run(self) -> EvaluationResult:
        """
        Execute the evaluation and return structured results.

        Algorithm
        ---------
        For each mutation in ground_truth.mutations:
            1. Attempt exact match against unused findings.
            2. If no exact match, attempt family match.
            3. If no family match, attempt semantic match.
            4. If still no match, record no_match.

        Each finding can be matched at most once (greedy first-come assignment).
        Unmatched findings are counted as false positives.

        Returns
        -------
        EvaluationResult
        """
        ground_truth = self._load_ground_truth()
        run_id: str = ground_truth.get("run_id", "")
        mutations: list[dict[str, Any]] = ground_truth.get("mutations", [])
        findings: list[dict[str, Any]] = self.tool_report.get("findings", [])

        used_finding_indices: set[int] = set()
        match_records: list[MatchRecord] = []

        for idx, mutation in enumerate(mutations):
            record = self._match_mutation(
                idx, mutation, findings, used_finding_indices, ground_truth
            )
            match_records.append(record)

        false_positive_count = sum(
            1 for i in range(len(findings)) if i not in used_finding_indices
        )

        # --- Adjudication phase ---
        pending = collect_pending_cases(match_records, mutations)
        verdicts = self.adjudicator.adjudicate(pending)
        if verdicts:
            verdict_map = {v.mutation_index: v for v in verdicts}
            for rec in match_records:
                if rec.mutation_index in verdict_map:
                    rec.adjudication_verdict = verdict_map[rec.mutation_index]

        return EvaluationResult(
            match_records=match_records,
            false_positive_count=false_positive_count,
            tool=self.tool_name,
            run_id=run_id,
            adjudicator_name=self.adjudicator.adjudicator_name,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_ground_truth(self) -> dict[str, Any]:
        """Load and return the ground_truth.json from the bundle directory."""
        gt_path = self.bundle_dir / "ground_truth.json"
        if not gt_path.exists():
            raise FileNotFoundError(
                f"ground_truth.json not found in bundle: {self.bundle_dir}"
            )
        with open(gt_path, encoding="utf-8") as fh:
            return json.load(fh)

    def _match_mutation(
        self,
        idx: int,
        mutation: dict[str, Any],
        findings: list[dict[str, Any]],
        used: set[int],
        ground_truth: dict[str, Any],
    ) -> MatchRecord:
        """
        Find the best matching finding for a single mutation.

        The CWE is read from the top-level ``ground_truth["cwe_id"]`` field
        because ground_truth.json stores a single CWE per bundle (one seed →
        one CWE class per run).  Per-mutation CWE override would require
        schema extension.

        Parameters
        ----------
        idx:
            Zero-based index of this mutation.
        mutation:
            Single mutation record from ground_truth.mutations.
        findings:
            All findings from the detector report.
        used:
            Set of already-consumed finding indices (mutated in place).
        ground_truth:
            Full ground_truth dict (for top-level cwe_id lookup).
        """
        mutation_cwe: Optional[str] = ground_truth.get("cwe_id") or None

        for level in ("exact", "family", "semantic"):
            for fi, finding in enumerate(findings):
                if fi in used:
                    continue

                matched = False
                if level == "exact":
                    matched = exact_match(mutation, finding, mutation_cwe)
                elif level == "family":
                    matched = family_match(mutation, finding, mutation_cwe)
                elif level == "semantic":
                    matched = semantic_match(mutation, finding, mutation_cwe)

                if matched:
                    used.add(fi)
                    return MatchRecord(
                        mutation_index=idx,
                        mutation_type=mutation.get("mutation_type", ""),
                        file=mutation.get("file", ""),
                        line=mutation.get("line", 0),
                        cwe_id=mutation_cwe,
                        match_level=level,
                        matched_finding=finding,
                        rationale=build_rationale(level, mutation, finding, mutation_cwe),
                        adjudication_pending=(level == "semantic"),
                    )

        return MatchRecord(
            mutation_index=idx,
            mutation_type=mutation.get("mutation_type", ""),
            file=mutation.get("file", ""),
            line=mutation.get("line", 0),
            cwe_id=mutation_cwe,
            match_level="no_match",
            matched_finding=None,
            rationale=(
                f"No finding matched mutation at {mutation.get('file', '?')}:"
                f"{mutation.get('line', '?')} (CWE={mutation_cwe}) "
                "at exact, family, or semantic level."
            ),
        )
