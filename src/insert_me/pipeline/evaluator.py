"""
Evaluator — per-project detector report evaluation against inserted ground truth.

Compares a normalized detector report to the ground truth mutations produced
by an insert_me run. Emits match_result.json and coverage_result.json.

Match levels (in order of precedence):
    exact    — same file (basename), same CWE ID, line within ±2 of inserted site
    family   — same CWE family group (e.g. CWE-122 and CWE-121 both → heap-buffer-overflow)
    semantic — keyword heuristic on finding message; if ambiguous → adjudication_pending=True
    no_match — none of the above

LLM adjudication is optional. When disabled, semantic cases are left as
UNRESOLVED with adjudication_pending=True; this does not fail the evaluation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import write_json_artifact


# ---------------------------------------------------------------------------
# CWE family mapping
# ---------------------------------------------------------------------------

_CWE_FAMILIES: dict[str, str] = {
    "CWE-119": "buffer-overflow",
    "CWE-120": "buffer-overflow",
    "CWE-121": "stack-buffer-overflow",
    "CWE-122": "heap-buffer-overflow",
    "CWE-123": "buffer-overflow",
    "CWE-124": "buffer-overflow",
    "CWE-125": "buffer-overflow",
    "CWE-190": "integer-overflow",
    "CWE-191": "integer-overflow",
    "CWE-680": "integer-overflow",
    "CWE-415": "use-after-free",
    "CWE-416": "use-after-free",
    "CWE-825": "use-after-free",
    "CWE-476": "null-pointer",
    "CWE-369": "divide-by-zero",
    "CWE-134": "format-string",
    "CWE-78":  "command-injection",
    "CWE-89":  "sql-injection",
}


# ---------------------------------------------------------------------------
# Semantic keyword hints
# ---------------------------------------------------------------------------

_SEMANTIC_KEYWORDS: dict[str, list[str]] = {
    "use-after-free": ["use after free", "use-after-free", "uaf", "freed", "dangling"],
    "heap-buffer-overflow": ["heap overflow", "heap buffer", "out of bounds", "oob"],
    "stack-buffer-overflow": ["stack overflow", "stack buffer"],
    "buffer-overflow": ["buffer overflow", "overrun", "overwrite"],
    "integer-overflow": ["integer overflow", "int overflow", "wrap"],
    "null-pointer": ["null pointer", "null dereference", "nullptr"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MatchRecord:
    """Result of matching one mutation against all detector findings."""

    mutation_index: int
    mutation_type: str
    file: str
    line: int
    cwe_id: Optional[str]
    match_level: str  # "exact" | "family" | "semantic" | "no_match"
    matched_finding: Optional[dict]
    rationale: str
    adjudication_pending: bool = False


@dataclass
class EvaluationResult:
    """Aggregate result of evaluating a detector report against a bundle."""

    match_records: list[MatchRecord]
    false_positive_count: int  # findings not matched to any mutation
    tool: str
    run_id: str


# ---------------------------------------------------------------------------
# Evaluator class
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
    ) -> None:
        self.bundle_dir = bundle_dir
        self.tool_report = tool_report
        self.tool_name = tool_name

    def run(self) -> EvaluationResult:
        """
        Execute the evaluation and return structured results.

        Returns
        -------
        EvaluationResult
        """
        ground_truth = self._load_ground_truth()
        run_id: str = ground_truth.get("run_id", "")
        mutations: list[dict] = ground_truth.get("mutations", [])
        findings: list[dict] = self.tool_report.get("findings", [])

        used_finding_indices: set[int] = set()
        match_records: list[MatchRecord] = []

        for idx, mutation in enumerate(mutations):
            record = self._match_mutation(idx, mutation, findings, used_finding_indices, ground_truth)
            match_records.append(record)

        # Count false positives: findings not matched to any mutation
        false_positive_count = sum(
            1 for i in range(len(findings)) if i not in used_finding_indices
        )

        return EvaluationResult(
            match_records=match_records,
            false_positive_count=false_positive_count,
            tool=self.tool_name,
            run_id=run_id,
        )

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

        Precedence: exact > family > semantic > no_match.
        When a finding is matched it is added to ``used`` to prevent double-counting.

        Parameters
        ----------
        idx:
            Zero-based index of this mutation in ground_truth.mutations.
        mutation:
            Single mutation record from ground_truth.mutations.
        findings:
            All findings from the detector report.
        used:
            Set of already-consumed finding indices (mutated in place).
        ground_truth:
            Full ground_truth dict (for top-level cwe_id lookup).

        Returns
        -------
        MatchRecord
        """
        # The CWE is stored at the root of ground_truth, not per-mutation
        mutation_cwe: Optional[str] = ground_truth.get("cwe_id") or None

        # Try each level in precedence order
        for level in ("exact", "family", "semantic"):
            for fi, finding in enumerate(findings):
                if fi in used:
                    continue
                matched = False
                if level == "exact":
                    matched = self._exact_match(mutation, finding, mutation_cwe)
                elif level == "family":
                    matched = self._family_match(mutation, finding, mutation_cwe)
                elif level == "semantic":
                    matched = self._semantic_match(mutation, finding, mutation_cwe)

                if matched:
                    used.add(fi)
                    adjudication_pending = level == "semantic"
                    rationale = _build_rationale(level, mutation, finding, mutation_cwe)
                    return MatchRecord(
                        mutation_index=idx,
                        mutation_type=mutation.get("mutation_type", ""),
                        file=mutation.get("file", ""),
                        line=mutation.get("line", 0),
                        cwe_id=mutation_cwe,
                        match_level=level,
                        matched_finding=finding,
                        rationale=rationale,
                        adjudication_pending=adjudication_pending,
                    )

        # No match found
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

    def _exact_match(
        self,
        mutation: dict[str, Any],
        finding: dict[str, Any],
        mutation_cwe: Optional[str],
    ) -> bool:
        """
        Exact match: same file basename, same CWE ID, line within ±2.
        """
        mut_basename = Path(mutation.get("file", "")).name
        find_basename = Path(finding.get("file", "")).name
        if mut_basename != find_basename:
            return False
        if finding.get("cwe_id") != mutation_cwe:
            return False
        mut_line: int = mutation.get("line", -999)
        find_line: int = finding.get("line", -999)
        return abs(find_line - mut_line) <= 2

    def _family_match(
        self,
        mutation: dict[str, Any],
        finding: dict[str, Any],
        mutation_cwe: Optional[str],
    ) -> bool:
        """
        Family match: same CWE family group (look up both in _CWE_FAMILIES).
        """
        if mutation_cwe is None:
            return False
        finding_cwe: Optional[str] = finding.get("cwe_id")
        if finding_cwe is None:
            return False
        mut_family = _CWE_FAMILIES.get(mutation_cwe)
        find_family = _CWE_FAMILIES.get(finding_cwe)
        if mut_family is None or find_family is None:
            return False
        return mut_family == find_family

    def _semantic_match(
        self,
        mutation: dict[str, Any],
        finding: dict[str, Any],
        mutation_cwe: Optional[str],
    ) -> bool:
        """
        Semantic match: keyword heuristic on finding message.

        Look up the mutation's CWE family → get keyword list → check any keyword
        in the finding message (case-insensitive).
        """
        if mutation_cwe is None:
            return False
        family = _CWE_FAMILIES.get(mutation_cwe)
        if family is None:
            return False
        keywords = _SEMANTIC_KEYWORDS.get(family)
        if not keywords:
            return False
        message = finding.get("message", "").lower()
        return any(kw in message for kw in keywords)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _build_rationale(
    level: str,
    mutation: dict[str, Any],
    finding: dict[str, Any],
    mutation_cwe: Optional[str],
) -> str:
    """Build a human-readable rationale string for a match."""
    mut_file = Path(mutation.get("file", "?")).name
    mut_line = mutation.get("line", "?")
    find_file = Path(finding.get("file", "?")).name
    find_line = finding.get("line", "?")
    find_cwe = finding.get("cwe_id", "none")

    if level == "exact":
        return (
            f"Exact match: file '{find_file}' (basename match), "
            f"CWE={find_cwe} matches mutation CWE={mutation_cwe}, "
            f"finding line {find_line} within ±2 of mutation line {mut_line}."
        )
    elif level == "family":
        mut_family = _CWE_FAMILIES.get(mutation_cwe or "", "unknown")
        return (
            f"Family match: mutation CWE={mutation_cwe} and finding CWE={find_cwe} "
            f"both belong to CWE family '{mut_family}'. "
            f"File: mutation={mut_file}, finding={find_file}."
        )
    elif level == "semantic":
        mut_family = _CWE_FAMILIES.get(mutation_cwe or "", "unknown")
        message_excerpt = finding.get("message", "")[:80]
        return (
            f"Semantic match: keyword from family '{mut_family}' found in finding message "
            f"'{message_excerpt}...'. Adjudication pending (LLM not invoked)."
        )
    return "Unknown match level."


# ---------------------------------------------------------------------------
# Emit functions
# ---------------------------------------------------------------------------

def emit_match_result(
    result: EvaluationResult,
    bundle_dir: Path,
    evaluated_at: str,
) -> dict[str, Any]:
    """
    Serialize the evaluation result to match_result.json and return the dict.

    Parameters
    ----------
    result:
        EvaluationResult from Evaluator.run().
    bundle_dir:
        Directory where match_result.json will be written.
    evaluated_at:
        ISO 8601 UTC timestamp string.

    Returns
    -------
    dict
        The serialized match_result artifact.
    """
    matches_list: list[dict[str, Any]] = []
    for rec in result.match_records:
        item: dict[str, Any] = {
            "mutation_index": rec.mutation_index,
            "mutation_type": rec.mutation_type,
            "file": rec.file,
            "line": rec.line,
            "match_level": rec.match_level,
            "matched_finding": rec.matched_finding,
            "rationale": rec.rationale,
        }
        if rec.cwe_id is not None:
            item["cwe_id"] = rec.cwe_id
        if rec.adjudication_pending:
            item["adjudication_pending"] = True
        matches_list.append(item)

    artifact: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": result.run_id,
        "tool": result.tool,
        "evaluated_at": evaluated_at,
        "mutations_evaluated": len(result.match_records),
        "matches": matches_list,
    }

    write_json_artifact(bundle_dir / "match_result.json", artifact)
    return artifact


def emit_coverage_result(
    result: EvaluationResult,
    bundle_dir: Path,
    evaluated_at: str,
) -> dict[str, Any]:
    """
    Compute coverage statistics and write coverage_result.json.

    Parameters
    ----------
    result:
        EvaluationResult from Evaluator.run().
    bundle_dir:
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

    write_json_artifact(bundle_dir / "coverage_result.json", artifact)
    return artifact
