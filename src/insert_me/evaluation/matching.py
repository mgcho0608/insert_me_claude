"""
Matching logic for per-project evaluation.

Defines CWE family groups, semantic keyword hints, and the three match
levels used by the Evaluator to compare detector findings to inserted
ground truth mutations.

Match levels (precedence order):
    exact    — same file basename + same CWE ID + finding line within ±2 of
               the mutation insertion site
    family   — both CWEs map to the same family group (e.g. CWE-416 and
               CWE-415 both → "use-after-free")
    semantic — a keyword from the mutation's CWE family appears in the
               finding message; marks adjudication_pending=True because
               this is a heuristic inference, not a hard match
    no_match — none of the above

LLM adjudication is a separate optional step (see adjudication.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from insert_me import ARTIFACT_SCHEMA_VERSION
from insert_me.artifacts import write_json_artifact

if TYPE_CHECKING:
    from insert_me.evaluation.evaluator import EvaluationResult


# ---------------------------------------------------------------------------
# CWE family mapping
# ---------------------------------------------------------------------------

_CWE_FAMILIES: dict[str, str] = {
    # Buffer errors
    "CWE-119": "buffer-overflow",
    "CWE-120": "buffer-overflow",
    "CWE-123": "buffer-overflow",
    "CWE-124": "buffer-overflow",
    "CWE-125": "buffer-overflow",
    # Heap / stack buffer overflow
    "CWE-121": "stack-buffer-overflow",
    "CWE-122": "heap-buffer-overflow",
    # Integer issues
    "CWE-190": "integer-overflow",
    "CWE-191": "integer-overflow",
    "CWE-680": "integer-overflow",
    # Use-after-free family
    "CWE-415": "use-after-free",
    "CWE-416": "use-after-free",
    "CWE-825": "use-after-free",
    # Other
    "CWE-476": "null-pointer",
    "CWE-369": "divide-by-zero",
    "CWE-134": "format-string",
    "CWE-78":  "command-injection",
    "CWE-89":  "sql-injection",
}


# ---------------------------------------------------------------------------
# Semantic keyword hints
# ---------------------------------------------------------------------------

# Maps CWE family → list of keywords to search in finding messages.
# Keywords must be specific enough to avoid false positives; prefer
# multi-word phrases over single words.
_SEMANTIC_KEYWORDS: dict[str, list[str]] = {
    "use-after-free":        ["use after free", "use-after-free", "uaf", "dangling pointer",
                              "freed memory", "after free"],
    "heap-buffer-overflow":  ["heap overflow", "heap buffer overflow", "heap buffer",
                              "out of bounds write", "oob write"],
    "stack-buffer-overflow": ["stack overflow", "stack buffer overflow", "stack buffer",
                              "stack smash"],
    "buffer-overflow":       ["buffer overflow", "buffer overrun", "buffer overwrite",
                              "out of bounds"],
    "integer-overflow":      ["integer overflow", "int overflow", "integer wrap",
                              "arithmetic overflow"],
    "null-pointer":          ["null pointer", "null dereference", "null pointer dereference",
                              "nullptr"],
    "format-string":         ["format string", "format-string"],
}


# ---------------------------------------------------------------------------
# Public match functions
# ---------------------------------------------------------------------------

def cwe_family(cwe_id: Optional[str]) -> Optional[str]:
    """Return the family group for a CWE ID, or None if not mapped."""
    if cwe_id is None:
        return None
    return _CWE_FAMILIES.get(cwe_id)


def exact_match(
    mutation: dict[str, Any],
    finding: dict[str, Any],
    mutation_cwe: Optional[str],
) -> bool:
    """
    Return True when the finding is an exact match for the mutation.

    Criteria:
    - Same file (basename comparison — tool reports may use different root paths)
    - Same CWE ID
    - Finding line within ±2 of the mutation's insertion line
    """
    mut_basename = Path(mutation.get("file", "")).name
    find_basename = Path(finding.get("file", "")).name
    if mut_basename != find_basename:
        return False
    if finding.get("cwe_id") != mutation_cwe:
        return False
    mut_line: int = mutation.get("line", -9999)
    find_line: int = finding.get("line", -9999)
    return abs(find_line - mut_line) <= 2


def family_match(
    mutation: dict[str, Any],
    finding: dict[str, Any],
    mutation_cwe: Optional[str],
) -> bool:
    """
    Return True when the finding shares a CWE family with the mutation.

    Both the mutation CWE and the finding CWE must be present and map to
    the same family in ``_CWE_FAMILIES``.  File proximity is not required
    because a tool may report the symptom at a different call site.
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


def semantic_match(
    mutation: dict[str, Any],
    finding: dict[str, Any],
    mutation_cwe: Optional[str],
) -> bool:
    """
    Return True when the finding message contains keywords from the mutation's
    CWE family.

    This is a heuristic inference: a True result does NOT guarantee the
    finding describes the inserted vulnerability.  Callers must set
    ``adjudication_pending=True`` and optionally invoke the LLM adjudicator
    to confirm.
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
# Rationale builder
# ---------------------------------------------------------------------------

def build_rationale(
    level: str,
    mutation: dict[str, Any],
    finding: dict[str, Any],
    mutation_cwe: Optional[str],
) -> str:
    """Return a human-readable explanation of why a match was made."""
    mut_file = Path(mutation.get("file", "?")).name
    mut_line = mutation.get("line", "?")
    find_file = Path(finding.get("file", "?")).name
    find_line = finding.get("line", "?")
    find_cwe = finding.get("cwe_id", "none")

    if level == "exact":
        return (
            f"Exact match: file '{find_file}' (basename), "
            f"CWE {find_cwe} == mutation CWE {mutation_cwe}, "
            f"line {find_line} within ±2 of mutation line {mut_line}."
        )
    if level == "family":
        family = _CWE_FAMILIES.get(mutation_cwe or "", "unknown")
        return (
            f"Family match: mutation CWE {mutation_cwe} and finding CWE {find_cwe} "
            f"both belong to CWE family '{family}'. "
            f"Mutation file: {mut_file}, finding file: {find_file}."
        )
    if level == "semantic":
        family = _CWE_FAMILIES.get(mutation_cwe or "", "unknown")
        excerpt = finding.get("message", "")[:80]
        return (
            f"Semantic match: keyword from family '{family}' found in message "
            f"'{excerpt}'. Adjudication pending — LLM not invoked."
        )
    return "No match found at exact, family, or semantic level."


# ---------------------------------------------------------------------------
# Emit function
# ---------------------------------------------------------------------------

def emit_match_result(
    result: "EvaluationResult",
    output_dir: Path,
    evaluated_at: str,
) -> dict[str, Any]:
    """
    Serialize evaluation result to match_result.json and return the artifact dict.

    Parameters
    ----------
    result:
        EvaluationResult from Evaluator.run().
    output_dir:
        Directory where match_result.json will be written.
    evaluated_at:
        ISO 8601 UTC timestamp string.
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

    write_json_artifact(output_dir / "match_result.json", artifact)
    return artifact
