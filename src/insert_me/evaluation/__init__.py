"""
insert_me evaluation module — per-project detector report evaluation.

Compare normalized detector reports against inserted ground truth to measure
how well a vulnerability detector finds what insert_me inserted.

This module is a separate concern from the insertion pipeline (pipeline/).
The evaluation step runs AFTER a successful insert-me run and operates on
the completed output bundle.

Public API
----------
Evaluator             Compare a detector report to ground truth in a bundle.
EvaluationResult      Aggregate result from Evaluator.run().
MatchRecord           Per-mutation match result (exact/family/semantic/no_match).
emit_match_result     Write match_result.json; return artifact dict.
emit_coverage_result  Write coverage_result.json; return artifact dict.
load_detector_report  Load a normalized detector report from a JSON file.
validate_detector_report  Schema-validate a detector report dict.

Matching levels
---------------
exact    same file basename + same CWE + line within ±2
family   same CWE family group (18 CWEs across 9 families)
semantic keyword heuristic on finding message (adjudication_pending=True)
no_match none of the above

Adjudication
------------
Semantic matches carry adjudication_pending=True.  The adjudication module
(adjudication.py) defines AdjudicationCase and emit_adjudication_result.
LLM-driven adjudication is Phase 7B; this phase leaves them as UNRESOLVED
without failing the evaluation.
"""

from insert_me.evaluation.evaluator import Evaluator, EvaluationResult, MatchRecord
from insert_me.evaluation.matching import emit_match_result
from insert_me.evaluation.coverage import emit_coverage_result
from insert_me.evaluation.detector_report import load_detector_report, validate_detector_report

__all__ = [
    "Evaluator",
    "EvaluationResult",
    "MatchRecord",
    "emit_match_result",
    "emit_coverage_result",
    "load_detector_report",
    "validate_detector_report",
]
