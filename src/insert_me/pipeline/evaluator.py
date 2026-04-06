"""
Backward-compatibility shim.

All evaluation logic has moved to ``src/insert_me/evaluation/``.
This module re-exports the public API so that existing code that imports
from ``insert_me.pipeline.evaluator`` continues to work.

New code should import from ``insert_me.evaluation`` directly.
"""

from insert_me.evaluation.evaluator import Evaluator, EvaluationResult, MatchRecord
from insert_me.evaluation.matching import emit_match_result
from insert_me.evaluation.coverage import emit_coverage_result

__all__ = [
    "Evaluator",
    "EvaluationResult",
    "MatchRecord",
    "emit_match_result",
    "emit_coverage_result",
]
