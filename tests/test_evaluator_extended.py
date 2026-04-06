"""
Extended evaluation tests — Phase 7A evaluation/ package structure.

Coverage
--------
11. TestEvaluationPackageStructure — evaluation/ exports, module separation
12. TestDetectorReportHelpers      — load_detector_report, validate_detector_report
13. TestAdjudicationModule         — collect_pending_cases, try_adjudicate, emit
14. TestMatchingModule             — exact/family/semantic match functions directly
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EVAL_FIXTURES = REPO_ROOT / "examples" / "evaluation"


# ---------------------------------------------------------------------------
# 11. TestEvaluationPackageStructure
# ---------------------------------------------------------------------------

class TestEvaluationPackageStructure:
    """evaluation/ package exports are accessible and correctly separated."""

    def test_evaluator_importable_from_evaluation_package(self):
        from insert_me.evaluation import Evaluator
        assert callable(Evaluator)

    def test_emit_match_result_importable(self):
        from insert_me.evaluation import emit_match_result
        assert callable(emit_match_result)

    def test_emit_coverage_result_importable(self):
        from insert_me.evaluation import emit_coverage_result
        assert callable(emit_coverage_result)

    def test_load_detector_report_importable(self):
        from insert_me.evaluation import load_detector_report
        assert callable(load_detector_report)

    def test_validate_detector_report_importable(self):
        from insert_me.evaluation import validate_detector_report
        assert callable(validate_detector_report)

    def test_pipeline_shim_still_works(self):
        """pipeline.evaluator shim must re-export the same Evaluator class."""
        from insert_me.evaluation import Evaluator as EvalEvaluator
        from insert_me.pipeline.evaluator import Evaluator as PipeEvaluator
        assert EvalEvaluator is PipeEvaluator

    def test_evaluation_has_separate_matching_module(self):
        from insert_me.evaluation import matching
        assert hasattr(matching, "exact_match")
        assert hasattr(matching, "family_match")
        assert hasattr(matching, "semantic_match")

    def test_evaluation_has_separate_coverage_module(self):
        from insert_me.evaluation import coverage
        assert hasattr(coverage, "emit_coverage_result")

    def test_evaluation_has_adjudication_module(self):
        from insert_me.evaluation import adjudication
        assert hasattr(adjudication, "AdjudicationCase")
        assert hasattr(adjudication, "try_adjudicate")
        assert hasattr(adjudication, "emit_adjudication_result")

    def test_evaluation_has_detector_report_module(self):
        from insert_me.evaluation import detector_report
        assert hasattr(detector_report, "load_detector_report")
        assert hasattr(detector_report, "validate_detector_report")


# ---------------------------------------------------------------------------
# 12. TestDetectorReportHelpers
# ---------------------------------------------------------------------------

class TestDetectorReportHelpers:
    """load_detector_report and validate_detector_report work correctly."""

    def test_load_detector_report_returns_dict(self):
        from insert_me.evaluation.detector_report import load_detector_report
        path = EVAL_FIXTURES / "exact_match_report.json"
        report = load_detector_report(path)
        assert isinstance(report, dict)
        assert "findings" in report

    def test_load_detector_report_raises_on_missing_file(self, tmp_path):
        from insert_me.evaluation.detector_report import load_detector_report
        with pytest.raises(FileNotFoundError):
            load_detector_report(tmp_path / "nonexistent.json")

    def test_validate_detector_report_passes_valid(self):
        from insert_me.evaluation.detector_report import (
            load_detector_report,
            validate_detector_report,
        )
        path = EVAL_FIXTURES / "exact_match_report.json"
        report = load_detector_report(path)
        validate_detector_report(report)  # should not raise

    def test_validate_detector_report_rejects_invalid(self):
        import jsonschema
        from insert_me.evaluation.detector_report import validate_detector_report
        bad = {"schema_version": "1.0"}  # missing required "tool" field
        with pytest.raises(jsonschema.ValidationError):
            validate_detector_report(bad)


# ---------------------------------------------------------------------------
# 13. TestAdjudicationModule
# ---------------------------------------------------------------------------

class TestAdjudicationModule:
    """collect_pending_cases and try_adjudicate behave correctly with no LLM."""

    def _make_semantic_record(self):
        from insert_me.evaluation.evaluator import MatchRecord
        return MatchRecord(
            mutation_index=0,
            mutation_type="insert_premature_free",
            file="uaf_demo.c",
            line=42,
            cwe_id="CWE-416",
            match_level="semantic",
            matched_finding={
                "file": "uaf_demo.c",
                "line": 42,
                "message": "use after free",
            },
            rationale="Semantic match.",
            adjudication_pending=True,
        )

    def _make_exact_record(self):
        from insert_me.evaluation.evaluator import MatchRecord
        return MatchRecord(
            mutation_index=1,
            mutation_type="insert_premature_free",
            file="uaf_demo.c",
            line=42,
            cwe_id="CWE-416",
            match_level="exact",
            matched_finding={"file": "uaf_demo.c", "line": 42, "cwe_id": "CWE-416"},
            rationale="Exact match.",
            adjudication_pending=False,
        )

    def test_collect_pending_returns_semantic_only(self):
        from insert_me.evaluation.adjudication import collect_pending_cases
        records = [self._make_exact_record(), self._make_semantic_record()]
        pending = collect_pending_cases(records)
        assert len(pending) == 1
        assert pending[0].match_level == "semantic"

    def test_collect_pending_empty_when_no_semantic(self):
        from insert_me.evaluation.adjudication import collect_pending_cases
        records = [self._make_exact_record()]
        pending = collect_pending_cases(records)
        assert pending == []

    def test_try_adjudicate_returns_empty_without_llm(self):
        from insert_me.evaluation.adjudication import try_adjudicate
        pending = [self._make_semantic_record()]
        cases = try_adjudicate(pending, llm_adapter=None)
        assert cases == []

    def test_emit_adjudication_result_skips_empty_cases(self, tmp_path):
        from insert_me.evaluation.adjudication import emit_adjudication_result
        result = emit_adjudication_result(
            [], "run-id-1234", "cppcheck", "heuristic", tmp_path
        )
        assert result is None
        assert not (tmp_path / "adjudication_result.json").exists()

    def test_emit_adjudication_result_writes_nonempty_cases(self, tmp_path):
        from insert_me.evaluation.adjudication import AdjudicationCase, emit_adjudication_result
        cases = [
            AdjudicationCase(
                mutation_index=0,
                finding_id="f001",
                verdict="match",
                confidence=0.85,
                rationale="Keyword match confirmed.",
                adjudicator="heuristic",
            )
        ]
        result = emit_adjudication_result(
            cases, "run-id-1234", "cppcheck", "heuristic", tmp_path
        )
        assert result is not None
        adj_path = tmp_path / "adjudication_result.json"
        assert adj_path.exists()
        data = json.loads(adj_path.read_text(encoding="utf-8"))
        assert data["adjudicator"] == "heuristic"
        assert len(data["cases"]) == 1
        assert data["cases"][0]["verdict"] == "match"

    def test_adjudication_result_schema_valid(self, tmp_path):
        from insert_me.evaluation.adjudication import AdjudicationCase, emit_adjudication_result
        from insert_me.schema import validate_artifact_file, SCHEMA_ADJUDICATION_RESULT
        cases = [
            AdjudicationCase(
                mutation_index=0,
                finding_id="f001",
                verdict="ambiguous",
                confidence=0.5,
                rationale="Could not determine.",
                adjudicator="heuristic",
            )
        ]
        emit_adjudication_result(
            cases, "run-id-1234", "cppcheck", "heuristic", tmp_path
        )
        validate_artifact_file(tmp_path / "adjudication_result.json", SCHEMA_ADJUDICATION_RESULT)


# ---------------------------------------------------------------------------
# 14. TestMatchingModule
# ---------------------------------------------------------------------------

class TestMatchingModule:
    """Unit tests for exact_match, family_match, semantic_match in matching.py."""

    def test_exact_match_same_file_cwe_line(self):
        from insert_me.evaluation.matching import exact_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 42, "cwe_id": "CWE-416"}
        assert exact_match(mutation, finding, "CWE-416") is True

    def test_exact_match_line_within_tolerance(self):
        from insert_me.evaluation.matching import exact_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 44, "cwe_id": "CWE-416"}
        assert exact_match(mutation, finding, "CWE-416") is True

    def test_exact_match_fails_line_too_far(self):
        from insert_me.evaluation.matching import exact_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 50, "cwe_id": "CWE-416"}
        assert exact_match(mutation, finding, "CWE-416") is False

    def test_exact_match_fails_wrong_cwe(self):
        from insert_me.evaluation.matching import exact_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 42, "cwe_id": "CWE-122"}
        assert exact_match(mutation, finding, "CWE-416") is False

    def test_exact_match_fails_wrong_file(self):
        from insert_me.evaluation.matching import exact_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "bar.c", "line": 42, "cwe_id": "CWE-416"}
        assert exact_match(mutation, finding, "CWE-416") is False

    def test_family_match_cwe416_cwe415(self):
        from insert_me.evaluation.matching import family_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "other.c", "line": 99, "cwe_id": "CWE-415"}
        # Family match does not require same file — symptom may be reported elsewhere
        assert family_match(mutation, finding, "CWE-416") is True

    def test_family_match_different_families_false(self):
        from insert_me.evaluation.matching import family_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 42, "cwe_id": "CWE-122"}
        # CWE-122 (heap-buffer-overflow) != CWE-416 (use-after-free)
        assert family_match(mutation, finding, "CWE-416") is False

    def test_family_match_missing_cwe_in_finding(self):
        from insert_me.evaluation.matching import family_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 42}  # no cwe_id
        assert family_match(mutation, finding, "CWE-416") is False

    def test_semantic_match_keyword_in_message(self):
        from insert_me.evaluation.matching import semantic_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"file": "foo.c", "line": 99, "message": "use after free detected"}
        assert semantic_match(mutation, finding, "CWE-416") is True

    def test_semantic_match_dangling_keyword(self):
        from insert_me.evaluation.matching import semantic_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"message": "dangling pointer dereference"}
        assert semantic_match(mutation, finding, "CWE-416") is True

    def test_semantic_match_no_keyword_false(self):
        from insert_me.evaluation.matching import semantic_match
        mutation = {"file": "foo.c", "line": 42}
        finding = {"message": "suspicious function call"}
        assert semantic_match(mutation, finding, "CWE-416") is False

    def test_semantic_match_heap_overflow_keyword(self):
        from insert_me.evaluation.matching import semantic_match
        mutation = {"file": "foo.c", "line": 10}
        finding = {"message": "heap buffer overflow at offset 4"}
        assert semantic_match(mutation, finding, "CWE-122") is True

    def test_cwe_family_known_values(self):
        from insert_me.evaluation.matching import cwe_family
        assert cwe_family("CWE-416") == "use-after-free"
        assert cwe_family("CWE-415") == "use-after-free"
        assert cwe_family("CWE-122") == "heap-buffer-overflow"
        assert cwe_family("CWE-190") == "integer-overflow"
        assert cwe_family("CWE-476") == "null-pointer"

    def test_cwe_family_unknown_returns_none(self):
        from insert_me.evaluation.matching import cwe_family
        assert cwe_family("CWE-9999") is None
        assert cwe_family(None) is None
