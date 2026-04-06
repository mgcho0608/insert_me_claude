"""
Evaluator tests — Phase 7A per-project evaluation against inserted ground truth.

Coverage
--------
1. TestExactMatch          — exact_match_report.json fixture → match_level == "exact"
2. TestFamilyMatch         — family_match_report.json fixture → match_level == "family"
3. TestNoMatch             — no_match_report.json fixture → match_level == "no_match"
4. TestCoverageResult      — exact match case: coverage_rate==1.0, matched==1, unmatched==0
5. TestSemanticMatch       — message-keyword finding, no CWE → match_level == "semantic"
6. TestAdjudicationPendingWhenNoLLM — semantic case: adjudication_result.json NOT written
7. TestEvaluateCLI         — subprocess call to insert-me evaluate, returncode==0, artifacts exist
8. TestDetectorReportSchemaValidation — validate fixture against schema
9. TestMatchResultSchemaValidation    — validate written match_result.json after evaluation
10. TestCoverageResultSchemaValidation — validate written coverage_result.json after evaluation
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED_CWE416 = REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"
EVAL_FIXTURES = REPO_ROOT / "examples" / "evaluation"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cwe416_config(tmp_path: Path):
    from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
    return Config(
        pipeline=PipelineConfig(
            seed_file=DEMO_SEED_CWE416,
            source_path=DEMO_SOURCE,
            output_root=tmp_path / "output",
        ),
        llm=LLMConfig(),
        validator=ValidatorConfig(),
        auditor=AuditorConfig(),
    )


def _run_cwe416_pipeline(tmp_path: Path):
    """Run the CWE-416 pipeline and return the bundle."""
    from insert_me.pipeline import run_pipeline
    config = _make_cwe416_config(tmp_path)
    return run_pipeline(config, dry_run=False)


def _load_fixture(name: str) -> dict:
    path = EVAL_FIXTURES / name
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _run_evaluator(bundle_dir: Path, report: dict, tool_name: str):
    from insert_me.pipeline.evaluator import Evaluator
    evaluator = Evaluator(bundle_dir, report, tool_name)
    return evaluator.run()


def _emit_all(result, bundle_dir: Path) -> tuple[dict, dict]:
    """Emit match_result and coverage_result, return both dicts."""
    import datetime
    from insert_me.pipeline.evaluator import emit_match_result, emit_coverage_result
    now_utc = "2026-04-06T10:00:00Z"
    mr = emit_match_result(result, bundle_dir, now_utc)
    cr = emit_coverage_result(result, bundle_dir, now_utc)
    return mr, cr


# ---------------------------------------------------------------------------
# 1. TestExactMatch
# ---------------------------------------------------------------------------

class TestExactMatch:
    """exact_match_report.json should produce match_level == 'exact'."""

    def test_exact_match_level(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        assert len(result.match_records) == 1
        rec = result.match_records[0]
        assert rec.match_level == "exact", (
            f"Expected 'exact', got '{rec.match_level}'. Rationale: {rec.rationale}"
        )

    def test_exact_match_has_finding(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        rec = result.match_records[0]
        assert rec.matched_finding is not None
        assert rec.matched_finding["cwe_id"] == "CWE-416"

    def test_exact_match_no_adjudication_pending(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        rec = result.match_records[0]
        assert not rec.adjudication_pending

    def test_exact_match_false_positives_zero(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        assert result.false_positive_count == 0


# ---------------------------------------------------------------------------
# 2. TestFamilyMatch
# ---------------------------------------------------------------------------

class TestFamilyMatch:
    """family_match_report.json (CWE-415) should produce match_level == 'family'."""

    def test_family_match_level(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("family_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        assert len(result.match_records) == 1
        rec = result.match_records[0]
        assert rec.match_level == "family", (
            f"Expected 'family', got '{rec.match_level}'. Rationale: {rec.rationale}"
        )

    def test_family_match_has_finding(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("family_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        rec = result.match_records[0]
        assert rec.matched_finding is not None
        # CWE-415 is not CWE-416, so this is family not exact
        assert rec.matched_finding.get("cwe_id") == "CWE-415"


# ---------------------------------------------------------------------------
# 3. TestNoMatch
# ---------------------------------------------------------------------------

class TestNoMatch:
    """no_match_report.json (different file, different CWE) should produce 'no_match'."""

    def test_no_match_level(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        assert len(result.match_records) == 1
        rec = result.match_records[0]
        assert rec.match_level == "no_match", (
            f"Expected 'no_match', got '{rec.match_level}'. Rationale: {rec.rationale}"
        )

    def test_no_match_finding_is_null(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")

        rec = result.match_records[0]
        assert rec.matched_finding is None

    def test_no_match_false_positive_counted(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        # The unmatched finding in other.c should count as a false positive
        assert result.false_positive_count == 1


# ---------------------------------------------------------------------------
# 4. TestCoverageResult
# ---------------------------------------------------------------------------

class TestCoverageResult:
    """Exact match case: coverage_rate==1.0, matched==1, unmatched==0."""

    def test_coverage_rate_exact_match(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _, cr = _emit_all(result, bundle.root)

        assert cr["coverage_rate"] == 1.0
        assert cr["matched"] == 1
        assert cr["unmatched"] == 0
        assert cr["total_mutations"] == 1

    def test_coverage_rate_no_match(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _, cr = _emit_all(result, bundle.root)

        assert cr["coverage_rate"] == 0.0
        assert cr["matched"] == 0
        assert cr["unmatched"] == 1

    def test_by_level_exact_count(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _, cr = _emit_all(result, bundle.root)

        assert cr["by_level"]["exact"] == 1
        assert cr["by_level"]["family"] == 0
        assert cr["by_level"]["semantic"] == 0
        assert cr["by_level"]["no_match"] == 0


# ---------------------------------------------------------------------------
# 5. TestSemanticMatch
# ---------------------------------------------------------------------------

class TestSemanticMatch:
    """Finding with message 'use after free detected' and no CWE → match_level == 'semantic'."""

    def _make_semantic_report(self) -> dict:
        return {
            "schema_version": "1.0",
            "tool": "test-tool",
            "findings": [
                {
                    "file": "uaf_demo.c",
                    "line": 42,
                    "message": "use after free detected in function process_record",
                }
            ],
        }

    def test_semantic_match_level(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")

        assert len(result.match_records) == 1
        rec = result.match_records[0]
        assert rec.match_level == "semantic", (
            f"Expected 'semantic', got '{rec.match_level}'. Rationale: {rec.rationale}"
        )

    def test_semantic_match_adjudication_pending(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")

        rec = result.match_records[0]
        assert rec.adjudication_pending is True, (
            "Semantic match should set adjudication_pending=True"
        )

    def test_semantic_match_finding_attached(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")

        rec = result.match_records[0]
        assert rec.matched_finding is not None
        assert "use after free" in rec.matched_finding.get("message", "").lower()


# ---------------------------------------------------------------------------
# 6. TestAdjudicationPendingWhenNoLLM
# ---------------------------------------------------------------------------

class TestAdjudicationPendingWhenNoLLM:
    """Without LLM: semantic cases are pending, adjudication_result.json is NOT written."""

    def _make_semantic_report(self) -> dict:
        return {
            "schema_version": "1.0",
            "tool": "test-tool",
            "findings": [
                {
                    "file": "uaf_demo.c",
                    "line": 42,
                    "message": "dangling pointer access after freed memory",
                }
            ],
        }

    def test_adjudication_result_not_written(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")
        _emit_all(result, bundle.root)

        adjudication_path = bundle.root / "adjudication_result.json"
        assert not adjudication_path.exists(), (
            "adjudication_result.json should NOT be written when LLM is not configured"
        )

    def test_match_result_written(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")
        _emit_all(result, bundle.root)

        match_path = bundle.root / "match_result.json"
        assert match_path.exists()

    def test_semantic_pending_in_match_result_json(self, tmp_path):
        bundle = _run_cwe416_pipeline(tmp_path)
        report = self._make_semantic_report()
        result = _run_evaluator(bundle.root, report, "test-tool")
        _emit_all(result, bundle.root)

        with open(bundle.root / "match_result.json", encoding="utf-8") as fh:
            mr = json.load(fh)

        assert len(mr["matches"]) == 1
        match = mr["matches"][0]
        assert match["match_level"] == "semantic"
        assert match.get("adjudication_pending") is True


# ---------------------------------------------------------------------------
# 7. TestEvaluateCLI
# ---------------------------------------------------------------------------

class TestEvaluateCLI:
    """subprocess call to insert-me evaluate; returncode==0; match_result.json exists."""

    def test_evaluate_cli_exact_match(self, tmp_path):
        # Step 1: create a bundle via CLI
        seed_file = str(DEMO_SEED_CWE416)
        source = str(DEMO_SOURCE)
        output_dir = str(tmp_path / "output")

        run_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", seed_file,
                "--source", source,
                "--output", output_dir,
            ],
            capture_output=True,
            text=True,
        )
        assert run_result.returncode == 0, (
            f"run failed: {run_result.stdout}\n{run_result.stderr}"
        )

        # Extract bundle dir from stdout
        bundle_dir = None
        for line in run_result.stdout.splitlines():
            if "bundle written to:" in line:
                bundle_dir = Path(line.split("bundle written to:", 1)[1].strip())
                break
        assert bundle_dir is not None, "Could not parse bundle dir from output"
        assert bundle_dir.exists()

        # Step 2: run evaluate
        report_path = str(EVAL_FIXTURES / "exact_match_report.json")
        eval_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "evaluate",
                "--bundle", str(bundle_dir),
                "--tool-report", report_path,
                "--tool", "cppcheck-demo",
            ],
            capture_output=True,
            text=True,
        )
        assert eval_result.returncode == 0, (
            f"evaluate failed: {eval_result.stdout}\n{eval_result.stderr}"
        )

        match_result_path = bundle_dir / "match_result.json"
        coverage_result_path = bundle_dir / "coverage_result.json"
        assert match_result_path.exists(), "match_result.json not written"
        assert coverage_result_path.exists(), "coverage_result.json not written"

    def test_evaluate_cli_output_summary(self, tmp_path):
        """The CLI should print coverage summary to stdout."""
        seed_file = str(DEMO_SEED_CWE416)
        source = str(DEMO_SOURCE)
        output_dir = str(tmp_path / "output")

        run_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run", "--seed-file", seed_file, "--source", source, "--output", output_dir,
            ],
            capture_output=True, text=True,
        )
        assert run_result.returncode == 0

        bundle_dir = None
        for line in run_result.stdout.splitlines():
            if "bundle written to:" in line:
                bundle_dir = Path(line.split("bundle written to:", 1)[1].strip())
                break

        report_path = str(EVAL_FIXTURES / "exact_match_report.json")
        eval_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "evaluate",
                "--bundle", str(bundle_dir),
                "--tool-report", report_path,
                "--tool", "cppcheck-demo",
            ],
            capture_output=True, text=True,
        )
        assert eval_result.returncode == 0
        stdout = eval_result.stdout
        assert "coverage_rate" in stdout
        assert "total_mutations" in stdout


# ---------------------------------------------------------------------------
# 8. TestDetectorReportSchemaValidation
# ---------------------------------------------------------------------------

class TestDetectorReportSchemaValidation:
    """Validate exact_match_report.json against detector_report.schema.json."""

    def test_exact_match_report_is_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
        report = _load_fixture("exact_match_report.json")
        # Should not raise
        validate_artifact(report, SCHEMA_DETECTOR_REPORT)

    def test_family_match_report_is_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
        report = _load_fixture("family_match_report.json")
        validate_artifact(report, SCHEMA_DETECTOR_REPORT)

    def test_no_match_report_is_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
        report = _load_fixture("no_match_report.json")
        validate_artifact(report, SCHEMA_DETECTOR_REPORT)

    def test_invalid_cwe_pattern_rejected(self):
        import jsonschema
        from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
        bad_report = {
            "schema_version": "1.0",
            "tool": "test",
            "findings": [
                {
                    "file": "foo.c",
                    "cwe_id": "416",  # Missing "CWE-" prefix — should fail
                }
            ],
        }
        with pytest.raises(jsonschema.ValidationError):
            validate_artifact(bad_report, SCHEMA_DETECTOR_REPORT)

    def test_missing_required_field_rejected(self):
        import jsonschema
        from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
        bad_report = {
            "schema_version": "1.0",
            # Missing "tool" field
            "findings": [],
        }
        with pytest.raises(jsonschema.ValidationError):
            validate_artifact(bad_report, SCHEMA_DETECTOR_REPORT)


# ---------------------------------------------------------------------------
# 9. TestMatchResultSchemaValidation
# ---------------------------------------------------------------------------

class TestMatchResultSchemaValidation:
    """After evaluation, validate written match_result.json against schema."""

    def test_match_result_exact_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_MATCH_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _emit_all(result, bundle.root)

        match_result_path = bundle.root / "match_result.json"
        assert match_result_path.exists()
        validate_artifact_file(match_result_path, SCHEMA_MATCH_RESULT)

    def test_match_result_no_match_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_MATCH_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _emit_all(result, bundle.root)

        validate_artifact_file(bundle.root / "match_result.json", SCHEMA_MATCH_RESULT)

    def test_match_result_family_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_MATCH_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("family_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _emit_all(result, bundle.root)

        validate_artifact_file(bundle.root / "match_result.json", SCHEMA_MATCH_RESULT)

    def test_match_result_semantic_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_MATCH_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        semantic_report = {
            "schema_version": "1.0",
            "tool": "test-tool",
            "findings": [
                {
                    "file": "uaf_demo.c",
                    "line": 42,
                    "message": "use after free detected",
                }
            ],
        }
        result = _run_evaluator(bundle.root, semantic_report, "test-tool")
        _emit_all(result, bundle.root)

        validate_artifact_file(bundle.root / "match_result.json", SCHEMA_MATCH_RESULT)


# ---------------------------------------------------------------------------
# 10. TestCoverageResultSchemaValidation
# ---------------------------------------------------------------------------

class TestCoverageResultSchemaValidation:
    """Validate written coverage_result.json against schema."""

    def test_coverage_result_exact_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_COVERAGE_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("exact_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _emit_all(result, bundle.root)

        coverage_result_path = bundle.root / "coverage_result.json"
        assert coverage_result_path.exists()
        validate_artifact_file(coverage_result_path, SCHEMA_COVERAGE_RESULT)

    def test_coverage_result_no_match_is_valid(self, tmp_path):
        from insert_me.schema import validate_artifact_file, SCHEMA_COVERAGE_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("no_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _emit_all(result, bundle.root)

        validate_artifact_file(bundle.root / "coverage_result.json", SCHEMA_COVERAGE_RESULT)

    def test_coverage_rate_range(self, tmp_path):
        """coverage_rate must be in [0, 1]."""
        from insert_me.schema import validate_artifact_file, SCHEMA_COVERAGE_RESULT
        bundle = _run_cwe416_pipeline(tmp_path)
        report = _load_fixture("family_match_report.json")
        result = _run_evaluator(bundle.root, report, "cppcheck-demo")
        _, cr = _emit_all(result, bundle.root)

        assert 0.0 <= cr["coverage_rate"] <= 1.0
        validate_artifact_file(bundle.root / "coverage_result.json", SCHEMA_COVERAGE_RESULT)
