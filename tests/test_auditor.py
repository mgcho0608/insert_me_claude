"""
Auditor tests — Phase 6 deterministic ground-truth and provenance generation.

Coverage
--------
- Auditor.run() writes ground_truth.json, audit.json, audit_result.json
- Mutation records in ground_truth.json match the real Patcher output
- validation_passed reflects the actual Validator verdict
- audit_result classification logic:
    - VALID  when real mutations + Validator PASS
    - INVALID when real mutations + Validator FAIL
    - AMBIGUOUS when real mutations + Validator SKIP
    - NOOP when no mutations (dry-run or no compatible target)
- dry-run produces valid, honest artifacts with empty mutations
- All artifacts pass schema validation
- Integration smoke test: demo fixture produces a complete bundle
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from insert_me.artifacts import BundlePaths
from insert_me.pipeline.auditor import (
    Auditor,
    GroundTruthRecord,
    MutationRecord,
    _audit_to_dict,
    _ground_truth_to_dict,
)
from insert_me.pipeline.patcher import Mutation, PatchResult, PatchTarget
from insert_me.pipeline.validator import CheckResult, CheckStatus, ValidationVerdict
from insert_me.schema import validate_artifact, SCHEMA_GROUND_TRUTH, SCHEMA_AUDIT_RECORD, SCHEMA_AUDIT_RESULT

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEED_DATA = {
    "schema_version": "1.0",
    "seed_id": "test-seed-001",
    "seed": 42,
    "cwe_id": "CWE-122",
    "vulnerability_class": "Heap Buffer Overflow",
    "mutation_strategy": "alloc_size_undercount",
    "target_pattern": {"pattern_type": "malloc_call"},
}


def _make_target(file: str = "foo.c", line: int = 10) -> PatchTarget:
    return PatchTarget(
        file=Path(file),
        line=line,
        score=0.75,
        mutation_strategy="alloc_size_undercount",
        context={"expression": "malloc(n)", "function_name": "fn"},
    )


def _make_mutation() -> Mutation:
    return Mutation(
        target=_make_target(),
        mutation_type="alloc_size_undercount",
        original_fragment="malloc(n * sizeof(char))",
        mutated_fragment="malloc((n * sizeof(char)) - 1)",
    )


def _make_patch_result(tmp_path: Path, *, with_mutation: bool = True) -> PatchResult:
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    mutations = [_make_mutation()] if with_mutation else []
    return PatchResult(bad_root=bad, good_root=good, mutations=mutations)


def _pass_verdict() -> ValidationVerdict:
    return ValidationVerdict(checks=[
        CheckResult("mutation_applied", CheckStatus.PASS, "1 mutation(s) applied."),
        CheckResult("good_tree_integrity", CheckStatus.PASS, "byte-identical."),
        CheckResult("bad_tree_changed", CheckStatus.PASS, "mutation present."),
        CheckResult("mutation_scope", CheckStatus.PASS, "1 file changed."),
        CheckResult("simple_syntax_sanity", CheckStatus.PASS, "parens balanced."),
    ])


def _fail_verdict() -> ValidationVerdict:
    return ValidationVerdict(checks=[
        CheckResult("mutation_applied", CheckStatus.PASS, "1 mutation(s) applied."),
        CheckResult("good_tree_integrity", CheckStatus.FAIL, "tampered."),
        CheckResult("bad_tree_changed", CheckStatus.PASS, "mutation present."),
        CheckResult("mutation_scope", CheckStatus.PASS, "1 file changed."),
        CheckResult("simple_syntax_sanity", CheckStatus.PASS, "parens balanced."),
    ])


def _skip_verdict() -> ValidationVerdict:
    return ValidationVerdict(checks=[])  # dry-run: SKIP, passed=False


def _make_auditor(
    tmp_path: Path,
    patch_result: PatchResult | None,
    verdict: ValidationVerdict,
) -> tuple[Auditor, BundlePaths]:
    bundle = BundlePaths.from_run_id(tmp_path / "output", "abcd1234ef567890")
    bundle.create_dirs()
    auditor = Auditor(
        patch_result=patch_result,
        verdict=verdict,
        bundle=bundle,
        run_id="abcd1234ef567890",
        seed=42,
        seed_data=_SEED_DATA,
        pipeline_version="0.1.0",
        spec_path=None,
        spec_hash="dryhash",
        source_root=tmp_path / "src",
        source_hash="srchash00000000",
    )
    return auditor, bundle


# ---------------------------------------------------------------------------
# MutationRecord
# ---------------------------------------------------------------------------

class TestMutationRecord:
    def test_from_mutation_uses_target_file_as_is(self):
        m = _make_mutation()
        rec = MutationRecord.from_mutation(m)
        assert rec.file == "foo.c"
        assert rec.line == 10
        assert rec.mutation_type == "alloc_size_undercount"
        assert rec.original_fragment == "malloc(n * sizeof(char))"
        assert rec.mutated_fragment == "malloc((n * sizeof(char)) - 1)"

    def test_from_mutation_extra_defaults_empty(self):
        m = _make_mutation()
        rec = MutationRecord.from_mutation(m)
        assert rec.extra == {}


# ---------------------------------------------------------------------------
# Auditor.run() — artifact writes
# ---------------------------------------------------------------------------

class TestAuditorWritesArtifacts:
    def test_writes_ground_truth_json(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()
        assert bundle.ground_truth.exists()

    def test_writes_audit_json(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()
        assert bundle.audit.exists()

    def test_writes_audit_result_json(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()
        assert bundle.audit_result.exists()

    def test_returns_ground_truth_and_audit_records(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        gt, ar = auditor.run()
        assert isinstance(gt, GroundTruthRecord)
        assert gt.run_id == "abcd1234ef567890"
        assert ar.run_id == "abcd1234ef567890"


# ---------------------------------------------------------------------------
# ground_truth.json content
# ---------------------------------------------------------------------------

class TestGroundTruthContent:
    def test_mutation_records_match_patcher_output(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert len(gt["mutations"]) == 1
        m = gt["mutations"][0]
        assert m["file"] == "foo.c"
        assert m["line"] == 10
        assert m["mutation_type"] == "alloc_size_undercount"
        assert m["original_fragment"] == "malloc(n * sizeof(char))"
        assert m["mutated_fragment"] == "malloc((n * sizeof(char)) - 1)"

    def test_validation_passed_true_on_pass_verdict(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["validation_passed"] is True

    def test_validation_passed_false_on_fail_verdict(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _fail_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["validation_passed"] is False

    def test_cwe_id_from_seed_data(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["cwe_id"] == "CWE-122"

    def test_empty_mutations_when_no_patch_result(self, tmp_path):
        auditor, bundle = _make_auditor(tmp_path, None, _skip_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["mutations"] == []
        assert gt["validation_passed"] is False

    def test_empty_mutations_when_patch_result_has_no_mutations(self, tmp_path):
        pr = _make_patch_result(tmp_path, with_mutation=False)
        auditor, bundle = _make_auditor(tmp_path, pr, _skip_verdict())
        auditor.run()

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["mutations"] == []


# ---------------------------------------------------------------------------
# audit.json content
# ---------------------------------------------------------------------------

class TestAuditContent:
    def test_audit_core_fields_present(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        ar = json.loads(bundle.audit.read_text(encoding="utf-8"))
        assert ar["run_id"] == "abcd1234ef567890"
        assert ar["seed"] == 42
        assert "pipeline_version" in ar
        assert "timestamp_utc" in ar
        assert "source_hash" in ar
        assert isinstance(ar["source_hash"], str)

    def test_audit_validation_verdict_reflects_pass(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        ar = json.loads(bundle.audit.read_text(encoding="utf-8"))
        assert ar["validation_verdict"]["passed"] is True
        assert len(ar["validation_verdict"]["checks"]) == 5

    def test_audit_validation_verdict_reflects_skip_in_dry_run(self, tmp_path):
        auditor, bundle = _make_auditor(tmp_path, None, _skip_verdict())
        auditor.run()

        ar = json.loads(bundle.audit.read_text(encoding="utf-8"))
        assert ar["validation_verdict"]["passed"] is False
        assert ar["validation_verdict"]["checks"] == []


# ---------------------------------------------------------------------------
# audit_result.json classification
# ---------------------------------------------------------------------------

class TestAuditResultClassification:
    def test_valid_when_mutations_and_pass_verdict(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "VALID"
        assert ar["confidence"] == "medium"

    def test_invalid_when_mutations_and_fail_verdict(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _fail_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "INVALID"
        assert ar["confidence"] == "medium"

    def test_ambiguous_when_mutations_and_skip_verdict(self, tmp_path):
        # Construct a SKIP verdict that still has mutations (edge case)
        pr = _make_patch_result(tmp_path)
        # Manual SKIP-like verdict: all checks are CheckStatus.SKIP
        skip_with_mutations = ValidationVerdict(checks=[
            CheckResult("mutation_applied", CheckStatus.SKIP, "skipped."),
        ])
        auditor, bundle = _make_auditor(tmp_path, pr, skip_with_mutations)
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "AMBIGUOUS"

    def test_noop_when_no_patch_result(self, tmp_path):
        auditor, bundle = _make_auditor(tmp_path, None, _skip_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "NOOP"
        assert ar["confidence"] == "low"

    def test_noop_when_patch_result_has_no_mutations(self, tmp_path):
        pr = _make_patch_result(tmp_path, with_mutation=False)
        auditor, bundle = _make_auditor(tmp_path, pr, _skip_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "NOOP"

    def test_audit_result_has_reviewer(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["reviewer"]["type"] == "deterministic"
        assert ar["reviewer"]["name"] == "auditor_phase6_v1"

    def test_invalid_evidence_names_failed_check(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _fail_verdict())
        auditor.run()

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        obs = ar["evidence"][0]["observation"]
        assert "good_tree_integrity" in obs


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestAuditorSchemaValidation:
    def test_ground_truth_passes_schema(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        data = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        validate_artifact(data, SCHEMA_GROUND_TRUTH)  # raises on failure

    def test_audit_passes_schema(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        data = json.loads(bundle.audit.read_text(encoding="utf-8"))
        validate_artifact(data, SCHEMA_AUDIT_RECORD)

    def test_audit_result_passes_schema(self, tmp_path):
        pr = _make_patch_result(tmp_path)
        auditor, bundle = _make_auditor(tmp_path, pr, _pass_verdict())
        auditor.run()

        data = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        validate_artifact(data, SCHEMA_AUDIT_RESULT)

    def test_dry_run_artifacts_pass_schema(self, tmp_path):
        auditor, bundle = _make_auditor(tmp_path, None, _skip_verdict())
        auditor.run()

        for path, schema in [
            (bundle.ground_truth, SCHEMA_GROUND_TRUTH),
            (bundle.audit, SCHEMA_AUDIT_RECORD),
            (bundle.audit_result, SCHEMA_AUDIT_RESULT),
        ]:
            data = json.loads(path.read_text(encoding="utf-8"))
            validate_artifact(data, schema)


# ---------------------------------------------------------------------------
# Pipeline integration via run_pipeline()
# ---------------------------------------------------------------------------

class TestAuditorPipelineIntegration:
    def _make_config(self, tmp_path, seed_file=DEMO_SEED, source=DEMO_SOURCE):
        from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
        return Config(
            pipeline=PipelineConfig(
                seed_file=seed_file,
                source_path=source,
                output_root=tmp_path / "output",
            ),
            llm=LLMConfig(),
            validator=ValidatorConfig(),
            auditor=AuditorConfig(),
        )

    def test_real_mode_ground_truth_has_mutation_record(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(self._make_config(tmp_path), dry_run=False)

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert len(gt["mutations"]) == 1
        m = gt["mutations"][0]
        assert m["mutation_type"] == "alloc_size_undercount"
        assert "malloc(" in m["original_fragment"]
        assert "- 1)" in m["mutated_fragment"]
        assert gt["validation_passed"] is True

    def test_real_mode_audit_json_fields(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(self._make_config(tmp_path), dry_run=False)

        ar = json.loads(bundle.audit.read_text(encoding="utf-8"))
        assert "run_id" in ar
        assert "timestamp_utc" in ar
        assert "pipeline_version" in ar
        assert ar["validation_verdict"]["passed"] is True
        assert len(ar["validation_verdict"]["checks"]) == 5

    def test_real_mode_audit_result_valid(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(self._make_config(tmp_path), dry_run=False)

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "VALID"
        assert ar["reviewer"]["name"] == "auditor_phase6_v1"

    def test_dry_run_ground_truth_empty_mutations(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(self._make_config(tmp_path), dry_run=True)

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["mutations"] == []
        assert gt["validation_passed"] is False

    def test_dry_run_audit_result_noop(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(self._make_config(tmp_path), dry_run=True)

        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "NOOP"

    def test_full_bundle_passes_validate_bundle(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli", "run",
                "--seed-file", str(DEMO_SEED),
                "--source", str(DEMO_SOURCE),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"CLI run failed:\n{result.stdout}\n{result.stderr}"
        )
        bundle = next((tmp_path / "output").iterdir())
        result2 = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle)],
            capture_output=True,
            text=True,
        )
        assert result2.returncode == 0, (
            f"validate-bundle failed:\n{result2.stdout}\n{result2.stderr}"
        )
