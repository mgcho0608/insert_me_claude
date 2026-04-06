"""
Phase 6 hardening tests — vertical-slice coherence and failure paths.

Coverage
--------
- Real-mode bundle: all 5 core artifacts present, run_id and plan_id interlinked
- INVALID classification path through the full pipeline
- validate-bundle correctly rejects an intentionally malformed artifact
- audit.json timestamp is a valid ISO 8601 UTC string (not a snapshot match)
- Dry-run honest-no-op: source trees untouched, classification NOOP
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(tmp_path, seed_file=DEMO_SEED, source=DEMO_SOURCE, dry_run=False):
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


# ---------------------------------------------------------------------------
# Cross-artifact coherence (real mode)
# ---------------------------------------------------------------------------

class TestBundleCoherence:
    """All 5 core artifacts must agree on run_id and plan_id."""

    def test_all_core_artifacts_present(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        assert bundle.patch_plan.exists(), "patch_plan.json missing"
        assert bundle.validation_result.exists(), "validation_result.json missing"
        assert bundle.audit_result.exists(), "audit_result.json missing"
        assert bundle.ground_truth.exists(), "ground_truth.json missing"
        assert bundle.audit.exists(), "audit.json missing"

    def test_run_id_consistent_across_all_artifacts(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        pp = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        vr = json.loads(bundle.validation_result.read_text(encoding="utf-8"))
        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        au = json.loads(bundle.audit.read_text(encoding="utf-8"))

        run_id = pp["run_id"]
        assert len(run_id) == 16, "run_id must be 16 hex chars"
        assert vr["run_id"] == run_id, "validation_result run_id mismatch"
        assert ar["run_id"] == run_id, "audit_result run_id mismatch"
        assert gt["run_id"] == run_id, "ground_truth run_id mismatch"
        assert au["run_id"] == run_id, "audit run_id mismatch"

    def test_plan_id_links_patch_plan_to_validation_result(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        pp = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        vr = json.loads(bundle.validation_result.read_text(encoding="utf-8"))

        plan_id = pp["plan_id"]
        assert plan_id.startswith("plan-"), "plan_id must begin with 'plan-'"
        assert vr["plan_id"] == plan_id, "validation_result plan_id must equal patch_plan plan_id"

    def test_source_tree_hash_consistent_patch_plan_and_audit(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        pp = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        au = json.loads(bundle.audit.read_text(encoding="utf-8"))

        assert pp["source_tree_hash"] == au["source_hash"], (
            "source_tree_hash in patch_plan must equal source_hash in audit"
        )

    def test_real_mode_bad_and_good_dirs_non_empty(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        bad_files = list(bundle.bad_dir.rglob("*"))
        good_files = list(bundle.good_dir.rglob("*"))
        assert any(f.is_file() for f in bad_files), "bad/ must contain at least one file"
        assert any(f.is_file() for f in good_files), "good/ must contain at least one file"

    def test_audit_timestamp_is_iso8601_utc(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        import datetime
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)

        au = json.loads(bundle.audit.read_text(encoding="utf-8"))
        ts = au["timestamp_utc"]
        # Must be parseable as ISO 8601 UTC (ends with Z or +00:00)
        assert ts.endswith("Z") or ts.endswith("+00:00"), (
            f"timestamp_utc must be UTC: {ts!r}"
        )
        # Must parse without error
        ts_normalized = ts.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(ts_normalized)
        assert dt.tzinfo is not None, "timestamp_utc must include timezone"


# ---------------------------------------------------------------------------
# Dry-run honest no-op
# ---------------------------------------------------------------------------

class TestDryRunHonestNoOp:
    def test_source_dir_unmodified(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        # Record source file mtimes before run
        before = {
            f: f.stat().st_mtime
            for f in DEMO_SOURCE.rglob("*")
            if f.is_file()
        }
        run_pipeline(_make_config(tmp_path), dry_run=True)
        after = {
            f: f.stat().st_mtime
            for f in DEMO_SOURCE.rglob("*")
            if f.is_file()
        }
        assert before == after, "dry-run must not modify source files"

    def test_bad_and_good_dirs_empty(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=True)

        bad_files = [f for f in bundle.bad_dir.rglob("*") if f.is_file()]
        good_files = [f for f in bundle.good_dir.rglob("*") if f.is_file()]
        assert bad_files == [], "dry-run bad/ must be empty"
        assert good_files == [], "dry-run good/ must be empty"

    def test_dry_run_patch_plan_status_planned(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=True)

        pp = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        assert pp["status"] in ("PLANNED", "PENDING"), (
            f"dry-run patch_plan status must be PLANNED or PENDING, got: {pp['status']}"
        )


# ---------------------------------------------------------------------------
# validate-bundle failure case
# ---------------------------------------------------------------------------

class TestValidateBundleFailure:
    """validate-bundle must reject malformed artifacts."""

    def _run_real_bundle(self, tmp_path) -> Path:
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
        assert result.returncode == 0, f"CLI run failed:\n{result.stderr}"
        return next((tmp_path / "output").iterdir())

    def test_valid_bundle_passes(self, tmp_path):
        bundle_dir = self._run_real_bundle(tmp_path)
        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"validate-bundle failed unexpectedly:\n{result.stderr}"

    def test_malformed_patch_plan_fails(self, tmp_path):
        bundle_dir = self._run_real_bundle(tmp_path)
        patch_plan = bundle_dir / "patch_plan.json"

        data = json.loads(patch_plan.read_text(encoding="utf-8"))
        # Remove a required field to invalidate the schema
        del data["run_id"]
        patch_plan.write_text(json.dumps(data), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "validate-bundle should fail on malformed patch_plan.json"
        )

    def test_malformed_audit_result_fails(self, tmp_path):
        bundle_dir = self._run_real_bundle(tmp_path)
        audit_result = bundle_dir / "audit_result.json"

        data = json.loads(audit_result.read_text(encoding="utf-8"))
        # Write an invalid classification value
        data["classification"] = "BOGUS_VALUE"
        audit_result.write_text(json.dumps(data), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "validate-bundle should fail on invalid classification in audit_result.json"
        )

    def test_missing_artifact_fails(self, tmp_path):
        bundle_dir = self._run_real_bundle(tmp_path)
        (bundle_dir / "ground_truth.json").unlink()

        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "validate-bundle should fail when ground_truth.json is missing"
        )


# ---------------------------------------------------------------------------
# INVALID classification path via Auditor unit test
# ---------------------------------------------------------------------------

class TestInvalidClassificationPath:
    """Confirm INVALID path through real Auditor (not mocked)."""

    def test_invalid_audit_result_schema_valid(self, tmp_path):
        from insert_me.artifacts import BundlePaths
        from insert_me.pipeline.auditor import Auditor
        from insert_me.pipeline.patcher import Mutation, PatchResult, PatchTarget
        from insert_me.pipeline.validator import CheckResult, CheckStatus, ValidationVerdict
        from insert_me.schema import validate_artifact, SCHEMA_AUDIT_RESULT

        bad = tmp_path / "bad"
        good = tmp_path / "good"
        bad.mkdir()
        good.mkdir()

        target = PatchTarget(
            file=Path("test.c"),
            line=5,
            score=0.8,
            mutation_strategy="alloc_size_undercount",
            context={"expression": "malloc(n)", "function_name": "fn"},
        )
        mutation = Mutation(
            target=target,
            mutation_type="alloc_size_undercount",
            original_fragment="malloc(n)",
            mutated_fragment="malloc((n) - 1)",
        )
        patch_result = PatchResult(bad_root=bad, good_root=good, mutations=[mutation])

        fail_verdict = ValidationVerdict(checks=[
            CheckResult("mutation_applied", CheckStatus.PASS, "applied."),
            CheckResult("good_tree_integrity", CheckStatus.FAIL, "integrity check failed: mismatch."),
            CheckResult("bad_tree_changed", CheckStatus.PASS, "changed."),
            CheckResult("mutation_scope", CheckStatus.PASS, "1 file."),
            CheckResult("simple_syntax_sanity", CheckStatus.PASS, "parens ok."),
        ])

        bundle = BundlePaths.from_run_id(tmp_path / "output", "deadbeef01234567")
        bundle.create_dirs()

        seed_data = {
            "schema_version": "1.0",
            "seed_id": "hardening-001",
            "seed": 99,
            "cwe_id": "CWE-122",
            "vulnerability_class": "Heap Buffer Overflow",
            "mutation_strategy": "alloc_size_undercount",
            "target_pattern": {"pattern_type": "malloc_call"},
        }

        auditor = Auditor(
            patch_result=patch_result,
            verdict=fail_verdict,
            bundle=bundle,
            run_id="deadbeef01234567",
            seed=99,
            seed_data=seed_data,
            pipeline_version="0.1.0",
            spec_path=None,
            spec_hash="testhash",
            source_root=tmp_path / "src",
            source_hash="srchash12345678",
        )
        auditor.run()

        data = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert data["classification"] == "INVALID"
        assert data["confidence"] == "medium"
        validate_artifact(data, SCHEMA_AUDIT_RESULT)  # must pass schema even for INVALID

    def test_invalid_evidence_references_failed_check_name(self, tmp_path):
        from insert_me.artifacts import BundlePaths
        from insert_me.pipeline.auditor import Auditor
        from insert_me.pipeline.patcher import Mutation, PatchResult, PatchTarget
        from insert_me.pipeline.validator import CheckResult, CheckStatus, ValidationVerdict

        bad = tmp_path / "bad"
        good = tmp_path / "good"
        bad.mkdir()
        good.mkdir()

        target = PatchTarget(
            file=Path("test.c"),
            line=5,
            score=0.8,
            mutation_strategy="alloc_size_undercount",
            context={"expression": "malloc(n)", "function_name": "fn"},
        )
        mutation = Mutation(
            target=target,
            mutation_type="alloc_size_undercount",
            original_fragment="malloc(n)",
            mutated_fragment="malloc((n) - 1)",
        )
        patch_result = PatchResult(bad_root=bad, good_root=good, mutations=[mutation])

        fail_verdict = ValidationVerdict(checks=[
            CheckResult("mutation_applied", CheckStatus.PASS, "applied."),
            CheckResult("simple_syntax_sanity", CheckStatus.FAIL, "unbalanced parens."),
        ])

        bundle = BundlePaths.from_run_id(tmp_path / "output", "cafebabe12345678")
        bundle.create_dirs()

        seed_data = {
            "schema_version": "1.0",
            "seed_id": "hardening-002",
            "seed": 1,
            "cwe_id": "CWE-122",
            "vulnerability_class": "Heap Buffer Overflow",
            "mutation_strategy": "alloc_size_undercount",
            "target_pattern": {"pattern_type": "malloc_call"},
        }

        auditor = Auditor(
            patch_result=patch_result,
            verdict=fail_verdict,
            bundle=bundle,
            run_id="cafebabe12345678",
            seed=1,
            seed_data=seed_data,
            pipeline_version="0.1.0",
            spec_path=None,
            spec_hash="testhash2",
            source_root=tmp_path / "src",
            source_hash="srchash87654321",
        )
        auditor.run()

        data = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert data["classification"] == "INVALID"
        # The evidence observation must mention the failing check by name
        observations = [e["observation"] for e in data["evidence"]]
        assert any("simple_syntax_sanity" in obs for obs in observations), (
            f"Expected 'simple_syntax_sanity' in evidence observations; got: {observations}"
        )
