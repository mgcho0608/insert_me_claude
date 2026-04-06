"""
Dry-run pipeline tests for insert_me.

Coverage
--------
- Canonical seed input loading (seed JSON file)
- Run ID determinism: same inputs → same ID, different inputs → different ID
- Dry-run bundle creation: all expected artifacts are emitted
- Artifact schema validation for every emitted file
- validate-bundle succeeds on a generated dry-run bundle
- Legacy input path (--seed INT + --spec PATH) still produces a valid bundle
- Error handling: missing seed file, missing required config fields
"""

from __future__ import annotations

import json
import copy
import subprocess
import sys
from pathlib import Path

import pytest

from insert_me.artifacts import BundlePaths, derive_run_id_from_seed_data
from insert_me.config import Config, PipelineConfig, load_config, apply_cli_overrides
from insert_me.pipeline import run_pipeline
from insert_me.schema import (
    SCHEMA_AUDIT_RECORD,
    SCHEMA_AUDIT_RESULT,
    SCHEMA_GROUND_TRUTH,
    SCHEMA_PATCH_PLAN,
    SCHEMA_VALIDATION_RESULT,
    validate_artifact_file,
    validate_bundle,
    load_example,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
SEED_CWE122 = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
SEED_CWE416 = REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json"


def _make_config(tmp_path: Path, seed_file: Path, source_path: Path | None = None) -> Config:
    """Build a minimal Config for testing."""
    cfg = Config()
    cfg.pipeline.seed_file = seed_file
    cfg.pipeline.source_path = source_path or tmp_path / "src"
    cfg.pipeline.output_root = tmp_path / "output"
    return cfg


# ---------------------------------------------------------------------------
# Canonical input loading
# ---------------------------------------------------------------------------

class TestSeedLoading:
    def test_seed_file_loads(self):
        """Seed JSON files in examples/ must be loadable as dicts."""
        data = load_example("seeds/cwe122_heap_overflow.json")
        assert isinstance(data, dict)
        assert data["seed"] == 42
        assert data["cwe_id"] == "CWE-122"

    def test_all_example_seeds_loadable(self):
        seed_files = [
            "seeds/cwe122_heap_overflow.json",
            "seeds/cwe416_use_after_free.json",
            "seeds/cwe190_integer_overflow.json",
        ]
        for rel in seed_files:
            data = load_example(rel)
            assert "seed" in data
            assert "cwe_id" in data

    def test_pipeline_raises_on_missing_seed_file(self, tmp_path):
        cfg = _make_config(tmp_path, seed_file=tmp_path / "no_such_seed.json")
        with pytest.raises(FileNotFoundError):
            run_pipeline(cfg, dry_run=True)

    def test_pipeline_raises_when_no_seed_configured(self, tmp_path):
        cfg = Config()
        cfg.pipeline.output_root = tmp_path / "output"
        with pytest.raises(ValueError, match="No seed input configured"):
            run_pipeline(cfg, dry_run=True)


# ---------------------------------------------------------------------------
# Run ID determinism
# ---------------------------------------------------------------------------

class TestRunIdDeterminism:
    def test_same_inputs_same_run_id(self, tmp_path):
        seed_data = load_example("seeds/cwe122_heap_overflow.json")
        source = tmp_path / "src"
        id1 = derive_run_id_from_seed_data(seed_data, source, "0.1.0")
        id2 = derive_run_id_from_seed_data(seed_data, source, "0.1.0")
        assert id1 == id2

    def test_different_seed_different_run_id(self, tmp_path):
        s1 = load_example("seeds/cwe122_heap_overflow.json")
        s2 = load_example("seeds/cwe416_use_after_free.json")
        source = tmp_path / "src"
        id1 = derive_run_id_from_seed_data(s1, source, "0.1.0")
        id2 = derive_run_id_from_seed_data(s2, source, "0.1.0")
        assert id1 != id2

    def test_different_source_path_different_run_id(self, tmp_path):
        seed_data = load_example("seeds/cwe122_heap_overflow.json")
        id1 = derive_run_id_from_seed_data(seed_data, tmp_path / "src_a", "0.1.0")
        id2 = derive_run_id_from_seed_data(seed_data, tmp_path / "src_b", "0.1.0")
        assert id1 != id2

    def test_different_version_different_run_id(self, tmp_path):
        seed_data = load_example("seeds/cwe122_heap_overflow.json")
        source = tmp_path / "src"
        id1 = derive_run_id_from_seed_data(seed_data, source, "0.1.0")
        id2 = derive_run_id_from_seed_data(seed_data, source, "0.2.0")
        assert id1 != id2

    def test_run_id_is_16_hex_chars(self, tmp_path):
        seed_data = load_example("seeds/cwe122_heap_overflow.json")
        run_id = derive_run_id_from_seed_data(seed_data, tmp_path, "0.1.0")
        assert len(run_id) == 16
        assert all(c in "0123456789abcdef" for c in run_id)

    def test_pipeline_produces_same_run_id_on_repeat(self, tmp_path):
        """Running the pipeline twice with the same inputs must produce the same bundle dir."""
        cfg = _make_config(tmp_path, SEED_CWE122)
        b1 = run_pipeline(cfg, dry_run=True)

        cfg2 = _make_config(tmp_path, SEED_CWE122)
        b2 = run_pipeline(cfg2, dry_run=True)

        assert b1.root == b2.root


# ---------------------------------------------------------------------------
# Dry-run bundle creation
# ---------------------------------------------------------------------------

class TestDryRunBundleCreation:
    def test_all_core_artifacts_emitted(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        assert bundle.patch_plan.exists(), "patch_plan.json missing"
        assert bundle.validation_result.exists(), "validation_result.json missing"
        assert bundle.audit_result.exists(), "audit_result.json missing"
        assert bundle.ground_truth.exists(), "ground_truth.json missing"
        assert bundle.audit.exists(), "audit.json missing"

    def test_bundle_dirs_created(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        assert bundle.bad_dir.exists()
        assert bundle.good_dir.exists()

    def test_artifacts_are_valid_json(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        for path in [
            bundle.patch_plan,
            bundle.validation_result,
            bundle.audit_result,
            bundle.ground_truth,
            bundle.audit,
        ]:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, dict), f"{path.name} is not a JSON object"

    def test_patch_plan_fields(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["schema_version"] == "1.0"
        assert data["status"] == "PENDING"
        assert data["seed"] == 42
        assert isinstance(data["targets"], list)
        assert len(data["targets"]) == 0

    def test_validation_result_fields(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.validation_result, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["overall"] == "SKIP"
        assert data["checks"] == []

    def test_audit_result_fields(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.audit_result, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["classification"] == "NOOP"
        assert data["confidence"] == "low"
        assert len(data["evidence"]) >= 1

    def test_ground_truth_fields(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.ground_truth, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["cwe_id"] == "CWE-122"
        assert data["seed"] == 42
        assert data["mutations"] == []
        assert data["validation_passed"] is False

    def test_audit_json_fields(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.audit, encoding="utf-8") as fh:
            data = json.load(fh)

        assert data["seed"] == 42
        assert "run_id" in data
        assert "pipeline_version" in data
        assert "timestamp_utc" in data
        assert data["source_hash"] == "dry-run"

    def test_run_id_consistent_across_artifacts(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        # Extract run_id from bundle directory name
        run_id = bundle.root.name

        for path in [
            bundle.patch_plan,
            bundle.validation_result,
            bundle.audit_result,
            bundle.ground_truth,
            bundle.audit,
        ]:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            assert data["run_id"] == run_id, (
                f"{path.name} has run_id={data['run_id']!r}, expected {run_id!r}"
            )

    def test_plan_id_consistent(self, tmp_path):
        """patch_plan.plan_id must match validation_result.plan_id."""
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)
        with open(bundle.validation_result, encoding="utf-8") as fh:
            vr = json.load(fh)

        assert plan["plan_id"] == vr["plan_id"]


# ---------------------------------------------------------------------------
# Artifact schema validation
# ---------------------------------------------------------------------------

class TestArtifactSchemaValidation:
    def test_patch_plan_validates(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.patch_plan, SCHEMA_PATCH_PLAN)

    def test_validation_result_validates(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.validation_result, SCHEMA_VALIDATION_RESULT)

    def test_audit_result_validates(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.audit_result, SCHEMA_AUDIT_RESULT)

    def test_ground_truth_validates(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.ground_truth, SCHEMA_GROUND_TRUTH)

    def test_audit_validates(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.audit, SCHEMA_AUDIT_RECORD)

    @pytest.mark.parametrize("seed_filename", [
        "seeds/cwe122_heap_overflow.json",
        "seeds/cwe416_use_after_free.json",
        "seeds/cwe190_integer_overflow.json",
    ])
    def test_all_example_seeds_produce_valid_bundles(self, tmp_path, seed_filename):
        seed_file = REPO_ROOT / "examples" / seed_filename
        cfg = _make_config(tmp_path, seed_file)
        bundle = run_pipeline(cfg, dry_run=True)

        for path, schema in [
            (bundle.patch_plan, SCHEMA_PATCH_PLAN),
            (bundle.validation_result, SCHEMA_VALIDATION_RESULT),
            (bundle.audit_result, SCHEMA_AUDIT_RESULT),
            (bundle.ground_truth, SCHEMA_GROUND_TRUTH),
            (bundle.audit, SCHEMA_AUDIT_RECORD),
        ]:
            validate_artifact_file(path, schema)


# ---------------------------------------------------------------------------
# validate-bundle on dry-run output
# ---------------------------------------------------------------------------

class TestValidateBundle:
    def test_validate_bundle_succeeds_on_dry_run_output(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        errors = validate_bundle(bundle.root)
        assert errors == [], f"Unexpected validation errors: {errors}"

    def test_validate_bundle_fails_on_corrupted_artifact(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122)
        bundle = run_pipeline(cfg, dry_run=True)

        # Corrupt the patch_plan.json by removing a required field
        with open(bundle.patch_plan, encoding="utf-8") as fh:
            data = json.load(fh)
        del data["status"]
        with open(bundle.patch_plan, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        errors = validate_bundle(bundle.root)
        assert any("patch_plan.json" in e for e in errors)


# ---------------------------------------------------------------------------
# CLI end-to-end (subprocess)
# ---------------------------------------------------------------------------

class TestCLIEndToEnd:
    def test_cli_run_with_seed_file(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", str(SEED_CWE122),
                "--source", str(tmp_path / "src"),
                "--output", str(tmp_path / "output"),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "bundle written to" in result.stdout.lower()

    def test_cli_run_legacy_seed_spec(self, tmp_path):
        """Legacy --seed INT --spec PATH interface must still work."""
        spec_file = tmp_path / "spec.toml"
        spec_file.write_text("[meta]\nid = 'test'\n")

        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed", "99",
                "--spec", str(spec_file),
                "--source", str(tmp_path / "src"),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_cli_run_fails_without_seed_input(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--source", str(tmp_path / "src"),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_cli_run_fails_with_both_seed_file_and_legacy(self, tmp_path):
        spec_file = tmp_path / "spec.toml"
        spec_file.write_text("")
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", str(SEED_CWE122),
                "--seed", "42",
                "--spec", str(spec_file),
                "--source", str(tmp_path / "src"),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_cli_validate_bundle_succeeds(self, tmp_path):
        # First produce a dry-run bundle
        run_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", str(SEED_CWE122),
                "--source", str(tmp_path / "src"),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert run_result.returncode == 0, f"run failed: {run_result.stderr}"

        # Find the bundle dir
        output_root = tmp_path / "output"
        bundle_dirs = list(output_root.iterdir())
        assert len(bundle_dirs) == 1
        bundle_dir = bundle_dirs[0]

        # Now validate it
        val_result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "validate-bundle",
                str(bundle_dir),
            ],
            capture_output=True,
            text=True,
        )
        assert val_result.returncode == 0, f"validate-bundle failed: {val_result.stderr}"
        assert "valid" in val_result.stdout.lower()


# ---------------------------------------------------------------------------
# Legacy input path
# ---------------------------------------------------------------------------

class TestLegacyInput:
    def test_legacy_int_seed_produces_valid_bundle(self, tmp_path):
        cfg = Config()
        cfg.pipeline.seed = 42
        cfg.pipeline.spec_path = tmp_path / "spec.toml"
        (tmp_path / "spec.toml").write_text("[meta]\nid = 'test'\n")
        cfg.pipeline.source_path = tmp_path / "src"
        cfg.pipeline.output_root = tmp_path / "output"

        bundle = run_pipeline(cfg, dry_run=True)

        assert bundle.patch_plan.exists()
        assert bundle.audit.exists()

        # Must pass schema validation
        validate_artifact_file(bundle.audit, SCHEMA_AUDIT_RECORD)

    def test_legacy_missing_spec_file_still_produces_bundle(self, tmp_path):
        """Legacy mode with non-existent spec file must still run (spec is optional)."""
        cfg = Config()
        cfg.pipeline.seed = 7
        cfg.pipeline.spec_path = tmp_path / "nonexistent.toml"
        cfg.pipeline.source_path = tmp_path / "src"
        cfg.pipeline.output_root = tmp_path / "output"

        # Should not raise; spec file is hashed if present, ignored if absent
        bundle = run_pipeline(cfg, dry_run=True)
        assert bundle.audit.exists()
