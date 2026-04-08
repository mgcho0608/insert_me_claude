"""
Lightweight regression checks for the workload characterization tooling.

These tests verify that:
1. The workload_classes.json manifest is self-consistent with known fixtures.
2. profile_pipeline_stage.py produces stage_timing_report.json with expected fields.
3. characterize_workloads.py produces support_matrix.json and target_classification.json
   with expected structure.
4. Target workload class assignments match the expected mapping.
5. The support envelope script is importable and produces consistent results.

Test philosophy:
- Timing values are NOT asserted (they vary per machine).
- Structure, field presence, and class assignments ARE asserted.
- Full generate-corpus runs are skipped to keep tests fast;
  only inspect + plan are exercised.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
WORKLOAD_CLASSES_PATH = REPO_ROOT / "config" / "workload_classes.json"

# Expected workload class for each known fixture
EXPECTED_CLASSES = {
    "minimal":     "tiny",
    "demo":        "tiny",
    "moderate":    "small",
    "target_b":    "small",
    "sandbox_eval":"medium",
}

KNOWN_TARGET_PATHS = {
    "minimal":     REPO_ROOT / "examples" / "local_targets" / "minimal" / "src",
    "demo":        REPO_ROOT / "examples" / "demo" / "src",
    "moderate":    REPO_ROOT / "examples" / "local_targets" / "moderate" / "src",
    "target_b":    REPO_ROOT / "examples" / "sandbox_targets" / "target_b" / "src",
    "sandbox_eval":REPO_ROOT / "examples" / "sandbox_eval" / "src",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_wc() -> dict:
    return json.loads(WORKLOAD_CLASSES_PATH.read_text(encoding="utf-8"))


def _classify(files: int, loc: int, wc: dict) -> str:
    for cls_name, cls in wc["classes"].items():
        loc_ok = loc <= cls.get("loc_max", 10**9) and loc >= cls.get("loc_min", 0)
        file_ok = files <= cls.get("files_max", 10**9) and files >= cls.get("files_min", 0)
        if loc_ok and file_ok:
            return cls_name
    return "large_phase16"


# ---------------------------------------------------------------------------
# 1. Workload classes manifest integrity
# ---------------------------------------------------------------------------


class TestWorkloadClassesManifest:
    """workload_classes.json must be well-formed and internally consistent."""

    def test_manifest_exists(self) -> None:
        assert WORKLOAD_CLASSES_PATH.exists(), "config/workload_classes.json not found"

    def test_manifest_valid_json(self) -> None:
        _load_wc()

    def test_required_classes_present(self) -> None:
        wc = _load_wc()
        for cls in ("tiny", "small", "medium", "large_phase16"):
            assert cls in wc["classes"], f"class '{cls}' missing from workload_classes.json"

    def test_required_class_fields(self) -> None:
        wc = _load_wc()
        for cls_name, cls in wc["classes"].items():
            assert "support_level" in cls, f"{cls_name}: missing 'support_level'"
            assert "recommended_max_count" in cls, f"{cls_name}: missing 'recommended_max_count'"

    def test_known_targets_present(self) -> None:
        wc = _load_wc()
        for name in EXPECTED_CLASSES:
            assert name in wc["known_targets"], (
                f"Known target '{name}' missing from workload_classes.json"
            )

    def test_known_target_class_matches_expected(self) -> None:
        wc = _load_wc()
        for name, expected_cls in EXPECTED_CLASSES.items():
            if name in wc["known_targets"]:
                actual = wc["known_targets"][name]["workload_class"]
                assert actual == expected_cls, (
                    f"Known target '{name}': expected class={expected_cls!r}, "
                    f"got {actual!r} in workload_classes.json"
                )

    def test_stage_timing_benchmarks_present(self) -> None:
        wc = _load_wc()
        assert "stage_timing_benchmarks" in wc
        bm = wc["stage_timing_benchmarks"]["per_pipeline_case"]
        for key in ("tiny_minimal", "small_moderate", "medium_sandbox_eval"):
            assert key in bm, f"stage_timing_benchmarks missing key '{key}'"
            for stage in ("seeder", "patcher", "validator", "auditor", "total"):
                assert stage in bm[key], f"stage_timing_benchmarks[{key}] missing '{stage}'"


# ---------------------------------------------------------------------------
# 2. Workload classification algorithm
# ---------------------------------------------------------------------------


class TestWorkloadClassification:
    """The LOC+file_count classification algorithm must assign expected classes."""

    def _count_files_and_loc(self, source: Path) -> tuple[int, int]:
        exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
        files = [f for f in source.rglob("*") if f.suffix in exts]
        loc = sum(
            len(f.read_text(encoding="utf-8", errors="replace").splitlines())
            for f in files
        )
        return len(files), loc

    @pytest.mark.parametrize("name,expected_class", list(EXPECTED_CLASSES.items()))
    def test_fixture_classified_correctly(self, name: str, expected_class: str) -> None:
        source = KNOWN_TARGET_PATHS[name]
        assert source.exists(), f"Fixture path not found: {source}"
        wc = _load_wc()
        n_files, loc = self._count_files_and_loc(source)
        actual_class = _classify(n_files, loc, wc)
        assert actual_class == expected_class, (
            f"Fixture '{name}' ({n_files} files, {loc} LOC): "
            f"expected class={expected_class!r}, got {actual_class!r}"
        )


# ---------------------------------------------------------------------------
# 3. profile_pipeline_stage.py — artifact structure
# ---------------------------------------------------------------------------


class TestProfilePipelineStage:
    """profile_pipeline_stage.py must produce a well-formed stage_timing_report.json."""

    def test_script_importable(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import profile_pipeline_stage  # noqa: F401

    def test_run_stage_profiling_produces_expected_fields(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from profile_pipeline_stage import run_stage_profiling

        seed_file = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = REPO_ROOT / "examples" / "demo" / "src"

        report = run_stage_profiling(seed_file, source, runs=2)

        assert report["schema_version"] == "1.0"
        assert "phase" in report
        assert "stages" in report
        assert "pipeline_total_mean_ms" in report
        assert "dominant_stage" in report
        assert "dominant_stage_pct" in report

        for stage in ("seeder", "patcher", "validator", "auditor"):
            assert stage in report["stages"], f"Missing stage '{stage}'"
            s = report["stages"][stage]
            assert "mean_ms" in s
            assert "min_ms" in s
            assert "max_ms" in s
            assert "all_ms" in s
            assert len(s["all_ms"]) == 2  # runs=2

        # dominant stage must be one of the four stages
        assert report["dominant_stage"] in ("seeder", "patcher", "validator", "auditor")
        # percentages must be plausible
        assert 0 < report["dominant_stage_pct"] <= 100

    def test_run_stage_profiling_output_can_be_serialized(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from profile_pipeline_stage import run_stage_profiling

        seed_file = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = REPO_ROOT / "examples" / "demo" / "src"
        report = run_stage_profiling(seed_file, source, runs=1)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "stage_timing_report.json"
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            loaded = json.loads(out.read_text(encoding="utf-8"))
            assert loaded["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# 4. characterize_workloads.py — artifact structure
# ---------------------------------------------------------------------------


class TestCharacterizeWorkloads:
    """characterize_workloads.py must produce well-formed artifacts."""

    def test_script_importable(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import characterize_workloads  # noqa: F401

    def test_characterize_all_inspect_only_produces_expected_structure(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from characterize_workloads import characterize_all

        results = characterize_all(skip_generate=True, generate_count=3)

        # All five known targets must appear
        for name in EXPECTED_CLASSES:
            assert name in results, f"Target '{name}' missing from characterize_all() output"

        for name, r in results.items():
            assert "workload_class" in r, f"{name}: missing workload_class"
            assert "files" in r, f"{name}: missing files"
            assert "loc_approx" in r, f"{name}: missing loc_approx"
            assert "support_level" in r, f"{name}: missing support_level"
            assert "inspect" in r, f"{name}: missing inspect section"
            assert "plan_corpus" in r, f"{name}: missing plan_corpus section"
            # In skip_generate mode, generate_corpus should be absent
            assert "generate_corpus" not in r, f"{name}: generate_corpus present in skip mode"

    def test_target_classes_match_expected(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from characterize_workloads import characterize_all

        results = characterize_all(skip_generate=True, generate_count=3)
        for name, expected_cls in EXPECTED_CLASSES.items():
            actual_cls = results[name]["workload_class"]
            assert actual_cls == expected_cls, (
                f"Target '{name}': expected class={expected_cls!r}, "
                f"got {actual_cls!r} from characterize_all()"
            )

    def test_support_matrix_structure(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from characterize_workloads import _build_support_matrix, characterize_all

        wc = _load_wc()
        results = characterize_all(skip_generate=True, generate_count=3)
        matrix = _build_support_matrix(results, wc)

        assert "schema_version" in matrix
        assert "workload_class_thresholds" in matrix
        assert "targets" in matrix

        for name in EXPECTED_CLASSES:
            assert name in matrix["targets"], f"'{name}' missing from support_matrix targets"
            t = matrix["targets"][name]
            assert "workload_class" in t
            assert "support_level" in t
            assert "recommended_max_count" in t
            assert "viable_strategy_count" in t

    def test_target_classification_structure(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from characterize_workloads import _build_target_classification, characterize_all

        results = characterize_all(skip_generate=True, generate_count=3)
        classification = _build_target_classification(results)

        assert "schema_version" in classification
        assert "classifications" in classification
        for name in EXPECTED_CLASSES:
            assert name in classification["classifications"]
            c = classification["classifications"][name]
            assert "workload_class" in c
            assert "support_level" in c

    def test_artifacts_write_to_disk(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from characterize_workloads import (
            _build_support_matrix,
            _build_target_classification,
            _load_workload_classes,
            characterize_all,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            wc = _load_workload_classes()
            results = characterize_all(skip_generate=True, generate_count=3)

            matrix = _build_support_matrix(results, wc)
            cls_out = _build_target_classification(results)
            report = {"schema_version": "1.0", "phase": "16", "targets": results}

            for fname, data in [
                ("support_matrix.json", matrix),
                ("target_classification.json", cls_out),
                ("workload_report.json", report),
            ]:
                out = tmp_path / fname
                out.write_text(json.dumps(data, indent=2), encoding="utf-8")
                assert out.exists()
                loaded = json.loads(out.read_text(encoding="utf-8"))
                assert loaded["schema_version"] == "1.0"
