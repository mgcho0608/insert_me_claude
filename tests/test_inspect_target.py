"""
Tests for insert-me inspect-target CLI subcommand and supporting logic.

Verifies that:
- inspect-target works when --source points to a non-bundled local fixture
- The preflight inspection returns correct suitability signals
- A small pilot run works end-to-end on the local fixture
- The workflow fails clearly when the target is unsuitable
- The --output flag writes target_suitability.json
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LOCAL_TARGET_DIR = FIXTURES_DIR / "local_target"
DEMO_SRC_DIR = FIXTURES_DIR / "c_src"
SANDBOX_SRC = Path(__file__).parent.parent / "examples" / "sandbox_eval" / "src"
SEEDS_DIR = Path(__file__).parent.parent / "examples" / "seeds" / "sandbox"


# ---------------------------------------------------------------------------
# Unit tests: _inspect_source_tree
# ---------------------------------------------------------------------------

class TestInspectSourceTree:

    def test_local_target_fixture_found(self):
        """Inspect the non-bundled local_target fixture — files are detected."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        assert report["file_count"] == 2
        assert "toy_heap.c" in report["files"] or any("toy_heap.c" in f for f in report["files"])

    def test_local_target_has_candidates(self):
        """Local fixture has candidates for all four corpus-admitted strategies."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        strats = report["candidates_by_strategy"]
        for name in ("alloc_size_undercount", "insert_premature_free",
                      "insert_double_free", "remove_free_call"):
            assert strats[name]["total"] > 0, f"{name} should have candidates in local fixture"

    def test_local_target_pilot_single_yes(self):
        """Local fixture passes pilot_single_case."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        assert report["suitability"]["pilot_single_case"] is True

    def test_local_target_pilot_batch_yes(self):
        """Local fixture passes pilot_small_batch (enough candidates per strategy)."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        assert report["suitability"]["pilot_small_batch"] is True

    def test_local_target_corpus_no_two_files(self):
        """Local fixture does NOT qualify for corpus generation (only 2 files)."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        # Only 2 files — corpus_generation needs >= 3
        assert report["suitability"]["corpus_generation"] is False

    def test_local_target_no_blockers(self):
        """Local fixture has no blockers."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        assert report["suitability"]["blockers"] == []

    def test_local_target_experimental_strategy_present(self):
        """remove_null_guard (experimental) is reported but has no corpus note conflict."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        rng = report["candidates_by_strategy"]["remove_null_guard"]
        assert "note" in rng, "experimental strategy should carry a note"
        assert rng["cwe"] == "CWE-476"

    def test_sandbox_src_corpus_ready(self):
        """The bundled sandbox_eval/src qualifies for corpus_generation."""
        if not SANDBOX_SRC.exists():
            pytest.skip("bundled sandbox not present")
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(SANDBOX_SRC)
        assert report["suitability"]["corpus_generation"] is True

    def test_empty_directory_blocker(self, tmp_path):
        """An empty directory produces a blocker."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(tmp_path)
        assert report["file_count"] == 0
        assert report["suitability"]["pilot_single_case"] is False
        assert len(report["suitability"]["blockers"]) > 0

    def test_directory_with_no_c_files_blocker(self, tmp_path):
        """A directory with only .py files produces a blocker."""
        (tmp_path / "helper.py").write_text("x = 1\n")
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(tmp_path)
        assert report["file_count"] == 0
        assert len(report["suitability"]["blockers"]) > 0

    def test_schema_version_present(self):
        """Report includes schema_version field."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        assert report["schema_version"] == "1.0"

    def test_concentration_risk_structure(self):
        """Concentration risk dict is present for all tracked pattern types."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        for pt in ("malloc_call", "pointer_deref", "free_call", "null_guard"):
            assert pt in report["concentration_risk"]
            c = report["concentration_risk"][pt]
            assert "fraction" in c
            assert 0.0 <= c["fraction"] <= 1.0

    def test_by_file_sums_to_total(self):
        """by_file counts sum to the total for each strategy."""
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        for name, info in report["candidates_by_strategy"].items():
            assert sum(info["by_file"].values()) == info["total"], (
                f"{name}: by_file sum != total"
            )


# ---------------------------------------------------------------------------
# Unit tests: _format_inspection_report
# ---------------------------------------------------------------------------

class TestFormatInspectionReport:

    def test_output_contains_file_count(self):
        from insert_me.cli import _inspect_source_tree, _format_inspection_report
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        text = _format_inspection_report(report)
        assert "Source files found: 2" in text

    def test_output_contains_suitability_lines(self):
        from insert_me.cli import _inspect_source_tree, _format_inspection_report
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        text = _format_inspection_report(report)
        assert "pilot_single_case" in text
        assert "pilot_small_batch" in text
        assert "corpus_generation" in text

    def test_output_contains_concentration_section(self):
        from insert_me.cli import _inspect_source_tree, _format_inspection_report
        report = _inspect_source_tree(LOCAL_TARGET_DIR)
        text = _format_inspection_report(report)
        assert "Concentration risk" in text

    def test_empty_dir_shows_blocker(self, tmp_path):
        from insert_me.cli import _inspect_source_tree, _format_inspection_report
        report = _inspect_source_tree(tmp_path)
        text = _format_inspection_report(report)
        assert "BLOCKER" in text or "blocker" in text.lower()


# ---------------------------------------------------------------------------
# CLI integration tests (subprocess)
# ---------------------------------------------------------------------------

class TestInspectTargetCLI:

    def _run(self, *extra_args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "inspect-target"] + list(extra_args),
            capture_output=True,
            text=True,
        )

    def test_local_fixture_exits_zero(self):
        """Local target with usable candidates exits 0."""
        result = self._run("--source", str(LOCAL_TARGET_DIR))
        assert result.returncode == 0, result.stderr

    def test_local_fixture_output_contains_files(self):
        result = self._run("--source", str(LOCAL_TARGET_DIR))
        assert "toy_heap.c" in result.stdout
        assert "toy_list.c" in result.stdout

    def test_local_fixture_output_contains_strategies(self):
        result = self._run("--source", str(LOCAL_TARGET_DIR))
        assert "alloc_size_undercount" in result.stdout
        assert "insert_premature_free" in result.stdout

    def test_empty_dir_exits_nonzero(self, tmp_path):
        """Empty directory exits 1 (has blockers)."""
        result = self._run("--source", str(tmp_path))
        assert result.returncode == 1

    def test_nonexistent_source_exits_nonzero(self, tmp_path):
        result = self._run("--source", str(tmp_path / "does_not_exist"))
        assert result.returncode == 1

    def test_output_flag_writes_json(self, tmp_path):
        """--output flag creates target_suitability.json."""
        result = self._run("--source", str(LOCAL_TARGET_DIR), "--output", str(tmp_path))
        assert result.returncode == 0, result.stderr
        out_file = tmp_path / "target_suitability.json"
        assert out_file.exists(), "target_suitability.json should be written"
        data = json.loads(out_file.read_text())
        assert data["schema_version"] == "1.0"
        assert data["file_count"] == 2

    def test_output_json_is_valid(self, tmp_path):
        """target_suitability.json has the expected top-level keys."""
        self._run("--source", str(LOCAL_TARGET_DIR), "--output", str(tmp_path))
        data = json.loads((tmp_path / "target_suitability.json").read_text())
        for key in ("source_root", "file_count", "files", "candidates_by_strategy",
                    "concentration_risk", "suitability"):
            assert key in data, f"Missing key: {key}"

    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "inspect-target", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "inspect" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Pilot run tests: local fixture is usable end-to-end
# ---------------------------------------------------------------------------

class TestLocalTargetPilotRun:
    """Prove that a full pipeline run works on the non-bundled local fixture."""

    # Pick a seed file that uses pointer_deref (insert_premature_free).
    # Uses the simplest available corpus seed.
    _SEED_FILE = SEEDS_DIR / "cwe416_sb_001.json"

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if not self._SEED_FILE.exists():
            pytest.skip("sandbox seed file not present")

    def _run_pipeline(self, tmp_path: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", str(self._SEED_FILE),
                "--source", str(LOCAL_TARGET_DIR),
                "--output", str(tmp_path),
            ],
            capture_output=True,
            text=True,
        )

    def test_pipeline_exits_zero_on_local_fixture(self, tmp_path):
        """Pipeline runs successfully on the local fixture."""
        result = self._run_pipeline(tmp_path)
        assert result.returncode == 0, (
            f"Pipeline failed on local fixture.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_bundle_artifacts_created(self, tmp_path):
        """All expected artifacts are written for a local fixture run."""
        self._run_pipeline(tmp_path)
        bundle_dirs = list(tmp_path.iterdir())
        assert len(bundle_dirs) >= 1, "No bundle directory created"
        bundle = bundle_dirs[0]
        for artifact in ("patch_plan.json", "audit_result.json",
                          "ground_truth.json", "audit.json", "validation_result.json"):
            assert (bundle / artifact).exists(), f"Missing artifact: {artifact}"

    def test_audit_result_is_valid_or_noop(self, tmp_path):
        """Audit result is VALID (mutation applied) or NOOP (no compatible target)."""
        self._run_pipeline(tmp_path)
        bundle = list(tmp_path.iterdir())[0]
        ar = json.loads((bundle / "audit_result.json").read_text())
        assert ar["classification"] in ("VALID", "NOOP"), (
            f"Unexpected classification: {ar['classification']}"
        )

    def test_validate_bundle_passes_on_local_fixture(self, tmp_path):
        """insert-me validate-bundle exits 0 for a local-fixture bundle."""
        self._run_pipeline(tmp_path)
        bundle = list(tmp_path.iterdir())[0]
        result = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"validate-bundle failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Negative path: unsuitable local target
# ---------------------------------------------------------------------------

class TestUnsuitableLocalTarget:

    def test_python_only_dir_is_not_suitable(self, tmp_path):
        """A Python-only directory is reported as unsuitable."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        from insert_me.cli import _inspect_source_tree
        report = _inspect_source_tree(tmp_path)
        assert report["suitability"]["pilot_single_case"] is False
        assert len(report["suitability"]["blockers"]) > 0

    def test_pipeline_on_empty_dir_produces_noop(self, tmp_path):
        """Pipeline run on an empty directory produces NOOP (no candidates)."""
        seed = Path(__file__).parent.parent / "examples" / "seeds" / "cwe122_heap_overflow.json"
        if not seed.exists():
            pytest.skip("demo seed not found")
        src_dir = tmp_path / "empty_src"
        src_dir.mkdir()
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli",
                "run",
                "--seed-file", str(seed),
                "--source", str(src_dir),
                "--output", str(tmp_path / "out"),
            ],
            capture_output=True,
            text=True,
        )
        # Pipeline exits 0 even with NOOP (no match is not an error)
        assert result.returncode == 0, result.stderr
        bundle = list((tmp_path / "out").iterdir())[0]
        ar = json.loads((bundle / "audit_result.json").read_text())
        assert ar["classification"] == "NOOP"
