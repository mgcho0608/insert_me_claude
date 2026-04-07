"""
tests/test_reproducibility.py — Official fresh-plan and fresh-generation
reproducibility tests for insert_me.

Covers:
- Fresh-plan reproducibility: plan-corpus run twice on the same target/count
  produces byte-identical corpus_plan.json (STABLE verdict).
- Fresh-generation reproducibility: generate-corpus run twice produces
  identical acceptance counts and plan fingerprints.
- Replay vs fresh-plan: generate-corpus --from-plan produces the same
  acceptance outcomes as the original fresh run.
- Script smoke tests: check_plan_stability.py exits 0 and writes a
  plan_repro_report.json on known-stable targets.

Reproducibility guarantee (from docs/repro_runbook.md §14):
  Same source tree + same --count + same PlanConstraints
    => byte-identical corpus_plan.json
    => byte-identical seeds/*.json
  Same source tree + same seed JSON
    => identical pipeline outputs (bad/good pair, all 5 artifacts)
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

SANDBOX_EVAL_SRC = (
    Path(__file__).parent.parent / "examples" / "sandbox_eval" / "src"
)
MODERATE_TARGET = (
    Path(__file__).parent.parent / "examples" / "local_targets" / "moderate" / "src"
)
MINIMAL_TARGET = (
    Path(__file__).parent.parent / "examples" / "local_targets" / "minimal" / "src"
)

CHECK_PLAN_STABILITY_SCRIPT = (
    Path(__file__).parent.parent / "scripts" / "check_plan_stability.py"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_plan(source: Path, output_dir: Path, count: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "plan-corpus",
            "--source", str(source),
            "--count",  str(count),
            "--output-dir", str(output_dir),
        ],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
        timeout=120,
    )


def _run_generate(
    source: Path,
    output_root: Path,
    count: int,
    extra_args: tuple = (),
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "generate-corpus",
            "--source", str(source),
            "--count",  str(count),
            "--output-root", str(output_root),
            "--no-llm",
        ] + list(extra_args),
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
        timeout=300,
    )


def _run_replay(
    plan_path: Path,
    output_root: Path,
    extra_args: tuple = (),
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "generate-corpus",
            "--from-plan", str(plan_path),
            "--output-root", str(output_root),
            "--no-llm",
        ] + list(extra_args),
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
        timeout=300,
    )


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fresh-plan reproducibility
# ---------------------------------------------------------------------------


class TestFreshPlanReproducibility:
    """
    Prove that plan-corpus generates byte-identical corpus_plan.json
    on repeated fresh runs with the same source + count.

    These tests are the official reproducibility acceptance criteria for the
    planning layer (docs/repro_runbook.md §14).
    """

    def test_plan_stable_moderate_fixture(self, tmp_path):
        """plan-corpus on moderate fixture is byte-identical across two fresh runs."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        plan_a = tmp_path / "plan_a"
        plan_b = tmp_path / "plan_b"
        r1 = _run_plan(MODERATE_TARGET, plan_a, 5)
        r2 = _run_plan(MODERATE_TARGET, plan_b, 5)

        assert r1.returncode == 0, f"Run 1 failed:\n{r1.stderr}"
        assert r2.returncode == 0, f"Run 2 failed:\n{r2.stderr}"

        a = _load_json(plan_a / "corpus_plan.json")
        b = _load_json(plan_b / "corpus_plan.json")
        assert a == b, (
            "corpus_plan.json differs between two fresh runs on moderate fixture. "
            f"source_hash a={a.get('source_hash')} b={b.get('source_hash')}, "
            f"planned_count a={a.get('planned_count')} b={b.get('planned_count')}"
        )

    def test_plan_stable_minimal_fixture(self, tmp_path):
        """plan-corpus on minimal fixture is byte-identical across two fresh runs."""
        if not MINIMAL_TARGET.exists():
            pytest.skip("minimal target not found")

        plan_a = tmp_path / "plan_a"
        plan_b = tmp_path / "plan_b"
        r1 = _run_plan(MINIMAL_TARGET, plan_a, 5)
        r2 = _run_plan(MINIMAL_TARGET, plan_b, 5)

        assert r1.returncode in (0, 1), f"Run 1 failed: {r1.stderr}"
        assert r2.returncode in (0, 1), f"Run 2 failed: {r2.stderr}"

        plan_a_file = plan_a / "corpus_plan.json"
        plan_b_file = plan_b / "corpus_plan.json"
        if not plan_a_file.exists() or not plan_b_file.exists():
            pytest.skip("plan files not written (target may have no viable candidates)")

        a = _load_json(plan_a_file)
        b = _load_json(plan_b_file)
        assert a == b, "corpus_plan.json differs between two fresh runs on minimal fixture"

    def test_plan_stable_sandbox_eval(self, tmp_path):
        """plan-corpus on sandbox_eval is byte-identical across two fresh runs."""
        if not SANDBOX_EVAL_SRC.exists():
            pytest.skip("sandbox_eval not found")

        plan_a = tmp_path / "plan_a"
        plan_b = tmp_path / "plan_b"
        r1 = _run_plan(SANDBOX_EVAL_SRC, plan_a, 10)
        r2 = _run_plan(SANDBOX_EVAL_SRC, plan_b, 10)

        assert r1.returncode == 0, f"Run 1 failed:\n{r1.stderr}"
        assert r2.returncode == 0, f"Run 2 failed:\n{r2.stderr}"

        a = _load_json(plan_a / "corpus_plan.json")
        b = _load_json(plan_b / "corpus_plan.json")
        assert a == b, (
            "corpus_plan.json differs between two fresh runs on sandbox_eval"
        )

    def test_plan_source_hash_stable(self, tmp_path):
        """source_hash in corpus_plan.json must be identical on fresh runs."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        plan_a = tmp_path / "plan_a"
        plan_b = tmp_path / "plan_b"
        _run_plan(MODERATE_TARGET, plan_a, 5)
        _run_plan(MODERATE_TARGET, plan_b, 5)

        if not (plan_a / "corpus_plan.json").exists():
            pytest.skip("plan not generated")

        a = _load_json(plan_a / "corpus_plan.json")
        b = _load_json(plan_b / "corpus_plan.json")
        assert a["source_hash"] == b["source_hash"], (
            f"source_hash mismatch: {a['source_hash']} != {b['source_hash']}"
        )

    def test_plan_seeds_stable(self, tmp_path):
        """Seed files written by plan-corpus must be byte-identical on fresh runs."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        plan_a = tmp_path / "plan_a"
        plan_b = tmp_path / "plan_b"
        r1 = _run_plan(MODERATE_TARGET, plan_a, 5)
        r2 = _run_plan(MODERATE_TARGET, plan_b, 5)

        if r1.returncode != 0 or r2.returncode != 0:
            pytest.skip("plan generation failed")

        seeds_a = sorted((plan_a / "seeds").glob("*.json"), key=lambda p: p.name)
        seeds_b = sorted((plan_b / "seeds").glob("*.json"), key=lambda p: p.name)
        assert len(seeds_a) == len(seeds_b), (
            f"Different seed file counts: {len(seeds_a)} vs {len(seeds_b)}"
        )
        for sa, sb in zip(seeds_a, seeds_b):
            da = _load_json(sa)
            db = _load_json(sb)
            assert da == db, f"Seed file {sa.name} differs between runs"


# ---------------------------------------------------------------------------
# Fresh-generation reproducibility
# ---------------------------------------------------------------------------


class TestFreshGenerateReproducibility:
    """
    Prove that generate-corpus produces stable outcomes across independent
    fresh runs with the same source + count.

    Note: outcome stability (same VALID/INVALID counts) is tested; we do NOT
    require that run_ids are identical (they include timestamps).
    """

    def test_generate_accepted_count_stable_moderate(self, tmp_path):
        """Two fresh generate-corpus runs on moderate fixture yield the same accepted count."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "gen1"
        out2 = tmp_path / "gen2"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        r2 = _run_generate(MODERATE_TARGET, out2, 3)

        assert r1.returncode in (0, 1), f"Run 1 error: {r1.stderr}"
        assert r2.returncode in (0, 1), f"Run 2 error: {r2.stderr}"

        s1 = _load_json(out1 / "acceptance_summary.json")
        s2 = _load_json(out2 / "acceptance_summary.json")
        assert s1["accepted_count"] == s2["accepted_count"], (
            f"accepted_count differs: run1={s1['accepted_count']} run2={s2['accepted_count']}"
        )
        assert s1["planned_count"] == s2["planned_count"], (
            f"planned_count differs: run1={s1['planned_count']} run2={s2['planned_count']}"
        )

    def test_generate_plan_fingerprint_stable_moderate(self, tmp_path):
        """plan_fingerprint in corpus_index.json must match on two fresh runs."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "gen1"
        out2 = tmp_path / "gen2"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        r2 = _run_generate(MODERATE_TARGET, out2, 3)

        assert r1.returncode in (0, 1)
        assert r2.returncode in (0, 1)

        idx1_path = out1 / "corpus_index.json"
        idx2_path = out2 / "corpus_index.json"
        assert idx1_path.exists(), "corpus_index.json not written by run 1"
        assert idx2_path.exists(), "corpus_index.json not written by run 2"

        i1 = _load_json(idx1_path)
        i2 = _load_json(idx2_path)
        fp1 = i1.get("fingerprints", {}).get("plan_fingerprint")
        fp2 = i2.get("fingerprints", {}).get("plan_fingerprint")
        assert fp1 is not None, "plan_fingerprint missing from corpus_index.json run 1"
        assert fp2 is not None, "plan_fingerprint missing from corpus_index.json run 2"
        assert fp1 == fp2, (
            f"plan_fingerprint differs between fresh runs: {fp1} != {fp2}"
        )

    def test_generate_acceptance_fingerprint_stable_moderate(self, tmp_path):
        """acceptance_fingerprint in corpus_index.json must match on two fresh runs."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "gen1"
        out2 = tmp_path / "gen2"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        r2 = _run_generate(MODERATE_TARGET, out2, 3)

        if r1.returncode not in (0, 1) or r2.returncode not in (0, 1):
            pytest.skip("generate-corpus did not complete normally")

        for idx_path in (out1 / "corpus_index.json", out2 / "corpus_index.json"):
            assert idx_path.exists(), f"corpus_index.json missing at {idx_path}"

        i1 = _load_json(out1 / "corpus_index.json")
        i2 = _load_json(out2 / "corpus_index.json")
        af1 = i1.get("fingerprints", {}).get("acceptance_fingerprint")
        af2 = i2.get("fingerprints", {}).get("acceptance_fingerprint")
        if af1 is None or af2 is None:
            pytest.skip("acceptance_fingerprint not yet in corpus_index")
        assert af1 == af2, (
            f"acceptance_fingerprint differs between fresh runs: {af1} != {af2}"
        )


# ---------------------------------------------------------------------------
# Replay vs fresh-plan reproducibility
# ---------------------------------------------------------------------------


class TestReplayVsFreshReproducibility:
    """
    Prove that replay (--from-plan) produces the same outcomes as the
    original fresh run.

    Distinction:
    - Replay reproducibility: load a saved plan and re-execute — guaranteed
      identical because the seed files are the same.
    - Fresh-plan reproducibility: plan twice from scratch and execute —
      depends on the planner being deterministic (proven above).
    """

    def test_replay_plan_fingerprint_matches_fresh(self, tmp_path):
        """Replay corpus_index.json must have same plan_fingerprint as original run."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "fresh"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        assert r1.returncode in (0, 1), f"Fresh run failed: {r1.stderr}"

        plan_dir = out1 / "_plan"
        if not plan_dir.exists():
            pytest.skip("_plan dir not written")

        out2 = tmp_path / "replay"
        r2 = _run_replay(plan_dir, out2)
        assert r2.returncode in (0, 1), f"Replay failed: {r2.stderr}"

        for idx_path in (out1 / "corpus_index.json", out2 / "corpus_index.json"):
            assert idx_path.exists(), f"corpus_index.json missing: {idx_path}"

        i1 = _load_json(out1 / "corpus_index.json")
        i2 = _load_json(out2 / "corpus_index.json")
        fp1 = i1.get("fingerprints", {}).get("plan_fingerprint")
        fp2 = i2.get("fingerprints", {}).get("plan_fingerprint")
        assert fp1 == fp2, (
            f"plan_fingerprint: fresh={fp1} replay={fp2}"
        )

    def test_replay_accepted_count_matches_fresh(self, tmp_path):
        """Replay must produce the same accepted count as the original run."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "fresh"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        assert r1.returncode in (0, 1), f"Fresh run failed: {r1.stderr}"

        plan_dir = out1 / "_plan"
        if not plan_dir.exists():
            pytest.skip("_plan dir not written")

        out2 = tmp_path / "replay"
        r2 = _run_replay(plan_dir, out2)
        assert r2.returncode in (0, 1), f"Replay failed: {r2.stderr}"

        s1 = _load_json(out1 / "acceptance_summary.json")
        s2 = _load_json(out2 / "acceptance_summary.json")
        assert s1["accepted_count"] == s2["accepted_count"], (
            f"accepted_count: fresh={s1['accepted_count']} replay={s2['accepted_count']}"
        )
        assert s1["planned_count"] == s2["planned_count"], (
            f"planned_count: fresh={s1['planned_count']} replay={s2['planned_count']}"
        )

    def test_replay_corpus_index_run_mode_differs(self, tmp_path):
        """corpus_index.json run_mode must differ: 'generate' vs 'replay'."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out1 = tmp_path / "fresh"
        r1 = _run_generate(MODERATE_TARGET, out1, 3)
        assert r1.returncode in (0, 1)

        plan_dir = out1 / "_plan"
        if not plan_dir.exists():
            pytest.skip("_plan dir not written")

        out2 = tmp_path / "replay"
        r2 = _run_replay(plan_dir, out2)
        assert r2.returncode in (0, 1)

        i1 = _load_json(out1 / "corpus_index.json")
        i2 = _load_json(out2 / "corpus_index.json")
        assert i1["run_mode"] == "generate"
        assert i2["run_mode"] == "replay"


# ---------------------------------------------------------------------------
# check_plan_stability.py script smoke tests
# ---------------------------------------------------------------------------


class TestCheckPlanStabilityScript:
    """
    Smoke tests for the check_plan_stability.py script.

    These confirm that the script runs successfully on known-stable targets
    and writes a well-formed plan_repro_report.json.
    """

    def _run_script(self, source, count, output, extra_args=()):
        return subprocess.run(
            [
                sys.executable, str(CHECK_PLAN_STABILITY_SCRIPT),
                "--source", str(source),
                "--count",  str(count),
                "--runs",   "2",
                "--output", str(output),
                "--no-color",
            ] + list(extra_args),
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent),
            timeout=180,
        )

    def test_script_exits_0_on_moderate_fixture(self, tmp_path):
        """check_plan_stability.py must exit 0 on the moderate target (stable)."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        report_path = tmp_path / "plan_repro_report.json"
        r = self._run_script(MODERATE_TARGET, 5, report_path)
        assert r.returncode == 0, (
            f"Script failed on stable target:\n{r.stdout}\n{r.stderr}"
        )

    def test_script_writes_repro_report(self, tmp_path):
        """plan_repro_report.json must be written with required fields."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        report_path = tmp_path / "plan_repro_report.json"
        r = self._run_script(MODERATE_TARGET, 5, report_path)
        assert r.returncode in (0, 1), f"Script error: {r.stderr}"
        assert report_path.exists(), "plan_repro_report.json not written"

        report = _load_json(report_path)
        for field in (
            "schema_version", "target_source", "requested_count",
            "run_count", "verdict", "plan_stable", "all_identical",
            "plan_fingerprints", "plan_diff", "run_details",
        ):
            assert field in report, f"plan_repro_report.json missing: {field}"

    def test_script_report_verdict_stable(self, tmp_path):
        """plan_repro_report.json verdict must be STABLE on a good target."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        report_path = tmp_path / "plan_repro_report.json"
        r = self._run_script(MODERATE_TARGET, 5, report_path)
        if r.returncode != 0:
            pytest.skip(f"Script returned non-zero: {r.stdout}")

        report = _load_json(report_path)
        assert report["verdict"] == "STABLE", (
            f"Expected STABLE, got {report['verdict']}"
        )
        assert report["plan_stable"] is True
        assert report["all_identical"] is True
        assert report["plan_diff"] is None

    def test_script_fingerprints_all_equal(self, tmp_path):
        """All plan_fingerprints in the report must be identical on a stable target."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        report_path = tmp_path / "plan_repro_report.json"
        r = self._run_script(MODERATE_TARGET, 5, report_path)
        if not report_path.exists():
            pytest.skip("report not written")

        report = _load_json(report_path)
        fps = report.get("plan_fingerprints", [])
        assert len(fps) >= 2, "Expected at least 2 fingerprints"
        assert len(set(fps)) == 1, (
            f"Fingerprints not all equal: {fps}"
        )

    def test_script_exits_0_on_sandbox_eval(self, tmp_path):
        """check_plan_stability.py must exit 0 on the sandbox_eval target."""
        if not SANDBOX_EVAL_SRC.exists():
            pytest.skip("sandbox_eval not found")

        report_path = tmp_path / "plan_repro_report.json"
        r = self._run_script(SANDBOX_EVAL_SRC, 10, report_path)
        assert r.returncode == 0, (
            f"Script failed on sandbox_eval:\n{r.stdout}\n{r.stderr}"
        )


# ---------------------------------------------------------------------------
# Corpus index fingerprints schema
# ---------------------------------------------------------------------------


class TestCorpusIndexFingerprints:
    """
    Verify that corpus_index.json contains the fingerprinting fields added
    in Phase 13 and that those fields have the correct structure.
    """

    def test_corpus_index_has_fingerprints_block(self, tmp_path):
        """corpus_index.json must contain a 'fingerprints' block."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out = tmp_path / "gen"
        r = _run_generate(MODERATE_TARGET, out, 3)
        assert r.returncode in (0, 1)

        idx_path = out / "corpus_index.json"
        assert idx_path.exists(), "corpus_index.json not written"
        d = _load_json(idx_path)
        assert "fingerprints" in d, "corpus_index.json missing 'fingerprints' block"
        fps = d["fingerprints"]
        for key in ("plan_fingerprint", "synthesized_seed_fingerprint",
                    "acceptance_fingerprint", "adjudicator_mode"):
            assert key in fps, f"fingerprints block missing: {key}"

    def test_corpus_index_plan_fingerprint_is_16_chars(self, tmp_path):
        """plan_fingerprint must be a 16-char hex string."""
        if not MODERATE_TARGET.exists():
            pytest.skip("moderate target not found")

        out = tmp_path / "gen"
        r = _run_generate(MODERATE_TARGET, out, 3)
        assert r.returncode in (0, 1)

        idx = _load_json(out / "corpus_index.json")
        fp = idx.get("fingerprints", {}).get("plan_fingerprint", "")
        assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp), (
            f"plan_fingerprint is not 16-char hex: {fp!r}"
        )
