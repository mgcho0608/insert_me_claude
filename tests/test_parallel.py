"""
Sequential vs parallel execution parity tests for insert_me.

These tests prove that ``generate-corpus`` and ``generate-portfolio`` produce
artifact-equivalent output regardless of whether ``--jobs 1`` (sequential) or
``--jobs 2`` (parallel) is used.

What is checked
---------------
* ``accepted_count`` and ``rejected_count`` in acceptance_summary.json are
  identical between sequential and parallel runs.
* ``acceptance_fingerprint`` in corpus_index.json / portfolio_index.json is
  identical (the fingerprint is computed over sorted accepted case IDs, so it
  is execution-order independent by construction).
* Replay from a saved plan behaves the same under sequential and parallel
  execution (same acceptance fingerprint as the fresh run).

What is NOT checked
-------------------
* Wall-clock timing (not deterministic and not the concern of parity tests).
* Bundle directory ordering on disk (non-canonical, irrelevant to correctness).
* Console print order (parallel mode prints results in canonical order, but the
  interleaved progress lines differ intentionally).

Fixture choice
--------------
``examples/local_targets/moderate/src`` is a small-class target (~339 LOC,
4 files) that runs in under 200ms/case. ``count=3`` keeps the test fast while
exercising the multi-case path.

``examples/targets/sandbox_targets.json`` has two small targets and is used
for portfolio parity tests with ``count=4``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

MODERATE_SOURCE   = REPO_ROOT / "examples" / "local_targets" / "moderate" / "src"
SANDBOX_TARGETS   = REPO_ROOT / "examples" / "targets" / "sandbox_targets.json"

CORPUS_COUNT      = 3   # small enough to be fast; large enough to exercise multi-case path
PORTFOLIO_COUNT   = 4   # gives 2 cases per target in the two-target portfolio


def _run_cli(*args: str) -> tuple[int, str, str]:
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _acceptance_summary(output_root: Path) -> dict:
    p = output_root / "acceptance_summary.json"
    assert p.exists(), f"acceptance_summary.json not found in {output_root}"
    return json.loads(p.read_text(encoding="utf-8"))


def _corpus_index(output_root: Path) -> dict:
    p = output_root / "corpus_index.json"
    assert p.exists(), f"corpus_index.json not found in {output_root}"
    return json.loads(p.read_text(encoding="utf-8"))


def _portfolio_acceptance_summary(output_root: Path) -> dict:
    p = output_root / "portfolio_acceptance_summary.json"
    assert p.exists(), f"portfolio_acceptance_summary.json not found in {output_root}"
    return json.loads(p.read_text(encoding="utf-8"))


def _portfolio_index(output_root: Path) -> dict:
    p = output_root / "portfolio_index.json"
    assert p.exists(), f"portfolio_index.json not found in {output_root}"
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. generate-corpus: sequential vs parallel parity
# ---------------------------------------------------------------------------

class TestCorpusParallelParity:
    """generate-corpus --jobs 1 and --jobs 2 must produce identical artifacts."""

    @pytest.fixture(autouse=True)
    def _require_fixture(self) -> None:
        if not MODERATE_SOURCE.exists():
            pytest.skip(f"fixture not found: {MODERATE_SOURCE}")

    def test_seq_par_acceptance_counts_match(self, tmp_path: Path) -> None:
        seq_out = tmp_path / "seq"
        par_out = tmp_path / "par"

        rc_seq, _, err_seq = _run_cli(
            "generate-corpus",
            "--source", str(MODERATE_SOURCE),
            "--count", str(CORPUS_COUNT),
            "--output-root", str(seq_out),
            "--jobs", "1",
        )
        assert rc_seq == 0, f"sequential run failed:\n{err_seq}"

        rc_par, _, err_par = _run_cli(
            "generate-corpus",
            "--source", str(MODERATE_SOURCE),
            "--count", str(CORPUS_COUNT),
            "--output-root", str(par_out),
            "--jobs", "2",
        )
        assert rc_par == 0, f"parallel run failed:\n{err_par}"

        seq_summary = _acceptance_summary(seq_out)
        par_summary = _acceptance_summary(par_out)

        assert seq_summary["accepted_count"] == par_summary["accepted_count"], (
            f"accepted_count differs: seq={seq_summary['accepted_count']} "
            f"par={par_summary['accepted_count']}"
        )
        assert seq_summary["rejected_count"] == par_summary["rejected_count"], (
            f"rejected_count differs: seq={seq_summary['rejected_count']} "
            f"par={par_summary['rejected_count']}"
        )
        assert seq_summary["planned_count"] == par_summary["planned_count"]

    def test_seq_par_acceptance_fingerprint_matches(self, tmp_path: Path) -> None:
        seq_out = tmp_path / "seq"
        par_out = tmp_path / "par"

        _run_cli(
            "generate-corpus",
            "--source", str(MODERATE_SOURCE),
            "--count", str(CORPUS_COUNT),
            "--output-root", str(seq_out),
            "--jobs", "1",
        )
        _run_cli(
            "generate-corpus",
            "--source", str(MODERATE_SOURCE),
            "--count", str(CORPUS_COUNT),
            "--output-root", str(par_out),
            "--jobs", "2",
        )

        seq_idx = _corpus_index(seq_out)
        par_idx = _corpus_index(par_out)

        seq_fp = seq_idx.get("fingerprints", {}).get("acceptance_fingerprint")
        par_fp = par_idx.get("fingerprints", {}).get("acceptance_fingerprint")

        assert seq_fp is not None, "sequential corpus_index missing acceptance_fingerprint"
        assert par_fp is not None, "parallel corpus_index missing acceptance_fingerprint"
        assert seq_fp == par_fp, (
            f"acceptance_fingerprint differs between sequential and parallel runs: "
            f"seq={seq_fp!r}  par={par_fp!r}"
        )

    def test_replay_parallel_matches_fresh_sequential(self, tmp_path: Path) -> None:
        """Replay (--from-plan) with parallel execution matches fresh sequential run."""
        fresh_out  = tmp_path / "fresh"
        replay_out = tmp_path / "replay"

        # Fresh sequential run
        rc, _, err = _run_cli(
            "generate-corpus",
            "--source", str(MODERATE_SOURCE),
            "--count", str(CORPUS_COUNT),
            "--output-root", str(fresh_out),
            "--jobs", "1",
        )
        assert rc == 0, f"fresh run failed:\n{err}"

        plan_dir = fresh_out / "_plan"
        assert plan_dir.exists()

        # Replay with parallel execution
        rc, _, err = _run_cli(
            "generate-corpus",
            "--from-plan", str(plan_dir),
            "--output-root", str(replay_out),
            "--jobs", "2",
        )
        assert rc == 0, f"parallel replay failed:\n{err}"

        fresh_idx  = _corpus_index(fresh_out)
        replay_idx = _corpus_index(replay_out)

        fresh_fp  = fresh_idx.get("fingerprints", {}).get("acceptance_fingerprint")
        replay_fp = replay_idx.get("fingerprints", {}).get("acceptance_fingerprint")

        assert fresh_fp == replay_fp, (
            f"acceptance_fingerprint differs between fresh (seq) and replay (par): "
            f"fresh={fresh_fp!r}  replay={replay_fp!r}"
        )


# ---------------------------------------------------------------------------
# 2. generate-portfolio: sequential vs parallel parity
# ---------------------------------------------------------------------------

class TestPortfolioParallelParity:
    """generate-portfolio --jobs 1 and --jobs 2 must produce identical artifacts."""

    @pytest.fixture(autouse=True)
    def _require_fixture(self) -> None:
        if not SANDBOX_TARGETS.exists():
            pytest.skip(f"fixture not found: {SANDBOX_TARGETS}")

    def test_seq_par_portfolio_acceptance_counts_match(self, tmp_path: Path) -> None:
        seq_out = tmp_path / "seq"
        par_out = tmp_path / "par"

        rc_seq, _, err_seq = _run_cli(
            "generate-portfolio",
            "--targets-file", str(SANDBOX_TARGETS),
            "--count", str(PORTFOLIO_COUNT),
            "--output-root", str(seq_out),
            "--jobs", "1",
        )
        assert rc_seq == 0, f"sequential portfolio run failed:\n{err_seq}"

        rc_par, _, err_par = _run_cli(
            "generate-portfolio",
            "--targets-file", str(SANDBOX_TARGETS),
            "--count", str(PORTFOLIO_COUNT),
            "--output-root", str(par_out),
            "--jobs", "2",
        )
        assert rc_par == 0, f"parallel portfolio run failed:\n{err_par}"

        seq_summary = _portfolio_acceptance_summary(seq_out)
        par_summary = _portfolio_acceptance_summary(par_out)

        assert seq_summary["accepted_count"] == par_summary["accepted_count"], (
            f"portfolio accepted_count differs: seq={seq_summary['accepted_count']} "
            f"par={par_summary['accepted_count']}"
        )
        assert seq_summary["rejected_count"] == par_summary["rejected_count"]
        assert seq_summary["planned_count"] == par_summary["planned_count"]

    def test_seq_par_portfolio_fingerprint_matches(self, tmp_path: Path) -> None:
        seq_out = tmp_path / "seq"
        par_out = tmp_path / "par"

        _run_cli(
            "generate-portfolio",
            "--targets-file", str(SANDBOX_TARGETS),
            "--count", str(PORTFOLIO_COUNT),
            "--output-root", str(seq_out),
            "--jobs", "1",
        )
        _run_cli(
            "generate-portfolio",
            "--targets-file", str(SANDBOX_TARGETS),
            "--count", str(PORTFOLIO_COUNT),
            "--output-root", str(par_out),
            "--jobs", "2",
        )

        seq_idx = _portfolio_index(seq_out)
        par_idx = _portfolio_index(par_out)

        seq_fp = seq_idx.get("fingerprints", {}).get("acceptance_fingerprint")
        par_fp = par_idx.get("fingerprints", {}).get("acceptance_fingerprint")

        assert seq_fp is not None, "sequential portfolio_index missing acceptance_fingerprint"
        assert par_fp is not None, "parallel portfolio_index missing acceptance_fingerprint"
        assert seq_fp == par_fp, (
            f"portfolio acceptance_fingerprint differs: seq={seq_fp!r}  par={par_fp!r}"
        )

    def test_portfolio_replay_parallel_matches_fresh_sequential(self, tmp_path: Path) -> None:
        """Portfolio replay (--from-plan) with parallel execution matches fresh sequential."""
        fresh_out  = tmp_path / "fresh"
        replay_out = tmp_path / "replay"

        rc, _, err = _run_cli(
            "generate-portfolio",
            "--targets-file", str(SANDBOX_TARGETS),
            "--count", str(PORTFOLIO_COUNT),
            "--output-root", str(fresh_out),
            "--jobs", "1",
        )
        assert rc == 0, f"fresh portfolio run failed:\n{err}"

        plan_file = fresh_out / "_plan" / "portfolio_plan.json"
        assert plan_file.exists()

        rc, _, err = _run_cli(
            "generate-portfolio",
            "--from-plan", str(plan_file),
            "--output-root", str(replay_out),
            "--jobs", "2",
        )
        assert rc == 0, f"parallel portfolio replay failed:\n{err}"

        fresh_idx  = _portfolio_index(fresh_out)
        replay_idx = _portfolio_index(replay_out)

        fresh_fp  = fresh_idx.get("fingerprints", {}).get("acceptance_fingerprint")
        replay_fp = replay_idx.get("fingerprints", {}).get("acceptance_fingerprint")

        assert fresh_fp == replay_fp, (
            f"portfolio acceptance_fingerprint differs between fresh (seq) and replay (par): "
            f"fresh={fresh_fp!r}  replay={replay_fp!r}"
        )


# ---------------------------------------------------------------------------
# 3. check_portfolio_stability.py import smoke test
# ---------------------------------------------------------------------------

class TestPortfolioStabilityScript:
    """check_portfolio_stability.py must be importable and its helpers must work."""

    def test_script_importable(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_portfolio_stability  # noqa: F401

    def test_portfolio_fingerprint_stable(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from check_portfolio_stability import _portfolio_fingerprint

        plan = {
            "targets_hash": "abc",
            "requested_count": 5,
            "planned_count": 4,
            "entries": [
                {"case_id": "plan_002", "target_name": "t1", "strategy": "s1",
                 "seed_integer": 2, "target_file": "f.c", "target_line": 10},
                {"case_id": "plan_001", "target_name": "t1", "strategy": "s1",
                 "seed_integer": 1, "target_file": "f.c", "target_line": 5},
            ],
        }
        fp1 = _portfolio_fingerprint(plan)
        # Reverse entry order — fingerprint must be identical (entries are sorted)
        plan["entries"] = list(reversed(plan["entries"]))
        fp2 = _portfolio_fingerprint(plan)
        assert fp1 == fp2, "fingerprint must be order-independent"

    def test_acceptance_fingerprint_stable(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from check_portfolio_stability import _acceptance_fingerprint

        summary = {
            "accepted_count": 3, "rejected_count": 1, "error_count": 0,
            "planned_count": 4,
            "by_target": {"t2": {"accepted": 1}, "t1": {"accepted": 2}},
            "by_strategy": {"s1": {"accepted": 3}},
        }
        fp1 = _acceptance_fingerprint(summary)
        # Reorder by_target — must be same fingerprint
        summary["by_target"] = dict(reversed(list(summary["by_target"].items())))
        fp2 = _acceptance_fingerprint(summary)
        assert fp1 == fp2, "acceptance fingerprint must be key-order independent"
