"""
Tests for the `insert-me batch` CLI subcommand.

Coverage
--------
- Parser registration: `insert-me batch --help` exits 0 and names the command
- Missing --seed-dir exits with error code 2
- Empty seed dir exits with error code 2
- Batch run over 2 sandbox seeds produces OK/VALID for each (CLI subprocess)
- Dry-run batch does not modify source files
- Exit code 0 when all seeds VALID; non-zero when a seed fails
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent
SANDBOX_SEEDS = REPO_ROOT / "examples" / "seeds" / "sandbox"
SANDBOX_SRC   = REPO_ROOT / "examples" / "sandbox_eval" / "src"

# Two seeds that are known-good for fast integration tests
_FAST_SEEDS = ["cwe122_sb_001.json", "cwe416_sb_001.json"]


def _cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "insert_me.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
    )


# ---------------------------------------------------------------------------
# Parser / help
# ---------------------------------------------------------------------------

class TestBatchParser:
    def test_help_exits_zero(self):
        r = _cli("batch", "--help")
        assert r.returncode == 0

    def test_help_mentions_seed_dir(self):
        r = _cli("batch", "--help")
        assert "--seed-dir" in r.stdout

    def test_help_mentions_source(self):
        r = _cli("batch", "--help")
        assert "--source" in r.stdout

    def test_missing_required_args_exits_nonzero(self):
        r = _cli("batch")
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# Input validation errors
# ---------------------------------------------------------------------------

class TestBatchInputErrors:
    def test_nonexistent_seed_dir_exits_2(self, tmp_path):
        r = _cli(
            "batch",
            "--seed-dir", str(tmp_path / "does_not_exist"),
            "--source", str(SANDBOX_SRC),
            "--output", str(tmp_path / "out"),
        )
        assert r.returncode == 2
        assert "seed-dir" in r.stderr.lower() or "not found" in r.stderr.lower()

    def test_empty_seed_dir_exits_2(self, tmp_path):
        empty_dir = tmp_path / "seeds"
        empty_dir.mkdir()
        r = _cli(
            "batch",
            "--seed-dir", str(empty_dir),
            "--source", str(SANDBOX_SRC),
            "--output", str(tmp_path / "out"),
        )
        assert r.returncode == 2
        assert "no .json" in r.stderr.lower() or "not found" in r.stderr.lower()


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------

class TestBatchDryRun:
    def test_dry_run_exits_zero_for_known_good_seeds(self, tmp_path):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        for name in _FAST_SEEDS:
            src = SANDBOX_SEEDS / name
            (seed_dir / name).write_bytes(src.read_bytes())

        r = _cli(
            "batch",
            "--seed-dir", str(seed_dir),
            "--source", str(SANDBOX_SRC),
            "--output", str(tmp_path / "out"),
            "--dry-run",
        )
        assert r.returncode == 0, r.stderr

    def test_dry_run_does_not_write_bad_good_dirs(self, tmp_path):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / _FAST_SEEDS[0]).write_bytes(
            (SANDBOX_SEEDS / _FAST_SEEDS[0]).read_bytes()
        )
        out_dir = tmp_path / "out"

        _cli(
            "batch",
            "--seed-dir", str(seed_dir),
            "--source", str(SANDBOX_SRC),
            "--output", str(out_dir),
            "--dry-run",
        )

        # In dry-run mode bad/ and good/ should be empty dirs (no source files)
        bad_dirs = list(out_dir.rglob("bad"))
        for bad in bad_dirs:
            c_files = list(bad.rglob("*.c"))
            assert len(c_files) == 0, f"dry-run wrote .c files into {bad}"


# ---------------------------------------------------------------------------
# Real-mode integration (fast: 2 seeds only)
# ---------------------------------------------------------------------------

class TestBatchRealMode:
    def test_two_known_good_seeds_all_ok(self, tmp_path):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        for name in _FAST_SEEDS:
            (seed_dir / name).write_bytes((SANDBOX_SEEDS / name).read_bytes())

        r = _cli(
            "batch",
            "--seed-dir", str(seed_dir),
            "--source", str(SANDBOX_SRC),
            "--output", str(tmp_path / "out"),
        )
        assert r.returncode == 0, r.stderr
        assert "2/2 OK" in r.stdout

    def test_output_contains_result_table(self, tmp_path):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / _FAST_SEEDS[0]).write_bytes(
            (SANDBOX_SEEDS / _FAST_SEEDS[0]).read_bytes()
        )

        r = _cli(
            "batch",
            "--seed-dir", str(seed_dir),
            "--source", str(SANDBOX_SRC),
            "--output", str(tmp_path / "out"),
        )
        assert "OK" in r.stdout
        assert "VALID" in r.stdout

    def test_exit_nonzero_when_seed_fails(self, tmp_path):
        """A seed pointing at a nonexistent source root should produce ERROR rows."""
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / _FAST_SEEDS[0]).write_bytes(
            (SANDBOX_SEEDS / _FAST_SEEDS[0]).read_bytes()
        )

        r = _cli(
            "batch",
            "--seed-dir", str(seed_dir),
            "--source", str(tmp_path / "no_src"),   # nonexistent source
            "--output", str(tmp_path / "out"),
        )
        assert r.returncode != 0
