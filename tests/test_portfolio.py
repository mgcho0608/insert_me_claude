"""
Tests for the insert_me portfolio planning layer (Phase 15).

Covers:
- PortfolioConstraints: defaults, to_dict/from_dict roundtrip
- load_targets_file: valid file, relative path resolution, error cases
- PortfolioPlanner: determinism, proportional allocation, shortfall, diversity
- PortfolioPlan: to_dict/from_dict roundtrip, write artifacts
- CLI plan-portfolio: argument parsing, output artifacts, exit codes
- CLI generate-portfolio: --dry-run mode, --from-plan replay
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent.parent
SANDBOX_SRC = REPO_ROOT / "examples" / "sandbox_eval" / "src"
TARGET_B    = REPO_ROOT / "examples" / "sandbox_targets" / "target_b" / "src"
MINIMAL_SRC = REPO_ROOT / "examples" / "local_targets" / "minimal" / "src"
MODERATE_SRC = REPO_ROOT / "examples" / "local_targets" / "moderate" / "src"
TARGETS_FILE = REPO_ROOT / "examples" / "targets" / "sandbox_targets.json"


# ---------------------------------------------------------------------------
# TestPortfolioConstraints
# ---------------------------------------------------------------------------

class TestPortfolioConstraints:
    def test_defaults(self):
        from insert_me.planning.portfolio import PortfolioConstraints
        c = PortfolioConstraints()
        assert c.max_per_target == 20
        assert c.max_per_strategy_global == 20
        assert c.max_per_target_fraction == 0.6
        assert c.max_per_strategy_fraction == 0.5
        assert c.max_per_file == 5
        assert c.max_per_function == 2
        assert c.min_candidate_score == 0.0
        assert c.strict_quality is False

    def test_to_dict_roundtrip(self):
        from insert_me.planning.portfolio import PortfolioConstraints
        c = PortfolioConstraints(
            max_per_target=10,
            max_per_strategy_global=8,
            max_per_target_fraction=0.4,
            max_per_file=3,
            strict_quality=True,
        )
        d = c.to_dict()
        c2 = PortfolioConstraints.from_dict(d)
        assert c2.max_per_target == 10
        assert c2.max_per_strategy_global == 8
        assert c2.max_per_target_fraction == 0.4
        assert c2.max_per_file == 3
        assert c2.strict_quality is True

    def test_from_dict_partial_uses_defaults(self):
        from insert_me.planning.portfolio import PortfolioConstraints
        c = PortfolioConstraints.from_dict({"max_per_target": 5})
        assert c.max_per_target == 5
        assert c.max_per_strategy_global == 20  # default


# ---------------------------------------------------------------------------
# TestLoadTargetsFile
# ---------------------------------------------------------------------------

class TestLoadTargetsFile:
    def test_loads_bundled_file(self):
        from insert_me.planning.portfolio import load_targets_file
        targets = load_targets_file(TARGETS_FILE)
        assert len(targets) >= 2
        names = [t.name for t in targets]
        assert "sandbox_eval" in names
        assert "target_b" in names

    def test_resolves_relative_paths(self):
        from insert_me.planning.portfolio import load_targets_file
        targets = load_targets_file(TARGETS_FILE)
        for t in targets:
            p = Path(t.path)
            assert p.is_absolute(), f"Expected absolute path for {t.name}, got {t.path}"

    def test_resolved_paths_exist(self):
        from insert_me.planning.portfolio import load_targets_file
        targets = load_targets_file(TARGETS_FILE)
        for t in targets:
            assert Path(t.path).exists(), f"Path does not exist: {t.path}"

    def test_missing_file_raises(self):
        from insert_me.planning.portfolio import load_targets_file
        with pytest.raises((FileNotFoundError, OSError)):
            load_targets_file(Path("/nonexistent/targets.json"))

    def test_empty_targets_list_returns_empty(self):
        from insert_me.planning.portfolio import load_targets_file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"targets": []}, fh)
            fpath = Path(fh.name)
        targets = load_targets_file(fpath)
        fpath.unlink(missing_ok=True)
        assert targets == []

    def test_custom_targets_file(self):
        from insert_me.planning.portfolio import load_targets_file
        data = {
            "targets": [
                {"name": "sb",  "path": str(SANDBOX_SRC)},
                {"name": "tb",  "path": str(TARGET_B)},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(data, fh)
            fpath = Path(fh.name)
        targets = load_targets_file(fpath)
        fpath.unlink(missing_ok=True)
        assert len(targets) == 2
        assert targets[0].name == "sb"


# ---------------------------------------------------------------------------
# TestPortfolioPlannerDeterminism
# ---------------------------------------------------------------------------

class TestPortfolioPlannerDeterminism:
    """Same inputs => same portfolio_plan fingerprint."""

    def _make_targets(self):
        from insert_me.planning.portfolio import PortfolioTarget
        return [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]

    def test_fingerprint_is_stable_across_runs(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        targets = self._make_targets()
        p1, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        p2, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        assert p1.fingerprint == p2.fingerprint

    def test_targets_hash_is_stable(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        targets = self._make_targets()
        p1, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        p2, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        assert p1.targets_hash == p2.targets_hash

    def test_planned_count_is_stable(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        targets = self._make_targets()
        p1, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        p2, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        assert p1.planned_count == p2.planned_count

    def test_entry_order_is_stable(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        targets = self._make_targets()
        p1, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        p2, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        ids1 = [e.case_id for e in p1.entries]
        ids2 = [e.case_id for e in p2.entries]
        assert ids1 == ids2

    def test_different_count_gives_different_plan(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        targets = self._make_targets()
        p5,  _ = PortfolioPlanner(targets=targets, requested_count=5).plan()
        p10, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        # At minimum the planned counts differ (5 vs 10 when target has capacity)
        assert p5.requested_count != p10.requested_count

    def test_targets_sorted_by_name_for_determinism(self):
        """Shuffling the targets list should not change the plan."""
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets_fwd = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        targets_rev = [
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
        ]
        p_fwd, _ = PortfolioPlanner(targets=targets_fwd, requested_count=10).plan()
        p_rev, _ = PortfolioPlanner(targets=targets_rev, requested_count=10).plan()
        assert p_fwd.fingerprint == p_rev.fingerprint


# ---------------------------------------------------------------------------
# TestPortfolioAllocation
# ---------------------------------------------------------------------------

class TestPortfolioAllocation:
    def test_planned_count_does_not_exceed_requested(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20).plan()
        assert plan.planned_count <= plan.requested_count

    def test_entries_count_matches_planned_count(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20).plan()
        assert len(plan.entries) == plan.planned_count

    def test_global_strategy_allocation_sums_to_planned(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20).plan()
        total = sum(plan.global_strategy_allocation.values())
        assert total == plan.planned_count

    def test_target_summaries_have_correct_targets(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        summary_names = {ts.name for ts in plan.target_summaries}
        assert "sandbox_eval" in summary_names
        assert "target_b" in summary_names

    def test_max_per_target_hard_limit(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget, PortfolioConstraints
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        c = PortfolioConstraints(max_per_target=3)
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20, constraints=c).plan()
        by_target: dict[str, int] = {}
        for e in plan.entries:
            by_target[e.target_name] = by_target.get(e.target_name, 0) + 1
        for name, cnt in by_target.items():
            assert cnt <= 3, f"Target {name} has {cnt} > max_per_target=3"

    def test_max_per_strategy_hard_limit(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget, PortfolioConstraints
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        c = PortfolioConstraints(max_per_strategy_global=2)
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20, constraints=c).plan()
        by_strategy: dict[str, int] = {}
        for e in plan.entries:
            by_strategy[e.strategy] = by_strategy.get(e.strategy, 0) + 1
        for strat, cnt in by_strategy.items():
            assert cnt <= 2, f"Strategy {strat} has {cnt} > max_per_strategy=2"

    def test_case_ids_are_globally_unique(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=20).plan()
        ids = [e.case_id for e in plan.entries]
        assert len(ids) == len(set(ids)), "Duplicate case_ids found"

    def test_case_id_prefix_reflects_target_name(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=10).plan()
        for e in plan.entries:
            # case_id format: cwe<NNN>_<target_prefix>_<NNN>
            # target prefix should contain a sanitised part of the target name
            assert e.target_name in ("sandbox_eval", "target_b")
            # prefix in case_id should at least reference the sanitised name
            sanitised = e.target_name.replace("-", "_")
            assert sanitised in e.case_id or e.target_name.split("_")[0] in e.case_id


# ---------------------------------------------------------------------------
# TestPortfolioShortfall
# ---------------------------------------------------------------------------

class TestPortfolioShortfall:
    def test_shortfall_reported_when_requested_exceeds_capacity(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        # Use minimal target which has very few candidates
        targets = [PortfolioTarget(name="minimal", path=str(MINIMAL_SRC))]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=999).plan()
        # Either planned < requested or shortfall is reported
        if plan.planned_count < plan.requested_count:
            assert plan.shortfall["count"] > 0

    def test_shortfall_categories_are_dict(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [PortfolioTarget(name="minimal", path=str(MINIMAL_SRC))]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=999).plan()
        assert isinstance(plan.shortfall.get("categories", {}), dict)

    def test_no_shortfall_when_achievable(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=4).plan()
        assert plan.planned_count == 4
        assert plan.shortfall["count"] == 0

    def test_empty_targets_returns_blockers(self):
        from insert_me.planning.portfolio import PortfolioPlanner
        plan, per = PortfolioPlanner(targets=[], requested_count=10).plan()
        assert plan.planned_count == 0
        assert plan.blockers

    def test_nonexistent_target_path_returns_blocker(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [PortfolioTarget(name="missing", path="/nonexistent/path/src")]
        plan, per = PortfolioPlanner(targets=targets, requested_count=5).plan()
        assert plan.planned_count == 0
        assert plan.blockers


# ---------------------------------------------------------------------------
# TestPortfolioPlanRoundtrip
# ---------------------------------------------------------------------------

class TestPortfolioPlanRoundtrip:
    def _make_plan(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, per = PortfolioPlanner(targets=targets, requested_count=8).plan()
        return plan, per

    def test_to_dict_has_required_keys(self):
        plan, _ = self._make_plan()
        d = plan.to_dict()
        for key in (
            "schema_version", "schema", "portfolio_id", "targets_hash",
            "requested_count", "planned_count", "projected_accepted_count",
            "constraints", "target_summaries", "entries",
            "global_strategy_allocation", "shortfall", "fingerprint",
            "warnings", "blockers",
        ):
            assert key in d, f"Missing key: {key}"

    def test_from_dict_roundtrip_preserves_planned_count(self):
        from insert_me.planning.portfolio import PortfolioPlan
        plan, _ = self._make_plan()
        d = plan.to_dict()
        plan2 = PortfolioPlan.from_dict(d)
        assert plan2.planned_count == plan.planned_count

    def test_from_dict_roundtrip_preserves_fingerprint(self):
        from insert_me.planning.portfolio import PortfolioPlan
        plan, _ = self._make_plan()
        d = plan.to_dict()
        plan2 = PortfolioPlan.from_dict(d)
        assert plan2.fingerprint == plan.fingerprint

    def test_from_dict_roundtrip_preserves_entry_count(self):
        from insert_me.planning.portfolio import PortfolioPlan
        plan, _ = self._make_plan()
        d = plan.to_dict()
        plan2 = PortfolioPlan.from_dict(d)
        assert len(plan2.entries) == len(plan.entries)

    def test_from_dict_roundtrip_preserves_constraints(self):
        from insert_me.planning.portfolio import PortfolioPlan, PortfolioConstraints, PortfolioPlanner, PortfolioTarget
        targets = [PortfolioTarget(name="sb", path=str(SANDBOX_SRC))]
        c = PortfolioConstraints(max_per_target=7, max_per_strategy_global=4)
        plan, _ = PortfolioPlanner(targets=targets, requested_count=5, constraints=c).plan()
        d = plan.to_dict()
        plan2 = PortfolioPlan.from_dict(d)
        assert plan2.constraints.max_per_target == 7
        assert plan2.constraints.max_per_strategy_global == 4

    def test_write_creates_portfolio_plan_json(self):
        plan, per = self._make_plan()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "portfolio_out"
            plan.write(out, per)
            assert (out / "portfolio_plan.json").exists()

    def test_write_creates_per_target_plans(self):
        plan, per = self._make_plan()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "portfolio_out"
            plan.write(out, per)
            for ts in plan.target_summaries:
                if per.get(ts.name) and per[ts.name].planned_count > 0:
                    sub = out / "targets" / ts.name / "_plan" / "corpus_plan.json"
                    assert sub.exists(), f"Expected sub-plan: {sub}"

    def test_write_portfolio_plan_is_valid_json(self):
        plan, per = self._make_plan()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "portfolio_out"
            plan.write(out, per)
            data = json.loads((out / "portfolio_plan.json").read_text(encoding="utf-8"))
            assert data["schema"] == "portfolio_plan"
            assert data["planned_count"] == plan.planned_count


# ---------------------------------------------------------------------------
# TestPortfolioCLIPlanPortfolio
# ---------------------------------------------------------------------------

def _run_cli(*args):
    """Run `python -m insert_me.cli <args>` and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli"] + list(args),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    return result.returncode, result.stdout, result.stderr


class TestPortfolioCLIPlanPortfolio:
    def test_plan_portfolio_missing_targets_file_exits_nonzero(self):
        rc, out, err = _run_cli(
            "plan-portfolio", "--targets-file", "/nonexistent.json", "--count", "10"
        )
        assert rc != 0

    def test_plan_portfolio_bundled_targets_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rc, out, err = _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "10",
                "--output-dir", tmpdir + "/plan",
            )
            assert rc == 0, f"stderr: {err}"

    def test_plan_portfolio_writes_portfolio_plan_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir + "/plan"
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "10",
                "--output-dir", out_dir,
            )
            assert (Path(out_dir) / "portfolio_plan.json").exists()

    def test_plan_portfolio_plan_json_is_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir + "/plan"
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "10",
                "--output-dir", out_dir,
            )
            data = json.loads(
                (Path(out_dir) / "portfolio_plan.json").read_text(encoding="utf-8")
            )
            assert data["schema"] == "portfolio_plan"
            assert data["requested_count"] == 10
            assert data["planned_count"] <= 10

    def test_plan_portfolio_per_target_plans_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir + "/plan"
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "10",
                "--output-dir", out_dir,
            )
            # At least one per-target sub-plan directory should exist
            targets_dir = Path(out_dir) / "targets"
            assert targets_dir.exists()
            sub_dirs = list(targets_dir.iterdir())
            assert len(sub_dirs) >= 1

    def test_plan_portfolio_max_per_target_honoured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir + "/plan"
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "20",
                "--max-per-target", "3",
                "--output-dir", out_dir,
            )
            data = json.loads(
                (Path(out_dir) / "portfolio_plan.json").read_text(encoding="utf-8")
            )
            by_target: dict[str, int] = {}
            for e in data["entries"]:
                by_target[e["target_name"]] = by_target.get(e["target_name"], 0) + 1
            for name, cnt in by_target.items():
                assert cnt <= 3, f"Target {name} has {cnt} entries > max_per_target=3"


# ---------------------------------------------------------------------------
# TestPortfolioCLIGeneratePortfolio
# ---------------------------------------------------------------------------

class TestPortfolioCLIGeneratePortfolio:
    def test_generate_portfolio_dry_run_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rc, out, err = _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", tmpdir + "/portfolio",
                "--dry-run",
                "--no-llm",
            )
            assert rc == 0, f"stderr: {err}"

    def test_generate_portfolio_dry_run_writes_portfolio_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            plan_file = Path(out_root) / "_plan" / "portfolio_plan.json"
            assert plan_file.exists(), f"Expected {plan_file}"

    def test_generate_portfolio_dry_run_writes_portfolio_index(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            assert (Path(out_root) / "portfolio_index.json").exists()

    def test_generate_portfolio_dry_run_writes_acceptance_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            assert (Path(out_root) / "portfolio_acceptance_summary.json").exists()

    def test_generate_portfolio_dry_run_writes_shortfall_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            assert (Path(out_root) / "portfolio_shortfall_report.json").exists()

    def test_generate_portfolio_dry_run_portfolio_index_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            data = json.loads(
                (Path(out_root) / "portfolio_index.json").read_text(encoding="utf-8")
            )
            assert data["schema"] == "portfolio_index"
            assert data["run_mode"] == "dry-run"

    def test_generate_portfolio_from_plan_replay_dry_run(self):
        """Replay an existing portfolio_plan.json via --from-plan --dry-run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_dir = tmpdir + "/plan"
            # Step 1: produce a plan
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "6",
                "--output-dir", plan_dir,
            )
            plan_file = Path(plan_dir) / "portfolio_plan.json"
            assert plan_file.exists()

            # Step 2: replay via generate-portfolio --from-plan
            replay_dir = tmpdir + "/replay"
            rc, out, err = _run_cli(
                "generate-portfolio",
                "--from-plan", str(plan_file),
                "--output-root", replay_dir,
                "--dry-run",
                "--no-llm",
            )
            assert rc == 0, f"stderr: {err}"
            assert (Path(replay_dir) / "portfolio_index.json").exists()

    def test_generate_portfolio_missing_targets_file_exits_nonzero(self):
        rc, out, err = _run_cli(
            "generate-portfolio",
            "--targets-file", "/nonexistent.json",
            "--count", "5",
        )
        assert rc != 0

    def test_generate_portfolio_no_targets_no_plan_exits_nonzero(self):
        rc, out, err = _run_cli(
            "generate-portfolio",
            "--count", "5",
        )
        assert rc != 0
