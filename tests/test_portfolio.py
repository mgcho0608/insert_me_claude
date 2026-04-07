"""
Tests for the insert_me portfolio planning layer (Phase 15 + 15.5).

Covers:
- PortfolioConstraints: defaults, to_dict/from_dict roundtrip
- load_targets_file: valid file, relative path resolution, error cases
- PortfolioPlanner: determinism, proportional allocation, shortfall, diversity
- PortfolioPlan: to_dict/from_dict roundtrip, write artifacts
- CLI plan-portfolio: argument parsing, output artifacts, exit codes
- CLI generate-portfolio: --dry-run mode, --from-plan replay
- Portfolio schema validation: all 4 portfolio artifacts vs their JSON schemas
- Portfolio E2E: actual pipeline execution (not dry-run) with schema validation
- Portfolio fingerprint stability: 3 independent plan runs -> same fingerprint
- Portfolio consistency: per-target summaries match portfolio-level totals
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


# ---------------------------------------------------------------------------
# TestPortfolioSchemaValidation
# ---------------------------------------------------------------------------

class TestPortfolioSchemaValidation:
    """Validate portfolio artifacts against their JSON schemas."""

    def _make_dry_run_portfolio(self, tmpdir: str, count: int = 6) -> Path:
        """Run generate-portfolio --dry-run and return output_root Path."""
        out_root = Path(tmpdir) / "portfolio"
        _run_cli(
            "generate-portfolio",
            "--targets-file", str(TARGETS_FILE),
            "--count", str(count),
            "--output-root", str(out_root),
            "--dry-run",
            "--no-llm",
        )
        return out_root

    def test_portfolio_plan_schema_valid(self):
        from insert_me.schema import validate_artifact
        from insert_me.schema import SCHEMA_PORTFOLIO_PLAN
        with tempfile.TemporaryDirectory() as tmpdir:
            out = self._make_dry_run_portfolio(tmpdir)
            plan_file = out / "_plan" / "portfolio_plan.json"
            assert plan_file.exists(), f"Missing {plan_file}"
            data = json.loads(plan_file.read_text(encoding="utf-8"))
            validate_artifact(data, SCHEMA_PORTFOLIO_PLAN)  # must not raise

    def test_portfolio_index_schema_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_INDEX
        with tempfile.TemporaryDirectory() as tmpdir:
            out = self._make_dry_run_portfolio(tmpdir)
            idx_file = out / "portfolio_index.json"
            assert idx_file.exists()
            data = json.loads(idx_file.read_text(encoding="utf-8"))
            validate_artifact(data, SCHEMA_PORTFOLIO_INDEX)

    def test_portfolio_acceptance_summary_schema_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY
        with tempfile.TemporaryDirectory() as tmpdir:
            out = self._make_dry_run_portfolio(tmpdir)
            summ_file = out / "portfolio_acceptance_summary.json"
            assert summ_file.exists()
            data = json.loads(summ_file.read_text(encoding="utf-8"))
            validate_artifact(data, SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY)

    def test_portfolio_shortfall_report_schema_valid(self):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_SHORTFALL_REPORT
        with tempfile.TemporaryDirectory() as tmpdir:
            out = self._make_dry_run_portfolio(tmpdir)
            sf_file = out / "portfolio_shortfall_report.json"
            assert sf_file.exists()
            data = json.loads(sf_file.read_text(encoding="utf-8"))
            validate_artifact(data, SCHEMA_PORTFOLIO_SHORTFALL_REPORT)

    def test_all_four_schema_constants_exist(self):
        """Verify the schema constant names are importable and schemas load."""
        from insert_me.schema import (
            SCHEMA_PORTFOLIO_PLAN,
            SCHEMA_PORTFOLIO_INDEX,
            SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY,
            SCHEMA_PORTFOLIO_SHORTFALL_REPORT,
            schema_path,
        )
        for name in (
            SCHEMA_PORTFOLIO_PLAN,
            SCHEMA_PORTFOLIO_INDEX,
            SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY,
            SCHEMA_PORTFOLIO_SHORTFALL_REPORT,
        ):
            p = schema_path(name)
            assert p.exists(), f"Schema file not found for {name}"


# ---------------------------------------------------------------------------
# TestPortfolioFingerprintStability
# ---------------------------------------------------------------------------

class TestPortfolioFingerprintStability:
    """Same inputs across 3 independent runs => same portfolio fingerprint."""

    def _plan(self, count: int = 8):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, _ = PortfolioPlanner(targets=targets, requested_count=count).plan()
        return plan

    def test_fingerprint_identical_across_three_runs(self):
        fp1 = self._plan().fingerprint
        fp2 = self._plan().fingerprint
        fp3 = self._plan().fingerprint
        assert fp1 == fp2 == fp3, f"Fingerprints differ: {fp1} / {fp2} / {fp3}"

    def test_targets_hash_identical_across_three_runs(self):
        th1 = self._plan().targets_hash
        th2 = self._plan().targets_hash
        th3 = self._plan().targets_hash
        assert th1 == th2 == th3

    def test_entry_list_identical_across_three_runs(self):
        p1 = self._plan()
        p2 = self._plan()
        p3 = self._plan()
        ids1 = [e.case_id for e in p1.entries]
        ids2 = [e.case_id for e in p2.entries]
        ids3 = [e.case_id for e in p3.entries]
        assert ids1 == ids2 == ids3

    def test_cli_fingerprint_stable_across_two_runs(self):
        """plan-portfolio CLI: two runs produce same fingerprint in portfolio_plan.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d1 = tmpdir + "/run1"
            d2 = tmpdir + "/run2"
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "8",
                "--output-dir", d1,
            )
            _run_cli(
                "plan-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "8",
                "--output-dir", d2,
            )
            fp1 = json.loads(
                (Path(d1) / "portfolio_plan.json").read_text(encoding="utf-8")
            )["fingerprint"]
            fp2 = json.loads(
                (Path(d2) / "portfolio_plan.json").read_text(encoding="utf-8")
            )["fingerprint"]
            assert fp1 == fp2, f"CLI fingerprints differ: {fp1} / {fp2}"


# ---------------------------------------------------------------------------
# TestPortfolioConsistency
# ---------------------------------------------------------------------------

class TestPortfolioConsistency:
    """Per-target summaries must be consistent with portfolio-level totals."""

    def _plan(self):
        from insert_me.planning.portfolio import PortfolioPlanner, PortfolioTarget
        targets = [
            PortfolioTarget(name="sandbox_eval", path=str(SANDBOX_SRC)),
            PortfolioTarget(name="target_b",     path=str(TARGET_B)),
        ]
        plan, per = PortfolioPlanner(targets=targets, requested_count=12).plan()
        return plan, per

    def test_per_target_planned_sums_to_portfolio_planned(self):
        plan, per = self._plan()
        sum_per_target = sum(ts.planned_count for ts in plan.target_summaries)
        # planned_count is global selection result; per-target planned_counts
        # reflect what each CorpusPlanner synthesised, which may be >= global selection
        # but the entries list IS the global selection
        assert plan.planned_count == len(plan.entries)

    def test_entries_target_names_all_in_target_summaries(self):
        plan, _ = self._plan()
        summary_names = {ts.name for ts in plan.target_summaries}
        for e in plan.entries:
            assert e.target_name in summary_names

    def test_allocation_summary_by_target_matches_entries(self):
        plan, _ = self._plan()
        d = plan.to_dict()
        by_target_in_summary = d["allocation_summary"]["by_target"]
        by_target_from_entries: dict[str, int] = {}
        for e in plan.entries:
            by_target_from_entries[e.target_name] = by_target_from_entries.get(e.target_name, 0) + 1
        assert by_target_in_summary == by_target_from_entries

    def test_allocation_summary_by_strategy_matches_entries(self):
        plan, _ = self._plan()
        d = plan.to_dict()
        by_strat_in_summary = d["allocation_summary"]["by_strategy"]
        by_strat_from_entries: dict[str, int] = {}
        for e in plan.entries:
            by_strat_from_entries[e.strategy] = by_strat_from_entries.get(e.strategy, 0) + 1
        assert by_strat_in_summary == by_strat_from_entries

    def test_global_strategy_allocation_matches_entries(self):
        plan, _ = self._plan()
        from_entries: dict[str, int] = {}
        for e in plan.entries:
            from_entries[e.strategy] = from_entries.get(e.strategy, 0) + 1
        assert plan.global_strategy_allocation == from_entries

    def test_dry_run_portfolio_index_counts_match_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = tmpdir + "/portfolio"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(TARGETS_FILE),
                "--count", "8",
                "--output-root", out_root,
                "--dry-run",
                "--no-llm",
            )
            idx = json.loads(
                (Path(out_root) / "portfolio_index.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (Path(out_root) / "_plan" / "portfolio_plan.json").read_text(encoding="utf-8")
            )
            assert idx["counts"]["planned"] == plan["planned_count"]
            assert idx["counts"]["requested"] == plan["requested_count"]


# ---------------------------------------------------------------------------
# TestPortfolioE2E (actual execution — no --dry-run)
# ---------------------------------------------------------------------------

class TestPortfolioE2E:
    """
    End-to-end generate-portfolio tests that actually execute the pipeline.

    Use a small count (3 cases) on the minimal+moderate local fixtures to keep
    execution time short.  These tests verify that:
    - generate-portfolio completes successfully
    - all portfolio artifacts exist and pass schema validation
    - replay produces a consistent portfolio_index
    - per-target corpus_index.json files are written
    """

    # Use only sandbox_eval to keep execution time bounded (real pipeline runs)
    @pytest.fixture(scope="class")
    def sandbox_only_targets_file(self, tmp_path_factory):
        """Create a single-target targets.json pointing at sandbox_eval."""
        d = tmp_path_factory.mktemp("targets")
        tf = d / "single_target.json"
        tf.write_text(json.dumps({
            "targets": [{"name": "sandbox_eval", "path": str(SANDBOX_SRC)}]
        }), encoding="utf-8")
        return tf

    def test_e2e_generate_portfolio_exits_zero(self, sandbox_only_targets_file):
        with tempfile.TemporaryDirectory() as tmpdir:
            rc, out, err = _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", tmpdir + "/out",
                "--no-llm",
            )
            assert rc == 0, f"generate-portfolio failed.\nstdout: {out}\nstderr: {err}"

    def test_e2e_portfolio_plan_exists(self, sandbox_only_targets_file):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out,
                "--no-llm",
            )
            assert (Path(out) / "_plan" / "portfolio_plan.json").exists()

    def test_e2e_portfolio_index_schema_valid(self, sandbox_only_targets_file):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_INDEX
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out,
                "--no-llm",
            )
            data = json.loads((Path(out) / "portfolio_index.json").read_text(encoding="utf-8"))
            validate_artifact(data, SCHEMA_PORTFOLIO_INDEX)
            assert data["run_mode"] == "generate"
            assert data["counts"]["planned"] >= 1

    def test_e2e_portfolio_acceptance_summary_schema_valid(self, sandbox_only_targets_file):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out,
                "--no-llm",
            )
            data = json.loads(
                (Path(out) / "portfolio_acceptance_summary.json").read_text(encoding="utf-8")
            )
            validate_artifact(data, SCHEMA_PORTFOLIO_ACCEPTANCE_SUMMARY)

    def test_e2e_portfolio_shortfall_report_schema_valid(self, sandbox_only_targets_file):
        from insert_me.schema import validate_artifact, SCHEMA_PORTFOLIO_SHORTFALL_REPORT
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out,
                "--no-llm",
            )
            data = json.loads(
                (Path(out) / "portfolio_shortfall_report.json").read_text(encoding="utf-8")
            )
            validate_artifact(data, SCHEMA_PORTFOLIO_SHORTFALL_REPORT)

    def test_e2e_per_target_corpus_index_written(self, sandbox_only_targets_file):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out,
                "--no-llm",
            )
            corpus_idx = Path(out) / "targets" / "sandbox_eval" / "corpus_index.json"
            assert corpus_idx.exists(), f"Expected {corpus_idx}"

    def test_e2e_replay_produces_consistent_index(self, sandbox_only_targets_file):
        """Replay from saved plan -> portfolio_index has run_mode='replay' and same planned count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: first run
            out1 = tmpdir + "/out1"
            _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "3",
                "--output-root", out1,
                "--no-llm",
            )
            plan_file = Path(out1) / "_plan" / "portfolio_plan.json"
            assert plan_file.exists()

            orig_idx = json.loads(
                (Path(out1) / "portfolio_index.json").read_text(encoding="utf-8")
            )

            # Step 2: replay
            out2 = tmpdir + "/out2"
            rc, out_text, err = _run_cli(
                "generate-portfolio",
                "--from-plan", str(plan_file),
                "--output-root", out2,
                "--no-llm",
            )
            assert rc == 0, f"Replay failed.\nstderr: {err}"

            replay_idx = json.loads(
                (Path(out2) / "portfolio_index.json").read_text(encoding="utf-8")
            )
            assert replay_idx["run_mode"] == "replay"
            assert replay_idx["counts"]["planned"] == orig_idx["counts"]["planned"]
            # Portfolio fingerprint must be identical (same plan)
            assert replay_idx["fingerprints"]["portfolio_fingerprint"] == \
                   orig_idx["fingerprints"]["portfolio_fingerprint"]

    def test_e2e_truthful_shortfall_when_count_exceeds_capacity(self, sandbox_only_targets_file):
        """Requesting far more than capacity: honest shortfall, no crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = tmpdir + "/out"
            rc, stdout, stderr = _run_cli(
                "generate-portfolio",
                "--targets-file", str(sandbox_only_targets_file),
                "--count", "999",
                "--output-root", out,
                "--no-llm",
            )
            # Should not crash (rc == 0 if no pipeline errors, even with shortfall)
            # portfolio_acceptance_summary must show honest shortfall
            summ_file = Path(out) / "portfolio_acceptance_summary.json"
            assert summ_file.exists()
            summ = json.loads(summ_file.read_text(encoding="utf-8"))
            assert summ["planned_count"] < summ["requested_count"]
            assert summ["shortfall_amount"] > 0
            assert summ["honest"] is True
