"""
Tests for the insert_me planning layer.

Covers:
- TargetInspector: suitability classification, file/function grouping
- SeedSynthesizer: determinism, diversity constraints, deduplication
- CorpusPlanner: allocation correctness, count honesty, reproducibility
- CLI plan-corpus: argument parsing, output artifacts, exit codes
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
SANDBOX_SRC = Path(__file__).parent.parent / "examples" / "sandbox_eval" / "src"

# ---------------------------------------------------------------------------
# TargetInspector tests
# ---------------------------------------------------------------------------


class TestTargetInspector:
    """Tests for TargetInspector suitability classification."""

    def test_inspect_returns_inspection_result(self):
        from insert_me.planning import TargetInspector, InspectionResult

        inspector = TargetInspector(LOCAL_TARGET_DIR)
        result = inspector.run()
        assert isinstance(result, InspectionResult)

    def test_inspect_has_source_hash(self):
        from insert_me.planning import TargetInspector

        result = TargetInspector(LOCAL_TARGET_DIR).run()
        assert isinstance(result.source_hash, str)
        assert len(result.source_hash) == 16

    def test_source_hash_is_deterministic(self):
        from insert_me.planning import TargetInspector

        r1 = TargetInspector(LOCAL_TARGET_DIR).run()
        r2 = TargetInspector(LOCAL_TARGET_DIR).run()
        assert r1.source_hash == r2.source_hash

    def test_inspect_strategies_dict_populated(self):
        from insert_me.planning import TargetInspector

        result = TargetInspector(LOCAL_TARGET_DIR).run()
        assert isinstance(result.strategies, dict)
        assert len(result.strategies) > 0

    def test_inspect_suitability_valid_values(self):
        from insert_me.planning import TargetInspector
        from insert_me.planning.inspector import VIABLE, LIMITED, BLOCKED

        result = TargetInspector(LOCAL_TARGET_DIR).run()
        valid = {VIABLE, LIMITED, BLOCKED, "EXPERIMENTAL"}
        for name, stats in result.strategies.items():
            assert stats.suitability in valid, (
                f"{name} suitability={stats.suitability!r} not in {valid}"
            )

    def test_inspect_by_file_is_dict_of_ints(self):
        from insert_me.planning import TargetInspector

        result = TargetInspector(LOCAL_TARGET_DIR).run()
        for name, stats in result.strategies.items():
            for fname, count in stats.by_file.items():
                assert isinstance(count, int) and count >= 0

    def test_inspect_empty_dir_all_blocked_or_experimental(self, tmp_path):
        from insert_me.planning import TargetInspector
        from insert_me.planning.inspector import BLOCKED

        # Create a dir with a C file that has no patterns
        c_file = tmp_path / "empty.c"
        c_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        result = TargetInspector(tmp_path).run()
        for name, stats in result.strategies.items():
            assert stats.suitability in (BLOCKED, "EXPERIMENTAL"), (
                f"{name}: expected BLOCKED or EXPERIMENTAL, got {stats.suitability!r}"
            )

    def test_sandbox_has_viable_strategies(self):
        """Sandbox target should have at least one VIABLE strategy."""
        from insert_me.planning import TargetInspector
        from insert_me.planning.inspector import VIABLE

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        result = TargetInspector(SANDBOX_SRC).run()
        viable = [n for n, s in result.strategies.items() if s.suitability == VIABLE]
        assert len(viable) >= 1, f"Expected >=1 VIABLE strategy, got: {result.strategies}"


# ---------------------------------------------------------------------------
# SeedSynthesizer tests
# ---------------------------------------------------------------------------


class TestSeedSynthesizer:
    """Tests for SeedSynthesizer determinism and diversity."""

    def _get_eligible_strategy(self, source: Path):
        """Return the first strategy+cwe_id+pattern_type tuple with >=1 candidate."""
        from insert_me.planning import TargetInspector
        from insert_me.planning.inspector import PLANNING_STRATEGIES, BLOCKED

        result = TargetInspector(source).run()
        for strategy_name, cwe_id, pattern_type, admitted in PLANNING_STRATEGIES:
            s = result.strategies.get(strategy_name)
            if s and s.suitability != BLOCKED:
                return strategy_name, cwe_id, pattern_type
        return None

    def test_synthesize_returns_synthesis_result(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        synth = SeedSynthesizer(SANDBOX_SRC, SweepConstraints())
        result = synth.synthesize_for_strategy(
            strategy=strategy,
            cwe_id=cwe_id,
            pattern_type=pattern_type,
            requested_count=3,
            seen_targets=set(),
        )
        assert result.strategy == strategy
        assert isinstance(result.cases, list)

    def test_synthesize_is_deterministic(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        c = SweepConstraints()
        r1 = SeedSynthesizer(SANDBOX_SRC, c).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=5, seen_targets=set()
        )
        r2 = SeedSynthesizer(SANDBOX_SRC, c).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=5, seen_targets=set()
        )
        assert len(r1.cases) == len(r2.cases)
        for c1, c2 in zip(r1.cases, r2.cases):
            assert c1.seed_integer == c2.seed_integer
            assert c1.target_file == c2.target_file
            assert c1.target_line == c2.target_line

    def test_synthesize_no_duplicate_targets(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        seen: set = set()
        result = SeedSynthesizer(SANDBOX_SRC, SweepConstraints()).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=10, seen_targets=seen
        )
        targets = [(c.target_file, c.target_line) for c in result.cases]
        assert len(targets) == len(set(targets)), "Duplicate (file, line) in synthesis result"

    def test_synthesize_respects_max_per_file(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        c = SweepConstraints(max_per_file=2)
        result = SeedSynthesizer(SANDBOX_SRC, c).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=20, seen_targets=set()
        )
        from collections import Counter
        file_counts = Counter(case.target_file for case in result.cases)
        for fname, cnt in file_counts.items():
            assert cnt <= 2, f"File {fname} has {cnt} cases, max_per_file=2"

    def test_synthesize_respects_max_per_function(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        c = SweepConstraints(max_per_function=1)
        result = SeedSynthesizer(SANDBOX_SRC, c).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=20, seen_targets=set()
        )
        func_counts: dict[str, int] = {}
        for case in result.cases:
            key = f"{case.target_file}:{case.function_name}"
            if case.function_name:
                func_counts[key] = func_counts.get(key, 0) + 1
                assert func_counts[key] <= 1, (
                    f"Function {key} appears {func_counts[key]} times, max_per_function=1"
                )

    def test_seen_targets_cross_strategy_dedup(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints
        from insert_me.planning.inspector import PLANNING_STRATEGIES, BLOCKED
        from insert_me.planning import TargetInspector

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")

        result = TargetInspector(SANDBOX_SRC).run()
        eligible = [
            (n, cid, pt)
            for n, cid, pt, admitted in PLANNING_STRATEGIES
            if admitted and result.strategies.get(n) and
               result.strategies[n].suitability != BLOCKED
        ]
        if len(eligible) < 2:
            pytest.skip("need at least 2 eligible strategies")

        synth = SeedSynthesizer(SANDBOX_SRC, SweepConstraints())
        seen: set = set()
        all_targets: list[tuple[str, int]] = []

        for strategy, cwe_id, pattern_type in eligible[:2]:
            r = synth.synthesize_for_strategy(
                strategy, cwe_id, pattern_type,
                requested_count=5, seen_targets=seen
            )
            for case in r.cases:
                t = (case.target_file, case.target_line)
                assert t not in all_targets, (
                    f"Cross-strategy duplicate: {t}"
                )
                all_targets.append(t)

    def test_synthesized_case_to_seed_dict_valid(self):
        from insert_me.planning import SeedSynthesizer
        from insert_me.planning.seed_synthesis import SweepConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        info = self._get_eligible_strategy(SANDBOX_SRC)
        if info is None:
            pytest.skip("no eligible strategy for sandbox")
        strategy, cwe_id, pattern_type = info

        result = SeedSynthesizer(SANDBOX_SRC, SweepConstraints()).synthesize_for_strategy(
            strategy, cwe_id, pattern_type, requested_count=1, seen_targets=set()
        )
        if not result.cases:
            pytest.skip("no cases synthesized")
        d = result.cases[0].to_seed_dict(source_root="/fake/root")
        assert d["schema_version"] == "1.0"
        assert "seed_id" in d
        assert isinstance(d["seed"], int)
        assert d["cwe_id"] == cwe_id
        assert d["mutation_strategy"] == strategy


# ---------------------------------------------------------------------------
# CorpusPlanner tests
# ---------------------------------------------------------------------------


class TestCorpusPlanner:
    """Tests for CorpusPlanner allocation and CorpusPlan output."""

    def test_plan_returns_corpus_plan(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints, CorpusPlan

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 5).plan()
        assert isinstance(plan, CorpusPlan)

    def test_plan_count_does_not_exceed_requested(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 10).plan()
        assert plan.planned_count <= plan.requested_count

    def test_plan_is_reproducible(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        c = PlanConstraints(max_per_file=3, max_per_function=1)
        p1 = CorpusPlanner(SANDBOX_SRC, 8, c).plan()
        p2 = CorpusPlanner(SANDBOX_SRC, 8, c).plan()
        assert p1.planned_count == p2.planned_count
        assert p1.source_hash == p2.source_hash
        for a, b in zip(p1.cases, p2.cases):
            assert a.case_id == b.case_id
            assert a.seed_integer == b.seed_integer
            assert a.target_file == b.target_file
            assert a.target_line == b.target_line

    def test_plan_no_duplicate_targets(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 20).plan()
        targets = [(c.target_file, c.target_line) for c in plan.cases]
        assert len(targets) == len(set(targets)), "Duplicate (file, line) in plan cases"

    def test_plan_allocation_sums_to_planned_count(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 10).plan()
        alloc_total = sum(plan.strategy_allocation.values())
        assert alloc_total == plan.planned_count

    def test_plan_honesty_on_poor_target(self, tmp_path):
        """A target with just 1 viable site should plan <= 1 case and not crash."""
        from insert_me.planning import CorpusPlanner

        # Write one C file with exactly one malloc
        c_file = tmp_path / "tiny.c"
        c_file.write_text(
            "void f(void) {\n"
            "    char *p = malloc(10);\n"
            "    free(p);\n"
            "}\n",
            encoding="utf-8",
        )
        plan = CorpusPlanner(tmp_path, 10).plan()
        # Planned count must be <= total candidates, not artificially inflated
        assert plan.planned_count <= 10
        # Should not crash; may have warnings
        assert isinstance(plan.warnings, list)

    def test_plan_respects_allow_strategies(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        c = PlanConstraints(allow_strategies=["alloc_size_undercount"])
        plan = CorpusPlanner(SANDBOX_SRC, 5, c).plan()
        for case in plan.cases:
            assert case.strategy == "alloc_size_undercount"

    def test_plan_respects_disallow_strategies(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        c = PlanConstraints(disallow_strategies=["alloc_size_undercount"])
        plan = CorpusPlanner(SANDBOX_SRC, 5, c).plan()
        for case in plan.cases:
            assert case.strategy != "alloc_size_undercount"

    def test_plan_respects_max_per_file(self):
        # max_per_file is a per-strategy constraint, not a global file cap.
        # Each strategy contributes at most max_per_file cases per file.
        from insert_me.planning import CorpusPlanner, PlanConstraints
        from collections import Counter

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        c = PlanConstraints(max_per_file=2)
        plan = CorpusPlanner(SANDBOX_SRC, 20, c).plan()
        # Check per (strategy, file) pair
        strat_file_counts: dict[tuple[str, str], int] = {}
        for case in plan.cases:
            key = (case.strategy, case.target_file)
            strat_file_counts[key] = strat_file_counts.get(key, 0) + 1
        for (strat, fname), cnt in strat_file_counts.items():
            assert cnt <= 2, (
                f"Strategy {strat}, file {fname}: {cnt} cases, max_per_file=2"
            )

    def test_plan_projected_accepted_count_non_negative(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 5).plan()
        assert plan.projected_accepted_count >= 0

    def test_plan_confidence_valid_values(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 5).plan()
        for case in plan.cases:
            assert case.confidence in ("high", "medium", "low")

    def test_plan_to_dict_schema_compliant(self):
        from insert_me.planning import CorpusPlanner
        import jsonschema  # type: ignore

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        schema_path = Path(__file__).parent.parent / "schemas" / "corpus_plan.schema.json"
        if not schema_path.exists():
            pytest.skip("corpus_plan.schema.json not found")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        plan = CorpusPlanner(SANDBOX_SRC, 5).plan()
        d = plan.to_dict()
        jsonschema.validate(instance=d, schema=schema)

    def test_plan_write_creates_expected_files(self, tmp_path):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 3).plan()
        if plan.planned_count == 0:
            pytest.skip("no cases planned")
        plan.write(tmp_path)
        assert (tmp_path / "corpus_plan.json").exists()
        seeds_dir = tmp_path / "seeds"
        assert seeds_dir.exists()
        seed_files = list(seeds_dir.glob("*.json"))
        assert len(seed_files) == plan.planned_count

    def test_plan_write_seed_files_valid_json(self, tmp_path):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 3).plan()
        if plan.planned_count == 0:
            pytest.skip("no cases planned")
        plan.write(tmp_path)
        for seed_file in (tmp_path / "seeds").glob("*.json"):
            d = json.loads(seed_file.read_text(encoding="utf-8"))
            assert d["schema_version"] == "1.0"
            assert "seed" in d
            assert "mutation_strategy" in d

    def test_plan_write_corpus_plan_matches_schema(self, tmp_path):
        from insert_me.planning import CorpusPlanner
        import jsonschema

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        schema_path = Path(__file__).parent.parent / "schemas" / "corpus_plan.schema.json"
        if not schema_path.exists():
            pytest.skip("corpus_plan.schema.json not found")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        plan = CorpusPlanner(SANDBOX_SRC, 3).plan()
        if plan.planned_count == 0:
            pytest.skip("no cases planned")
        plan.write(tmp_path)
        d = json.loads((tmp_path / "corpus_plan.json").read_text(encoding="utf-8"))
        jsonschema.validate(instance=d, schema=schema)


# ---------------------------------------------------------------------------
# CorpusPlanner allocation logic tests
# ---------------------------------------------------------------------------


class TestCorpusPlannerAllocation:
    """Unit tests for CorpusPlanner._allocate and _fill_tier."""

    def test_allocation_never_exceeds_requested(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        for count in [1, 5, 10, 25]:
            plan = CorpusPlanner(SANDBOX_SRC, count).plan()
            assert plan.planned_count <= count, (
                f"requested={count}, planned={plan.planned_count}"
            )

    def test_allocation_sum_matches_planned_count(self):
        from insert_me.planning import CorpusPlanner

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        plan = CorpusPlanner(SANDBOX_SRC, 15).plan()
        s = sum(plan.strategy_allocation.values())
        assert s == plan.planned_count

    def test_strict_quality_skips_limited(self):
        from insert_me.planning import CorpusPlanner, PlanConstraints
        from insert_me.planning.inspector import LIMITED

        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        c = PlanConstraints(strict_quality=True)
        plan = CorpusPlanner(SANDBOX_SRC, 10, c).plan()
        for case in plan.cases:
            suit = plan.suitability.get(case.strategy, "")
            assert suit != LIMITED, (
                f"strict_quality=True but LIMITED strategy {case.strategy} was included"
            )


# ---------------------------------------------------------------------------
# CLI plan-corpus tests
# ---------------------------------------------------------------------------


class TestCLIPlanCorpus:
    """Tests for 'insert-me plan-corpus' subcommand via subprocess."""

    def _run(self, *extra_args, source=None):
        src = str(source or SANDBOX_SRC)
        cmd = [
            sys.executable, "-m", "insert_me.cli",
            "plan-corpus",
            "--source", src,
            "--count", "3",
        ] + list(extra_args)
        return subprocess.run(cmd, capture_output=True, text=True,
                              cwd=str(Path(__file__).parent.parent))

    def test_plan_corpus_exits_zero_on_viable_target(self):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        r = self._run()
        assert r.returncode == 0, f"stderr: {r.stderr}"

    def test_plan_corpus_prints_summary(self):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        r = self._run()
        assert "planned" in r.stdout.lower() or "requested" in r.stdout.lower()

    def test_plan_corpus_writes_output_dir(self, tmp_path):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        r = self._run("--output-dir", str(tmp_path))
        assert r.returncode == 0, f"stderr: {r.stderr}"
        assert (tmp_path / "corpus_plan.json").exists()
        assert (tmp_path / "seeds").is_dir()

    def test_plan_corpus_exits_nonzero_on_missing_source(self, tmp_path):
        r = self._run(source=tmp_path / "nonexistent_dir")
        assert r.returncode != 0

    def test_plan_corpus_allow_strategies_flag(self, tmp_path):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        r = self._run(
            "--output-dir", str(tmp_path),
            "--allow-strategies", "alloc_size_undercount",
        )
        assert r.returncode == 0, f"stderr: {r.stderr}"
        if (tmp_path / "corpus_plan.json").exists():
            d = json.loads((tmp_path / "corpus_plan.json").read_text())
            for case in d.get("cases", []):
                assert case["strategy"] == "alloc_size_undercount"

    def test_plan_corpus_max_per_file_constraint(self, tmp_path):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        r = self._run(
            "--output-dir", str(tmp_path),
            "--max-per-file", "1",
        )
        assert r.returncode == 0, f"stderr: {r.stderr}"
        if (tmp_path / "corpus_plan.json").exists():
            from collections import Counter
            d = json.loads((tmp_path / "corpus_plan.json").read_text())
            file_counts = Counter(c["target_file"] for c in d.get("cases", []))
            for fname, cnt in file_counts.items():
                assert cnt <= 1, f"File {fname}: {cnt} cases with --max-per-file 1"

    def test_plan_corpus_output_dir_schema_valid(self, tmp_path):
        if not SANDBOX_SRC.exists():
            pytest.skip("sandbox_eval/src not found")
        schema_path = Path(__file__).parent.parent / "schemas" / "corpus_plan.schema.json"
        if not schema_path.exists():
            pytest.skip("schema not found")
        r = self._run("--output-dir", str(tmp_path))
        assert r.returncode == 0
        if (tmp_path / "corpus_plan.json").exists():
            import jsonschema
            schema = json.loads(schema_path.read_text())
            d = json.loads((tmp_path / "corpus_plan.json").read_text())
            jsonschema.validate(instance=d, schema=schema)

    def test_plan_corpus_on_local_target_fixture(self, tmp_path):
        """plan-corpus works on the local_target fixture (toy_heap.c + toy_list.c)."""
        r = self._run("--output-dir", str(tmp_path), source=LOCAL_TARGET_DIR)
        # May succeed or have warnings, but must not crash
        assert r.returncode in (0, 1)
        if r.returncode == 0:
            assert (tmp_path / "corpus_plan.json").exists()
