"""
CorpusPlanner — target-aware corpus planning and seed synthesis orchestration.

Given a local evaluation-only C/C++ source tree and a requested case count,
CorpusPlanner:

  1. Runs TargetInspector to enumerate all candidates and assess suitability.
  2. Determines which corpus-admitted strategies are VIABLE or LIMITED.
  3. Allocates the requested count across viable strategies, respecting
     per-file and per-function diversity constraints.
  4. Calls SeedSynthesizer to produce concrete (seed_integer, file, line) tuples.
  5. Returns a CorpusPlan containing PlanCase entries and can write:
       - corpus_plan.json
       - seeds/<case_id>.json  (one per planned case)

Allocation algorithm
--------------------
1. Strategies with suitability VIABLE get priority allocation.
2. Strategies with suitability LIMITED get a reduced allocation (up to
   their actual candidate count).
3. If VIABLE strategies cannot reach the requested count, LIMITED strategies
   fill the gap.
4. If total achievable < requested_count, the plan reports the shortfall
   honestly rather than inflating the count.

Reproducibility
---------------
Same source tree + same requested_count + same PlanConstraints => same plan.
The plan is deterministic because:
  - TargetInspector uses the Seeder with seed=1 (fixed).
  - SeedSynthesizer sweeps seed integers 1..N in fixed order.
  - Allocation decisions are deterministic given the above.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inspector import TargetInspector, InspectionResult, VIABLE, LIMITED, BLOCKED
from .seed_synthesis import SeedSynthesizer, SweepConstraints, SynthesizedCase


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------

@dataclass
class PlanConstraints:
    """User-facing planning constraints."""
    max_per_file: int = 5
    max_per_function: int = 2
    max_per_family: int | None = None          # per strategy name cap
    allow_strategies: list[str] | None = None  # whitelist; None = all admitted
    disallow_strategies: list[str] | None = None
    min_candidate_score: float = 0.0
    strict_quality: bool = False               # if True, skip LIMITED strategies

    def to_dict(self) -> dict:
        return {
            "max_per_file": self.max_per_file,
            "max_per_function": self.max_per_function,
            "max_per_family": self.max_per_family,
            "allow_strategies": self.allow_strategies,
            "disallow_strategies": self.disallow_strategies,
            "min_candidate_score": self.min_candidate_score,
            "strict_quality": self.strict_quality,
        }


@dataclass
class PlanCase:
    """One planned vulnerability insertion case."""
    case_id: str
    strategy: str
    cwe_id: str
    seed_integer: int
    target_file: str
    target_line: int
    function_name: str
    candidate_score: float
    confidence: str    # "high" (score >= 0.7) | "medium" | "low"
    seed_file: str     # relative path within plan output directory

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "strategy": self.strategy,
            "cwe_id": self.cwe_id,
            "seed_integer": self.seed_integer,
            "target_file": self.target_file,
            "target_line": self.target_line,
            "function_name": self.function_name,
            "candidate_score": round(self.candidate_score, 3),
            "confidence": self.confidence,
            "seed_file": self.seed_file,
        }


@dataclass
class CorpusPlan:
    """
    The complete planning result.

    Holds the allocation, per-case synthesis details, and can serialise
    itself to corpus_plan.json + individual seed files.
    """
    source_root: str
    source_hash: str
    requested_count: int
    planned_count: int
    projected_accepted_count: int   # based on strategy quality_gate_pass_rate
    constraints: PlanConstraints
    strategy_allocation: dict[str, int]   # strategy -> planned count
    suitability: dict[str, str]           # strategy -> VIABLE/LIMITED/BLOCKED/EXPERIMENTAL
    cases: list[PlanCase]
    blockers: list[str]
    warnings: list[str]

    def to_dict(self) -> dict:
        by_strategy: dict[str, int] = {}
        by_file: dict[str, int] = {}
        for c in self.cases:
            by_strategy[c.strategy] = by_strategy.get(c.strategy, 0) + 1
            by_file[c.target_file] = by_file.get(c.target_file, 0) + 1

        return {
            "schema_version": "1.0",
            "source_root": self.source_root,
            "source_hash": self.source_hash,
            "requested_count": self.requested_count,
            "planned_count": self.planned_count,
            "projected_accepted_count": self.projected_accepted_count,
            "constraints": self.constraints.to_dict(),
            "strategy_allocation": self.strategy_allocation,
            "suitability": self.suitability,
            "cases": [c.to_dict() for c in self.cases],
            "allocation_summary": {
                "by_strategy": by_strategy,
                "by_file": by_file,
                "blockers": self.blockers,
                "warnings": self.warnings,
            },
        }

    def write(self, output_dir: Path) -> None:
        """
        Write corpus_plan.json and one seed file per planned case.

        Directory layout::

            <output_dir>/
                corpus_plan.json
                seeds/
                    cwe416_plan_001.json
                    cwe122_plan_002.json
                    ...
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        seeds_dir = output_dir / "seeds"
        seeds_dir.mkdir(exist_ok=True)

        # Update seed_file paths to be relative to output_dir
        plan_dict = self.to_dict()
        for case_d, case_obj in zip(plan_dict["cases"], self.cases):
            seed_path = seeds_dir / f"{case_obj.case_id}.json"
            rel = str(seed_path.relative_to(output_dir))
            case_d["seed_file"] = rel
            seed_dict = SynthesizedCase(
                case_id=case_obj.case_id,
                strategy=case_obj.strategy,
                cwe_id=case_obj.cwe_id,
                seed_integer=case_obj.seed_integer,
                target_file=case_obj.target_file,
                target_line=case_obj.target_line,
                function_name=case_obj.function_name,
                candidate_score=case_obj.candidate_score,
                pattern_type=_STRATEGY_PATTERN_TYPE[case_obj.strategy],
            ).to_seed_dict(source_root=self.source_root)
            seed_path.write_text(json.dumps(seed_dict, indent=2), encoding="utf-8")

        # Write corpus_plan.json
        plan_path = output_dir / "corpus_plan.json"
        plan_path.write_text(json.dumps(plan_dict, indent=2), encoding="utf-8")


_STRATEGY_PATTERN_TYPE: dict[str, str] = {
    "alloc_size_undercount": "malloc_call",
    "insert_premature_free": "pointer_deref",
    "insert_double_free":    "free_call",
    "remove_free_call":      "free_call",
    "remove_null_guard":     "null_guard",
}

# Quality gate pass rate priors from the strategy catalog
_STRATEGY_PASS_RATE: dict[str, float] = {
    "alloc_size_undercount": 1.00,
    "insert_premature_free": 1.00,
    "insert_double_free":    0.90,
    "remove_free_call":      0.90,
    "remove_null_guard":     0.50,   # experimental; low confidence
}


# ---------------------------------------------------------------------------
# CorpusPlanner
# ---------------------------------------------------------------------------

class CorpusPlanner:
    """
    Target-aware corpus planner.

    Usage::

        planner = CorpusPlanner(
            source_root=Path("/path/to/project"),
            requested_count=30,
            constraints=PlanConstraints(max_per_file=5),
        )
        plan = planner.plan()
        plan.write(Path("plan_out/"))
    """

    def __init__(
        self,
        source_root: Path,
        requested_count: int,
        constraints: PlanConstraints | None = None,
    ) -> None:
        self._source_root = source_root
        self._requested = requested_count
        self._constraints = constraints or PlanConstraints()

    def plan(self) -> CorpusPlan:
        """Run inspection, allocation, and synthesis.  Returns CorpusPlan."""
        from .inspector import PLANNING_STRATEGIES

        c = self._constraints

        # --- 1. Inspect target ---
        inspector = TargetInspector(self._source_root)
        inspection = inspector.run()

        # --- 2. Determine eligible strategies ---
        eligible: list[tuple[str, str, str]] = []  # (name, cwe_id, pattern_type)
        suitability_map: dict[str, str] = {}

        for strategy_name, cwe_id, pattern_type, corpus_admitted in PLANNING_STRATEGIES:
            s = inspection.strategies.get(strategy_name)
            suit = s.suitability if s else BLOCKED
            suitability_map[strategy_name] = suit

            if not corpus_admitted:
                continue
            if c.allow_strategies and strategy_name not in c.allow_strategies:
                continue
            if c.disallow_strategies and strategy_name in c.disallow_strategies:
                continue
            if suit == BLOCKED:
                continue
            if c.strict_quality and suit != VIABLE:
                continue
            eligible.append((strategy_name, cwe_id, pattern_type))

        blockers: list[str] = []
        warnings: list[str] = []

        if not eligible:
            blockers.append(
                "No corpus-admitted strategies have viable candidates in this target. "
                "Run inspect-target for details."
            )
            return CorpusPlan(
                source_root=str(self._source_root.resolve()),
                source_hash=inspection.source_hash,
                requested_count=self._requested,
                planned_count=0,
                projected_accepted_count=0,
                constraints=c,
                strategy_allocation={},
                suitability=suitability_map,
                cases=[],
                blockers=blockers,
                warnings=warnings,
            )

        # --- 3. Compute per-strategy allocation ---
        allocation = self._allocate(eligible, inspection, c)

        # --- 4. Synthesise seeds ---
        sweep_c = SweepConstraints(
            max_per_file=c.max_per_file,
            max_per_function=c.max_per_function,
            min_candidate_score=c.min_candidate_score,
        )
        synthesizer = SeedSynthesizer(self._source_root, sweep_c)
        seen_targets: set[tuple[str, int]] = set()
        all_cases: list[PlanCase] = []
        case_counter = 1

        for strategy_name, cwe_id, pattern_type in eligible:
            count = allocation.get(strategy_name, 0)
            if count == 0:
                continue

            result = synthesizer.synthesize_for_strategy(
                strategy=strategy_name,
                cwe_id=cwe_id,
                pattern_type=pattern_type,
                requested_count=count,
                seen_targets=seen_targets,
                case_id_prefix="plan",
                case_id_start=case_counter,
            )
            if result.warning:
                warnings.append(result.warning)

            for sc in result.cases:
                conf = "high" if sc.candidate_score >= 0.70 else (
                    "medium" if sc.candidate_score >= 0.40 else "low"
                )
                all_cases.append(PlanCase(
                    case_id=sc.case_id,
                    strategy=sc.strategy,
                    cwe_id=sc.cwe_id,
                    seed_integer=sc.seed_integer,
                    target_file=sc.target_file,
                    target_line=sc.target_line,
                    function_name=sc.function_name,
                    candidate_score=sc.candidate_score,
                    confidence=conf,
                    seed_file=f"seeds/{sc.case_id}.json",
                ))
                case_counter += 1

        planned = len(all_cases)
        if planned < self._requested:
            warnings.append(
                f"Only {planned} cases planned (requested {self._requested}): "
                "the target does not have sufficient diverse candidates to reach "
                "the requested count at current quality constraints. "
                "Consider: adding more source files, relaxing --max-per-file, "
                "or lowering --count."
            )

        # Projected accepted count (apply strategy-specific pass rate priors)
        projected = sum(
            int(round(_STRATEGY_PASS_RATE.get(c2.strategy, 0.8)))
            for c2 in all_cases
        )
        # More accurate: weighted sum
        projected = round(sum(
            _STRATEGY_PASS_RATE.get(c2.strategy, 0.8) for c2 in all_cases
        ))

        final_allocation = {
            s: sum(1 for c2 in all_cases if c2.strategy == s)
            for s, _, _ in eligible
        }

        return CorpusPlan(
            source_root=str(self._source_root.resolve()),
            source_hash=inspection.source_hash,
            requested_count=self._requested,
            planned_count=planned,
            projected_accepted_count=projected,
            constraints=c,
            strategy_allocation=final_allocation,
            suitability=suitability_map,
            cases=all_cases,
            blockers=blockers,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Allocation helpers
    # ------------------------------------------------------------------

    def _allocate(
        self,
        eligible: list[tuple[str, str, str]],
        inspection: InspectionResult,
        c: PlanConstraints,
    ) -> dict[str, int]:
        """
        Distribute *requested_count* across eligible strategies.

        Priority: VIABLE > LIMITED.  Within priority tier, weight by
        available candidate count (capped at max_per_family if set).
        """
        viable = [
            (n, cid, pt) for n, cid, pt in eligible
            if inspection.strategies.get(n) and
               inspection.strategies[n].suitability == VIABLE
        ]
        limited = [
            (n, cid, pt) for n, cid, pt in eligible
            if (n, cid, pt) not in viable
        ]

        allocation: dict[str, int] = {}
        remaining = self._requested

        # Fill VIABLE strategies first (proportional to candidate count)
        remaining = self._fill_tier(
            viable, inspection, c, remaining, allocation
        )
        # Then LIMITED strategies if VIABLE didn't exhaust the count
        if remaining > 0:
            remaining = self._fill_tier(
                limited, inspection, c, remaining, allocation
            )

        return allocation

    def _fill_tier(
        self,
        tier: list[tuple[str, str, str]],
        inspection: InspectionResult,
        c: PlanConstraints,
        remaining: int,
        allocation: dict[str, int],
    ) -> int:
        if not tier or remaining <= 0:
            return remaining

        # Compute capacity for each strategy in this tier
        caps: dict[str, int] = {}
        for name, _, _ in tier:
            s = inspection.strategies.get(name)
            if not s:
                caps[name] = 0
                continue
            # Capacity = min(diverse candidates, max_per_family)
            file_capped = sum(min(v, c.max_per_file) for v in s.by_file.values())
            cap = file_capped
            if c.max_per_family is not None:
                cap = min(cap, c.max_per_family)
            caps[name] = max(0, cap)

        total_capacity = sum(caps.values())
        if total_capacity == 0:
            return remaining

        # Distribute proportionally; clamp total to avoid over-allocation.
        base = min(remaining, total_capacity)
        names_in_tier = [n for n, _, _ in tier]
        raw: dict[str, int] = {}
        for name in names_in_tier:
            if total_capacity > 0:
                share = int(base * caps[name] / total_capacity)
            else:
                share = 0
            raw[name] = min(share, caps[name])

        # Distribute leftover (due to int truncation) to highest-capacity strategies
        assigned = sum(raw.values())
        leftover = base - assigned
        sorted_by_cap = sorted(names_in_tier, key=lambda n: caps[n], reverse=True)
        for name in sorted_by_cap:
            if leftover <= 0:
                break
            extra = min(leftover, caps[name] - raw[name])
            raw[name] += extra
            leftover -= extra

        for name in names_in_tier:
            allocation[name] = allocation.get(name, 0) + raw[name]

        used = sum(raw.values())
        return max(0, remaining - used)
