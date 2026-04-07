"""
PortfolioPlanner — multi-target corpus orchestration layer.

Given a list of evaluation-only C/C++ target roots and a requested global count,
PortfolioPlanner:

  1. Inspects each target (via TargetInspector) to assess per-strategy suitability.
  2. Computes each target's effective capacity: sum of per-file-capped candidate
     counts across VIABLE/LIMITED corpus-admitted strategies, capped at
     max_per_target.
  3. Allocates the global count proportionally to effective capacity.
  4. Runs CorpusPlanner for each target with its sub-allocation.
  5. Merges all cases into a global pool.
  6. Applies global diversity selection (max_per_target, max_per_strategy_global).
  7. Reports shortfall with machine-readable categories.

Allocation algorithm
--------------------
- VIABLE strategies contribute full file-capped capacity.
- LIMITED strategies contribute half capacity (rounded up).
- BLOCKED strategies contribute 0.
- Sub-allocations are integer-proportional with remainder distributed by
  highest fractional part, then highest capacity (deterministic tie-break).
- Global selection is a greedy pass over candidates sorted by:
    (suitability_weight DESC, candidate_score DESC,
     target_name ASC, strategy ASC, seed_integer ASC)
  respecting max_per_target and max_per_strategy_global hard limits.

Reproducibility
---------------
Same targets list (same names + resolved paths) + same requested_count +
same PortfolioConstraints => same portfolio_plan.json (byte-identical).
Targets are processed in lexicographic order by name.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .corpus_planner import (
    CorpusPlanner,
    CorpusPlan,
    PlanCase,
    PlanConstraints,
    _STRATEGY_PASS_RATE,
)
from .inspector import (
    TargetInspector,
    InspectionResult,
    VIABLE,
    LIMITED,
    BLOCKED,
    EXPERIMENTAL,
)


# ---------------------------------------------------------------------------
# Shortfall category keys (machine-readable)
# ---------------------------------------------------------------------------

CAT_TARGET_CAPACITY      = "target_capacity_limit"
CAT_STRATEGY_BLOCKED     = "strategy_blocked_no_candidates"
CAT_DIVERSITY_TARGET     = "global_diversity_constraint_per_target"
CAT_DIVERSITY_STRATEGY   = "global_diversity_constraint_per_strategy"
CAT_NO_VIABLE_TARGETS    = "no_viable_targets"
CAT_EXPERIMENTAL         = "experimental_strategy_excluded"
CAT_SWEEP_EXHAUSTED      = "sweep_exhausted"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PortfolioConstraints:
    """
    Controls allocation and diversity in a multi-target corpus plan.

    Hard limits (enforced during selection):
    - max_per_target: no more than this many cases from any one target.
    - max_per_strategy_global: no more than this many cases of any one strategy.

    Soft signals (generate warnings in the plan but do not block selection):
    - max_per_target_fraction: warn if >X% of cases come from one target.
    - max_per_strategy_fraction: warn if >X% of cases are one strategy.

    Per-target planning limits (forwarded to each CorpusPlanner):
    - max_per_file, max_per_function, min_candidate_score, strict_quality.
    """
    max_per_target: int = 20
    max_per_target_fraction: float = 0.6
    max_per_strategy_global: int = 20
    max_per_strategy_fraction: float = 0.5
    max_per_file: int = 5
    max_per_function: int = 2
    min_candidate_score: float = 0.0
    strict_quality: bool = False

    def to_dict(self) -> dict:
        return {
            "max_per_target": self.max_per_target,
            "max_per_target_fraction": self.max_per_target_fraction,
            "max_per_strategy_global": self.max_per_strategy_global,
            "max_per_strategy_fraction": self.max_per_strategy_fraction,
            "max_per_file": self.max_per_file,
            "max_per_function": self.max_per_function,
            "min_candidate_score": self.min_candidate_score,
            "strict_quality": self.strict_quality,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PortfolioConstraints":
        return cls(
            max_per_target=d.get("max_per_target", 20),
            max_per_target_fraction=d.get("max_per_target_fraction", 0.6),
            max_per_strategy_global=d.get("max_per_strategy_global", 20),
            max_per_strategy_fraction=d.get("max_per_strategy_fraction", 0.5),
            max_per_file=d.get("max_per_file", 5),
            max_per_function=d.get("max_per_function", 2),
            min_candidate_score=d.get("min_candidate_score", 0.0),
            strict_quality=d.get("strict_quality", False),
        )


@dataclass
class PortfolioTarget:
    """A single evaluation-only target in a portfolio targets file."""
    name: str
    path: str   # as given (relative or absolute); resolved to absolute internally


@dataclass
class PortfolioEntry:
    """One planned vulnerability insertion case in a portfolio."""
    case_id: str
    strategy: str
    cwe_id: str
    seed_integer: int
    target_name: str
    target_path: str    # absolute path to the source root
    target_file: str    # relative to target_path
    target_line: int
    function_name: str
    candidate_score: float
    confidence: str     # "high" | "medium" | "low"

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "strategy": self.strategy,
            "cwe_id": self.cwe_id,
            "seed_integer": self.seed_integer,
            "target_name": self.target_name,
            "target_path": self.target_path,
            "target_file": self.target_file,
            "target_line": self.target_line,
            "function_name": self.function_name,
            "candidate_score": round(self.candidate_score, 3),
            "confidence": self.confidence,
        }


@dataclass
class PortfolioTargetSummary:
    """Per-target planning summary stored in portfolio_plan.json."""
    name: str
    path: str           # absolute
    source_hash: str
    effective_capacity: int
    allocated_count: int
    planned_count: int
    suitability: dict[str, str]     # strategy → VIABLE/LIMITED/BLOCKED/EXPERIMENTAL
    viable_strategies: list[str]
    limited_strategies: list[str]
    blocked_strategies: list[str]
    sub_plan_path: str              # relative path to targets/<name>/_plan/corpus_plan.json
    blockers: list[str]
    warnings: list[str]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "source_hash": self.source_hash,
            "effective_capacity": self.effective_capacity,
            "allocated_count": self.allocated_count,
            "planned_count": self.planned_count,
            "suitability": self.suitability,
            "viable_strategies": self.viable_strategies,
            "limited_strategies": self.limited_strategies,
            "blocked_strategies": self.blocked_strategies,
            "sub_plan_path": self.sub_plan_path,
            "blockers": self.blockers,
            "warnings": self.warnings,
        }


@dataclass
class PortfolioPlan:
    """
    Complete multi-target corpus plan.

    Produced by PortfolioPlanner.plan().  Can be serialised to
    portfolio_plan.json and replayed via generate-portfolio --from-plan.
    """
    schema_version: str
    portfolio_id: str
    targets_hash: str
    requested_count: int
    planned_count: int
    projected_accepted_count: int
    constraints: PortfolioConstraints
    target_summaries: list[PortfolioTargetSummary]
    entries: list[PortfolioEntry]
    global_strategy_allocation: dict[str, int]
    shortfall: dict[str, Any]   # {count, categories, notes}
    fingerprint: str
    warnings: list[str]
    blockers: list[str]

    # ---------------------------------------------------------------------------
    # Serialisation
    # ---------------------------------------------------------------------------

    def to_dict(self) -> dict:
        by_strategy: dict[str, int] = {}
        by_target: dict[str, int] = {}
        for e in self.entries:
            by_strategy[e.strategy] = by_strategy.get(e.strategy, 0) + 1
            by_target[e.target_name] = by_target.get(e.target_name, 0) + 1

        return {
            "schema_version": self.schema_version,
            "schema": "portfolio_plan",
            "portfolio_id": self.portfolio_id,
            "targets_hash": self.targets_hash,
            "requested_count": self.requested_count,
            "planned_count": self.planned_count,
            "projected_accepted_count": self.projected_accepted_count,
            "constraints": self.constraints.to_dict(),
            "target_summaries": [ts.to_dict() for ts in self.target_summaries],
            "entries": [e.to_dict() for e in self.entries],
            "global_strategy_allocation": self.global_strategy_allocation,
            "allocation_summary": {
                "by_strategy": by_strategy,
                "by_target": by_target,
            },
            "shortfall": self.shortfall,
            "fingerprint": self.fingerprint,
            "warnings": self.warnings,
            "blockers": self.blockers,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PortfolioPlan":
        """Deserialise portfolio_plan.json for replay."""
        constraints = PortfolioConstraints.from_dict(d.get("constraints", {}))
        target_summaries = [
            PortfolioTargetSummary(
                name=ts["name"],
                path=ts["path"],
                source_hash=ts.get("source_hash", ""),
                effective_capacity=ts.get("effective_capacity", 0),
                allocated_count=ts.get("allocated_count", 0),
                planned_count=ts.get("planned_count", 0),
                suitability=ts.get("suitability", {}),
                viable_strategies=ts.get("viable_strategies", []),
                limited_strategies=ts.get("limited_strategies", []),
                blocked_strategies=ts.get("blocked_strategies", []),
                sub_plan_path=ts.get("sub_plan_path", ""),
                blockers=ts.get("blockers", []),
                warnings=ts.get("warnings", []),
            )
            for ts in d.get("target_summaries", [])
        ]
        entries = [
            PortfolioEntry(
                case_id=e["case_id"],
                strategy=e["strategy"],
                cwe_id=e["cwe_id"],
                seed_integer=e["seed_integer"],
                target_name=e["target_name"],
                target_path=e["target_path"],
                target_file=e["target_file"],
                target_line=e["target_line"],
                function_name=e.get("function_name", ""),
                candidate_score=e["candidate_score"],
                confidence=e.get("confidence", "medium"),
            )
            for e in d.get("entries", [])
        ]
        return cls(
            schema_version=d.get("schema_version", "1.0"),
            portfolio_id=d.get("portfolio_id", ""),
            targets_hash=d.get("targets_hash", ""),
            requested_count=d["requested_count"],
            planned_count=d["planned_count"],
            projected_accepted_count=d.get("projected_accepted_count", 0),
            constraints=constraints,
            target_summaries=target_summaries,
            entries=entries,
            global_strategy_allocation=d.get("global_strategy_allocation", {}),
            shortfall=d.get("shortfall", {}),
            fingerprint=d.get("fingerprint", ""),
            warnings=d.get("warnings", []),
            blockers=d.get("blockers", []),
        )

    # ---------------------------------------------------------------------------
    # Writing
    # ---------------------------------------------------------------------------

    def write(
        self,
        output_dir: Path,
        per_target_plans: dict[str, CorpusPlan],
    ) -> None:
        """
        Write portfolio_plan.json and per-target sub-plans.

        Directory layout::

            <output_dir>/
                portfolio_plan.json
                targets/
                    <name>/
                        _plan/
                            corpus_plan.json
                            seeds/
                                <case_id>.json
                                ...
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        targets_root = output_dir / "targets"

        # Write per-target sub-plans and update sub_plan_path in summaries
        plan_dict = self.to_dict()
        for ts_dict, ts_obj in zip(
            plan_dict["target_summaries"], self.target_summaries
        ):
            target_plan = per_target_plans.get(ts_obj.name)
            if target_plan is None:
                continue
            sub_dir = targets_root / ts_obj.name / "_plan"
            target_plan.write(sub_dir)
            rel = str((sub_dir / "corpus_plan.json").relative_to(output_dir))
            ts_dict["sub_plan_path"] = rel
            ts_obj.sub_plan_path = rel

        # Re-serialise with updated sub_plan_path values
        plan_dict = self.to_dict()
        (output_dir / "portfolio_plan.json").write_text(
            json.dumps(plan_dict, indent=2), encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# PortfolioPlanner
# ---------------------------------------------------------------------------

class PortfolioPlanner:
    """
    Multi-target corpus planner.

    Usage::

        planner = PortfolioPlanner(
            targets=[
                PortfolioTarget(name="sandbox_eval", path="examples/sandbox_eval/src"),
                PortfolioTarget(name="target_b", path="examples/sandbox_targets/target_b/src"),
            ],
            requested_count=20,
        )
        portfolio_plan, per_target_plans = planner.plan()
        portfolio_plan.write(Path("portfolio_out"), per_target_plans)
    """

    def __init__(
        self,
        targets: list[PortfolioTarget],
        requested_count: int,
        constraints: PortfolioConstraints | None = None,
    ) -> None:
        self._targets = targets
        self._requested = requested_count
        self._constraints = constraints or PortfolioConstraints()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def plan(self) -> tuple["PortfolioPlan", dict[str, CorpusPlan]]:
        """
        Run inspection, allocation, and per-target synthesis.

        Returns
        -------
        (PortfolioPlan, {target_name: CorpusPlan})
        """
        c = self._constraints
        blockers: list[str] = []
        warnings: list[str] = []

        if not self._targets:
            empty_plan = _empty_portfolio_plan(self._requested, c, "No targets specified.")
            return empty_plan, {}

        # Sort targets by name for determinism
        sorted_targets = sorted(self._targets, key=lambda t: t.name)

        # --- 1. Inspect each target ---
        resolved: list[tuple[str, Path]] = []
        for tgt in sorted_targets:
            p = Path(tgt.path).resolve()
            resolved.append((tgt.name, p))

        targets_hash = _targets_hash(resolved)

        inspections: dict[str, InspectionResult] = {}
        caps: dict[str, int] = {}

        for name, path in resolved:
            if not path.exists() or not path.is_dir():
                blockers.append(
                    f"Target '{name}' path not found or not a directory: {path}"
                )
                caps[name] = 0
                continue
            insp = TargetInspector(path).run()
            inspections[name] = insp
            caps[name] = _effective_capacity(insp, c)

        if blockers:
            empty = _empty_portfolio_plan(
                self._requested, c, blockers[0], targets_hash=targets_hash
            )
            empty.blockers = blockers
            return empty, {}

        # --- 2. Check if any target is viable at all ---
        if all(v == 0 for v in caps.values()):
            msg = (
                "No viable candidates found across all targets for any corpus-admitted "
                "strategy. Run inspect-target on each target for details."
            )
            blockers.append(msg)
            tgt_summaries = _make_target_summaries(resolved, inspections, caps, {}, {})
            empty = _empty_portfolio_plan(
                self._requested, c, msg, targets_hash=targets_hash,
                target_summaries=tgt_summaries,
            )
            empty.blockers = blockers
            return empty, {}

        # --- 3. Allocate global count across targets ---
        per_target_allocation = _allocate_proportional(caps, self._requested)

        # --- 4. Run CorpusPlanner for each target ---
        per_target_plans: dict[str, CorpusPlan] = {}
        all_entries: list[PortfolioEntry] = []

        for name, path in resolved:
            alloc = per_target_allocation.get(name, 0)
            if alloc == 0:
                per_target_plans[name] = _empty_corpus_plan_for(name, path, inspections.get(name))
                continue

            plan_c = PlanConstraints(
                max_per_file=c.max_per_file,
                max_per_function=c.max_per_function,
                min_candidate_score=c.min_candidate_score,
                strict_quality=c.strict_quality,
            )
            # Use target name (sanitised) as case_id_prefix for unique IDs
            prefix = _sanitise_name(name)
            tp = CorpusPlanner(
                source_root=path,
                requested_count=alloc,
                constraints=plan_c,
                case_id_prefix=prefix,
            ).plan()
            per_target_plans[name] = tp

            if tp.warnings:
                for w in tp.warnings:
                    warnings.append(f"[{name}] {w}")
            if tp.blockers:
                for b in tp.blockers:
                    warnings.append(f"[{name}] blocker: {b}")

            insp = inspections.get(name)
            for case in tp.cases:
                suit_weight = _suitability_weight(
                    insp, case.strategy if insp else BLOCKED
                )
                all_entries.append(PortfolioEntry(
                    case_id=case.case_id,
                    strategy=case.strategy,
                    cwe_id=case.cwe_id,
                    seed_integer=case.seed_integer,
                    target_name=name,
                    target_path=str(path),
                    target_file=case.target_file,
                    target_line=case.target_line,
                    function_name=case.function_name,
                    candidate_score=case.candidate_score,
                    confidence=case.confidence,
                ))

        # --- 5. Global diversity selection ---
        selected, skipped_target, skipped_strategy = _select_global(
            all_entries, self._requested, c, inspections
        )

        # --- 6. Warn on concentration ---
        total_selected = len(selected)
        if total_selected > 0:
            per_target_counts: dict[str, int] = {}
            per_strategy_counts: dict[str, int] = {}
            for e in selected:
                per_target_counts[e.target_name] = per_target_counts.get(e.target_name, 0) + 1
                per_strategy_counts[e.strategy] = per_strategy_counts.get(e.strategy, 0) + 1
            for tname, cnt in per_target_counts.items():
                frac = cnt / total_selected
                if frac > c.max_per_target_fraction:
                    warnings.append(
                        f"{cnt}/{total_selected} cases ({frac:.0%}) come from target "
                        f"'{tname}' (threshold {c.max_per_target_fraction:.0%}). "
                        "Consider adding more targets."
                    )
            for strat, cnt in per_strategy_counts.items():
                frac = cnt / total_selected
                if frac > c.max_per_strategy_fraction:
                    warnings.append(
                        f"{cnt}/{total_selected} cases ({frac:.0%}) use strategy "
                        f"'{strat}' (threshold {c.max_per_strategy_fraction:.0%}). "
                        "Consider using more diverse targets."
                    )

        # --- 7. Shortfall diagnostics ---
        shortfall = _compute_shortfall(
            requested=self._requested,
            selected_count=len(selected),
            pool_size=len(all_entries),
            caps=caps,
            skipped_by_target=skipped_target,
            skipped_by_strategy=skipped_strategy,
            inspections=inspections,
        )

        if shortfall["count"] > 0:
            warnings.append(
                f"Only {len(selected)} cases planned (requested {self._requested}): "
                "see shortfall.categories for reasons."
            )

        # --- 8. Compute fingerprint ---
        global_alloc: dict[str, int] = {}
        for e in selected:
            global_alloc[e.strategy] = global_alloc.get(e.strategy, 0) + 1

        fingerprint = _portfolio_fingerprint(
            targets_hash=targets_hash,
            requested=self._requested,
            entries=selected,
        )
        portfolio_id = fingerprint

        # Projected accepted count
        projected = round(sum(
            _STRATEGY_PASS_RATE.get(e.strategy, 0.8) for e in selected
        ))

        # Per-target summaries
        target_summaries = _make_target_summaries(
            resolved, inspections, caps, per_target_allocation, per_target_plans
        )

        plan = PortfolioPlan(
            schema_version="1.0",
            portfolio_id=portfolio_id,
            targets_hash=targets_hash,
            requested_count=self._requested,
            planned_count=len(selected),
            projected_accepted_count=projected,
            constraints=c,
            target_summaries=target_summaries,
            entries=selected,
            global_strategy_allocation=global_alloc,
            shortfall=shortfall,
            fingerprint=fingerprint,
            warnings=warnings,
            blockers=blockers,
        )
        return plan, per_target_plans


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def load_targets_file(path: Path) -> list[PortfolioTarget]:
    """
    Parse a targets.json file and return a list of PortfolioTarget objects.

    Expected format::

        {
          "schema_version": "1.0",
          "targets": [
            {"name": "sandbox_eval", "path": "examples/sandbox_eval/src"},
            {"name": "target_b",     "path": "examples/sandbox_targets/target_b/src"}
          ]
        }

    Paths are interpreted relative to the directory containing targets.json.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    base = path.parent
    targets: list[PortfolioTarget] = []
    for entry in data.get("targets", []):
        raw_path = entry["path"]
        # Resolve relative to targets file location
        resolved = (base / raw_path).resolve()
        targets.append(PortfolioTarget(name=entry["name"], path=str(resolved)))
    return targets


def _targets_hash(resolved: list[tuple[str, Path]]) -> str:
    """Stable 16-char hex hash of the sorted (name, abs_path) pairs."""
    canonical = json.dumps(
        sorted([(name, str(p)) for name, p in resolved]),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()[:16]


def _effective_capacity(inspection: InspectionResult, c: PortfolioConstraints) -> int:
    """
    Estimate the maximum number of diverse cases this target can supply.

    VIABLE strategies contribute their full file-capped candidate count.
    LIMITED strategies contribute half (rounded up) of their file-capped count.
    BLOCKED / EXPERIMENTAL strategies contribute 0.
    Result is capped at max_per_target.
    """
    total = 0
    for strat_name, stats in inspection.strategies.items():
        if not stats.corpus_admitted:
            continue
        if stats.suitability == VIABLE:
            weight = 1.0
        elif stats.suitability == LIMITED:
            weight = 0.5
        else:
            continue

        file_capped = sum(min(v, c.max_per_file) for v in stats.by_file.values())
        total += int(file_capped * weight + 0.999)  # ceil for LIMITED

    return min(total, c.max_per_target)


def _allocate_proportional(caps: dict[str, int], budget: int) -> dict[str, int]:
    """
    Distribute *budget* across keys proportionally to their *caps*.

    - Never allocates more than cap[k] to any key k.
    - Total allocated <= budget.
    - Deterministic: names sorted lexicographically for tie-breaks.
    """
    names = sorted(caps.keys())
    total_cap = sum(caps[n] for n in names)
    if total_cap == 0 or budget <= 0:
        return {n: 0 for n in names}

    effective = min(budget, total_cap)
    alloc: dict[str, int] = {}

    # Floor-proportional
    for n in names:
        alloc[n] = min(int(effective * caps[n] / total_cap), caps[n])

    # Distribute leftover by highest fractional part (then highest cap for ties)
    assigned = sum(alloc.values())
    leftover = effective - assigned

    fracs = [
        (effective * caps[n] / total_cap - int(effective * caps[n] / total_cap), caps[n], n)
        for n in names
    ]
    fracs.sort(key=lambda x: (-x[0], -x[1], x[2]))

    for _, cap, n in fracs:
        if leftover <= 0:
            break
        extra = min(leftover, caps[n] - alloc[n])
        alloc[n] += extra
        leftover -= extra

    return alloc


def _suitability_weight(
    inspection: InspectionResult | None, strategy: str
) -> int:
    """Return 2 for VIABLE, 1 for LIMITED, 0 otherwise."""
    if inspection is None:
        return 0
    stats = inspection.strategies.get(strategy)
    if stats is None:
        return 0
    if stats.suitability == VIABLE:
        return 2
    if stats.suitability == LIMITED:
        return 1
    return 0


def _select_global(
    entries: list[PortfolioEntry],
    requested: int,
    c: PortfolioConstraints,
    inspections: dict[str, InspectionResult],
) -> tuple[list[PortfolioEntry], dict[str, int], dict[str, int]]:
    """
    Greedy global selection with per-target and per-strategy hard limits.

    Candidates are sorted by:
        (suitability_weight DESC, candidate_score DESC,
         target_name ASC, strategy ASC, seed_integer ASC)

    Returns
    -------
    (selected, skipped_by_target_limit, skipped_by_strategy_limit)
    """
    def sort_key(e: PortfolioEntry) -> tuple:
        sw = _suitability_weight(inspections.get(e.target_name), e.strategy)
        return (-sw, -e.candidate_score, e.target_name, e.strategy, e.seed_integer)

    sorted_entries = sorted(entries, key=sort_key)

    selected: list[PortfolioEntry] = []
    per_target: dict[str, int] = {}
    per_strategy: dict[str, int] = {}
    skipped_target: dict[str, int] = {}
    skipped_strategy: dict[str, int] = {}

    for e in sorted_entries:
        if len(selected) >= requested:
            break

        t_cnt = per_target.get(e.target_name, 0)
        s_cnt = per_strategy.get(e.strategy, 0)

        if t_cnt >= c.max_per_target:
            skipped_target[e.target_name] = skipped_target.get(e.target_name, 0) + 1
            continue
        if s_cnt >= c.max_per_strategy_global:
            skipped_strategy[e.strategy] = skipped_strategy.get(e.strategy, 0) + 1
            continue

        selected.append(e)
        per_target[e.target_name] = t_cnt + 1
        per_strategy[e.strategy] = s_cnt + 1

    return selected, skipped_target, skipped_strategy


def _compute_shortfall(
    requested: int,
    selected_count: int,
    pool_size: int,
    caps: dict[str, int],
    skipped_by_target: dict[str, int],
    skipped_by_strategy: dict[str, int],
    inspections: dict[str, InspectionResult],
) -> dict[str, Any]:
    """Attribute shortfall between requested and selected to machine-readable categories."""
    shortfall_count = max(0, requested - selected_count)
    categories: dict[str, int] = {}
    notes: list[str] = []

    if shortfall_count == 0:
        return {"count": 0, "categories": {}, "notes": []}

    # Pool too small for the requested count
    if pool_size < requested:
        deficit = requested - pool_size
        categories[CAT_TARGET_CAPACITY] = deficit
        notes.append(
            f"Total planned pool ({pool_size} cases across all targets) is smaller "
            f"than requested ({requested})."
        )

    # Diversity limits caused skips
    total_target_skip = sum(skipped_by_target.values())
    total_strategy_skip = sum(skipped_by_strategy.values())
    if total_target_skip > 0:
        categories[CAT_DIVERSITY_TARGET] = total_target_skip
        notes.append(
            f"max_per_target limit skipped {total_target_skip} candidate(s): "
            + ", ".join(f"{k}={v}" for k, v in sorted(skipped_by_target.items()))
        )
    if total_strategy_skip > 0:
        categories[CAT_DIVERSITY_STRATEGY] = total_strategy_skip
        notes.append(
            f"max_per_strategy_global limit skipped {total_strategy_skip} candidate(s): "
            + ", ".join(f"{k}={v}" for k, v in sorted(skipped_by_strategy.items()))
        )

    # Blocked targets (zero capacity)
    blocked_targets = [n for n, cap in sorted(caps.items()) if cap == 0]
    if blocked_targets:
        categories[CAT_STRATEGY_BLOCKED] = len(blocked_targets)
        notes.append(
            f"Targets with no viable candidates: {', '.join(blocked_targets)}."
        )

    # Experimental strategies excluded
    exp_strategies: list[str] = []
    for name, insp in sorted(inspections.items()):
        for s, stats in sorted(insp.strategies.items()):
            if stats.suitability == EXPERIMENTAL and stats.total_candidates > 0:
                exp_strategies.append(f"{name}/{s}")
    if exp_strategies:
        categories[CAT_EXPERIMENTAL] = len(set(exp_strategies))
        notes.append(
            f"Experimental (non-corpus-admitted) strategies with candidates were skipped: "
            f"{', '.join(exp_strategies[:5])}."
        )

    if not categories:
        categories[CAT_SWEEP_EXHAUSTED] = shortfall_count
        notes.append(
            "Sweep exhausted: no more unique diverse candidates found within constraints."
        )

    return {"count": shortfall_count, "categories": categories, "notes": notes}


def _portfolio_fingerprint(
    targets_hash: str,
    requested: int,
    entries: list[PortfolioEntry],
) -> str:
    """16-char hex sha256 of the canonical portfolio plan entries."""
    canonical_entries = sorted(
        [
            {
                "case_id":      e.case_id,
                "strategy":     e.strategy,
                "seed_integer": e.seed_integer,
                "target_name":  e.target_name,
                "target_file":  e.target_file,
                "target_line":  e.target_line,
            }
            for e in entries
        ],
        key=lambda x: (x["target_name"], x["case_id"]),
    )
    payload = json.dumps(
        {
            "targets_hash":    targets_hash,
            "requested_count": requested,
            "planned_count":   len(entries),
            "entries":         canonical_entries,
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def _make_target_summaries(
    resolved: list[tuple[str, Path]],
    inspections: dict[str, InspectionResult],
    caps: dict[str, int],
    allocations: dict[str, int],
    per_target_plans: dict[str, CorpusPlan],
) -> list[PortfolioTargetSummary]:
    summaries = []
    for name, path in resolved:
        insp = inspections.get(name)
        tp = per_target_plans.get(name)
        summaries.append(PortfolioTargetSummary(
            name=name,
            path=str(path),
            source_hash=insp.source_hash if insp else "unknown",
            effective_capacity=caps.get(name, 0),
            allocated_count=allocations.get(name, 0),
            planned_count=tp.planned_count if tp else 0,
            suitability={s: stats.suitability for s, stats in insp.strategies.items()}
                        if insp else {},
            viable_strategies=insp.viable_strategies if insp else [],
            limited_strategies=insp.limited_strategies if insp else [],
            blocked_strategies=insp.blocked_strategies if insp else [],
            sub_plan_path="",   # filled in by PortfolioPlan.write()
            blockers=tp.blockers if tp else [],
            warnings=tp.warnings if tp else [],
        ))
    return summaries


def _sanitise_name(name: str) -> str:
    """Replace non-alphanumeric characters with underscores for use in case_id prefix."""
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)


def _empty_corpus_plan_for(
    name: str,
    path: Path,
    inspection: InspectionResult | None,
) -> CorpusPlan:
    """Return a zero-case CorpusPlan for a target that was allocated 0 cases."""
    from .corpus_planner import PlanConstraints
    return CorpusPlan(
        source_root=str(path),
        source_hash=inspection.source_hash if inspection else "unknown",
        requested_count=0,
        planned_count=0,
        projected_accepted_count=0,
        constraints=PlanConstraints(),
        strategy_allocation={},
        suitability={s: st.suitability for s, st in inspection.strategies.items()} if inspection else {},
        cases=[],
        blockers=[],
        warnings=[],
    )


def _empty_portfolio_plan(
    requested: int,
    c: PortfolioConstraints,
    reason: str,
    targets_hash: str = "unknown",
    target_summaries: list[PortfolioTargetSummary] | None = None,
) -> PortfolioPlan:
    return PortfolioPlan(
        schema_version="1.0",
        portfolio_id="empty",
        targets_hash=targets_hash,
        requested_count=requested,
        planned_count=0,
        projected_accepted_count=0,
        constraints=c,
        target_summaries=target_summaries or [],
        entries=[],
        global_strategy_allocation={},
        shortfall={
            "count": requested,
            "categories": {CAT_NO_VIABLE_TARGETS: requested},
            "notes": [reason],
        },
        fingerprint="empty",
        warnings=[],
        blockers=[reason],
    )
