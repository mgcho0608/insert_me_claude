"""
Planning layer for target-aware corpus synthesis.

This module provides deterministic, target-aware corpus planning for insert_me.
Two planning modes are supported:

Single-target (CorpusPlanner)
-------------------------------
Given a local evaluation-only C/C++ source tree and a requested case count,
the planning layer:

  1. Inspects the target (file inventory, per-strategy candidate counts,
     file/function concentration signals).
  2. Assesses suitability for each implemented strategy family.
  3. Synthesises concrete seed integers via a deterministic sweep, respecting
     diversity constraints (max per file, max per function).
  4. Produces a CorpusPlan with one PlanCase per planned insertion, written
     to ``corpus_plan.json`` + one ``seeds/*.json`` file per case.

Multi-target (PortfolioPlanner)
---------------------------------
Given a targets JSON file listing multiple source trees and a global count,
the portfolio planner:

  1. Inspects each target and computes effective capacity per target.
  2. Allocates the global count proportionally across targets.
  3. Runs CorpusPlanner for each target with its sub-allocation.
  4. Merges all cases and applies global diversity constraints.
  5. Produces a PortfolioPlan (``portfolio_plan.json``) and per-target sub-plans.

Design constraints
------------------
- No LLM required.  Fully deterministic: same inputs + same constraints => same plan.
- Reuses Seeder machinery; no new file-format parser.
- Does NOT execute mutations; the plan is executed separately via
  ``insert-me batch`` or ``insert-me generate-corpus / generate-portfolio``.

Public API
----------
    from insert_me.planning import CorpusPlanner, PlanConstraints

    planner = CorpusPlanner(
        source_root=Path("/path/to/project"),
        requested_count=30,
        constraints=PlanConstraints(max_per_file=5, max_per_function=2),
    )
    plan = planner.plan()
    plan.write(output_dir=Path("plan_out/"))

    # Multi-target
    from insert_me.planning import PortfolioPlanner, PortfolioTarget, load_targets_file

    targets = load_targets_file(Path("examples/targets/sandbox_targets.json"))
    pplanner = PortfolioPlanner(targets=targets, requested_count=40)
    portfolio_plan, per_target_plans = pplanner.plan()
    portfolio_plan.write(Path("portfolio_out"), per_target_plans)
"""

from .corpus_planner import CorpusPlanner, CorpusPlan, PlanCase, PlanConstraints
from .inspector import TargetInspector, InspectionResult, FileStats, StrategyStats
from .seed_synthesis import SeedSynthesizer, SynthesisResult, SynthesizedCase
from .portfolio import (
    PortfolioPlanner,
    PortfolioPlan,
    PortfolioConstraints,
    PortfolioTarget,
    PortfolioEntry,
    load_targets_file,
)

__all__ = [
    # Single-target planning
    "CorpusPlanner",
    "CorpusPlan",
    "PlanCase",
    "PlanConstraints",
    "TargetInspector",
    "InspectionResult",
    "FileStats",
    "StrategyStats",
    "SeedSynthesizer",
    "SynthesisResult",
    "SynthesizedCase",
    # Multi-target portfolio planning
    "PortfolioPlanner",
    "PortfolioPlan",
    "PortfolioConstraints",
    "PortfolioTarget",
    "PortfolioEntry",
    "load_targets_file",
]
