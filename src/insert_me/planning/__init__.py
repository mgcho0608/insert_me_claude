"""
Planning layer for target-aware corpus synthesis.

This module provides deterministic, target-aware corpus planning for insert_me.
Given a local evaluation-only C/C++ source tree and a requested case count,
the planning layer:

  1. Inspects the target (file inventory, per-strategy candidate counts,
     file/function concentration signals).
  2. Assesses suitability for each implemented strategy family.
  3. Synthesises concrete seed integers via a deterministic sweep, respecting
     diversity constraints (max per file, max per function).
  4. Produces a CorpusPlan with one PlanCase per planned insertion, written
     to ``corpus_plan.json`` + one ``seeds/*.json`` file per case.

Design constraints
------------------
- No LLM required.  Fully deterministic: same source tree + same count +
  same constraints => same plan.
- Reuses Seeder machinery; no new file-format parser.
- Does NOT execute mutations; the plan is executed separately via
  ``insert-me batch`` or ``scripts/generate_corpus.py``.

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
"""

from .corpus_planner import CorpusPlanner, CorpusPlan, PlanCase, PlanConstraints
from .inspector import TargetInspector, InspectionResult, FileStats, StrategyStats
from .seed_synthesis import SeedSynthesizer, SynthesisResult, SynthesizedCase

__all__ = [
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
]
