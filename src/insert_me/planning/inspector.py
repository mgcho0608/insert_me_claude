"""
TargetInspector — enhanced target inspection for corpus planning.

Builds on the raw pattern-regex scanning in cli._inspect_source_tree by
adding function-level analysis via the Seeder's existing candidate enumeration.

For each corpus-admitted strategy the inspector runs the Seeder in "enumerate
all" mode (no max_targets cap) and groups the resulting PatchTargets by file
and function name.  This gives accurate per-function candidate counts without
requiring a separate AST parser.

Outputs
-------
InspectionResult — fully serialisable dataclass:
  - file_count, files (list of FileStats)
  - strategies (dict[strategy_name, StrategyStats])
  - source_hash
  - concentration signals at file and function level
  - overall suitability tier per strategy
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Corpus-admitted strategies available for planning
# ---------------------------------------------------------------------------

#: (strategy_name, cwe_id, pattern_type, corpus_admitted)
PLANNING_STRATEGIES: tuple[tuple[str, str, str, bool], ...] = (
    ("alloc_size_undercount", "CWE-122", "malloc_call",   True),
    ("insert_premature_free", "CWE-416", "pointer_deref", True),
    ("insert_double_free",    "CWE-415", "free_call",     True),
    ("remove_free_call",      "CWE-401", "free_call",     True),
    ("remove_null_guard",     "CWE-476", "null_guard",    False),  # experimental
)

#: Strategy suitability tiers.
VIABLE    = "VIABLE"       # >= 10 candidates across >= 3 files
LIMITED   = "LIMITED"      # 1-9 candidates or < 3 files
BLOCKED   = "BLOCKED"      # 0 candidates
EXPERIMENTAL = "EXPERIMENTAL"  # not corpus-admitted


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionStats:
    """Candidate statistics for one function within one file."""
    function_name: str
    file: str
    candidate_count: int = 0


@dataclass
class FileStats:
    """Candidate statistics for one source file."""
    relative_path: str
    line_count: int = 0
    candidate_count: int = 0
    functions: list[FunctionStats] = field(default_factory=list)

    @property
    def function_count(self) -> int:
        return len([f for f in self.functions if f.candidate_count > 0])


@dataclass
class StrategyStats:
    """Candidate statistics for one strategy across the entire target."""
    strategy: str
    cwe_id: str
    pattern_type: str
    corpus_admitted: bool
    total_candidates: int = 0
    files_with_candidates: int = 0
    functions_with_candidates: int = 0
    by_file: dict[str, int] = field(default_factory=dict)        # file -> count
    by_function: dict[str, int] = field(default_factory=dict)    # "file:func" -> count
    max_file_fraction: float = 0.0       # highest single-file fraction
    max_function_fraction: float = 0.0  # highest single-function fraction
    dominant_file: str = ""
    dominant_function: str = ""
    suitability: str = BLOCKED

    def _compute_suitability(self) -> None:
        if not self.corpus_admitted:
            self.suitability = EXPERIMENTAL
            return
        if self.total_candidates == 0:
            self.suitability = BLOCKED
        elif self.total_candidates >= 10 and self.files_with_candidates >= 3:
            self.suitability = VIABLE
        else:
            self.suitability = LIMITED

    def _compute_concentration(self) -> None:
        if self.total_candidates == 0:
            return
        # File concentration
        if self.by_file:
            best_file = max(self.by_file, key=lambda k: self.by_file[k])
            self.dominant_file = best_file
            self.max_file_fraction = self.by_file[best_file] / self.total_candidates
        # Function concentration
        if self.by_function:
            best_func = max(self.by_function, key=lambda k: self.by_function[k])
            self.dominant_function = best_func
            self.max_function_fraction = self.by_function[best_func] / self.total_candidates


@dataclass
class InspectionResult:
    """Complete target inspection result."""
    source_root: str
    source_hash: str
    file_count: int
    files: list[FileStats] = field(default_factory=list)
    strategies: dict[str, StrategyStats] = field(default_factory=dict)
    # Top-level suitability tiers
    viable_strategies: list[str] = field(default_factory=list)
    limited_strategies: list[str] = field(default_factory=list)
    blocked_strategies: list[str] = field(default_factory=list)
    experimental_strategies: list[str] = field(default_factory=list)
    # Max supportable corpus size estimate
    max_supportable_count: int = 0

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "source_root": self.source_root,
            "source_hash": self.source_hash,
            "file_count": self.file_count,
            "files": [
                {
                    "path": f.relative_path,
                    "line_count": f.line_count,
                    "candidate_count": f.candidate_count,
                    "function_count": f.function_count,
                }
                for f in self.files
            ],
            "strategies": {
                name: {
                    "cwe_id": s.cwe_id,
                    "pattern_type": s.pattern_type,
                    "corpus_admitted": s.corpus_admitted,
                    "suitability": s.suitability,
                    "total_candidates": s.total_candidates,
                    "files_with_candidates": s.files_with_candidates,
                    "functions_with_candidates": s.functions_with_candidates,
                    "by_file": s.by_file,
                    "max_file_fraction": round(s.max_file_fraction, 3),
                    "dominant_file": s.dominant_file,
                    "max_function_fraction": round(s.max_function_fraction, 3),
                    "dominant_function": s.dominant_function,
                }
                for name, s in self.strategies.items()
            },
            "suitability_summary": {
                "viable": self.viable_strategies,
                "limited": self.limited_strategies,
                "blocked": self.blocked_strategies,
                "experimental": self.experimental_strategies,
            },
            "max_supportable_count": self.max_supportable_count,
        }


# ---------------------------------------------------------------------------
# TargetInspector
# ---------------------------------------------------------------------------

class TargetInspector:
    """
    Inspect a C/C++ source tree and produce an InspectionResult.

    Uses the Seeder with max_targets uncapped to enumerate ALL candidates
    for each planning strategy.  Fully deterministic; no file writes.
    """

    def __init__(self, source_root: Path) -> None:
        self._source_root = source_root

    def run(self) -> InspectionResult:
        from insert_me.pipeline.seeder import (
            Seeder,
            SOURCE_EXTENSIONS,
            DEFAULT_EXCLUDE_PATTERNS,
        )
        import fnmatch

        source_root = self._source_root

        # --- File inventory ---
        all_paths = sorted(
            p for p in source_root.rglob("*")
            if p.is_file()
            and p.suffix.lower() in SOURCE_EXTENSIONS
            and not any(fnmatch.fnmatch(p.name, pat) for pat in DEFAULT_EXCLUDE_PATTERNS)
        )

        file_stats_map: dict[str, FileStats] = {}
        for p in all_paths:
            rel = str(p.relative_to(source_root))
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                lines = []
            file_stats_map[rel] = FileStats(
                relative_path=rel,
                line_count=len(lines),
            )

        # Source hash (same algorithm as Seeder)
        source_hash = _compute_source_hash(source_root, all_paths)

        # --- Per-strategy candidate enumeration ---
        strategy_stats: dict[str, StrategyStats] = {}
        for strategy_name, cwe_id, pattern_type, corpus_admitted in PLANNING_STRATEGIES:
            spec: dict[str, Any] = {
                "schema_version": "1.0",
                "seed_id": f"inspect_{strategy_name}",
                "cwe_id": cwe_id,
                "mutation_strategy": strategy_name,
                "target_pattern": {
                    "pattern_type": pattern_type,
                    "min_candidate_score": 0.0,
                },
                # No max_targets — enumerate all candidates
            }
            try:
                ptl = Seeder(1, spec, source_root).run()
                candidates = ptl.targets
            except Exception:
                candidates = []

            s = StrategyStats(
                strategy=strategy_name,
                cwe_id=cwe_id,
                pattern_type=pattern_type,
                corpus_admitted=corpus_admitted,
            )

            func_set: set[str] = set()
            for c in candidates:
                rel = str(c.file)
                func = c.context.get("function_name", "")
                s.by_file[rel] = s.by_file.get(rel, 0) + 1
                s.total_candidates += 1
                if func:
                    key = f"{rel}:{func}"
                    s.by_function[key] = s.by_function.get(key, 0) + 1
                    func_set.add(key)

                # Update per-file stats
                if rel in file_stats_map:
                    file_stats_map[rel].candidate_count += 1

            s.files_with_candidates = len(s.by_file)
            s.functions_with_candidates = len(func_set)
            s._compute_concentration()
            s._compute_suitability()
            strategy_stats[strategy_name] = s

        # --- Aggregate file stats ---
        # Each file's candidate_count was incremented above (any strategy)
        # Re-compute as total across all strategies for the file
        for rel, fstats in file_stats_map.items():
            total = sum(
                s.by_file.get(rel, 0)
                for s in strategy_stats.values()
            )
            fstats.candidate_count = total

        # --- Suitability summary ---
        viable, limited, blocked, experimental = [], [], [], []
        for name, s in strategy_stats.items():
            if s.suitability == VIABLE:
                viable.append(name)
            elif s.suitability == LIMITED:
                limited.append(name)
            elif s.suitability == BLOCKED:
                blocked.append(name)
            else:
                experimental.append(name)

        # --- Max supportable count estimate ---
        # Conservative: sum of distinct candidates for admitted strategies,
        # capped by diversity constraints (max_per_file heuristic = 5)
        max_supportable = 0
        for s in strategy_stats.values():
            if not s.corpus_admitted:
                continue
            # Estimate: each file can contribute min(actual, 5) cases
            file_contrib = sum(min(v, 5) for v in s.by_file.values())
            max_supportable += file_contrib

        result = InspectionResult(
            source_root=str(source_root.resolve()),
            source_hash=source_hash,
            file_count=len(all_paths),
            files=sorted(file_stats_map.values(), key=lambda f: f.relative_path),
            strategies=strategy_stats,
            viable_strategies=viable,
            limited_strategies=limited,
            blocked_strategies=blocked,
            experimental_strategies=experimental,
            max_supportable_count=max_supportable,
        )
        return result


def _compute_source_hash(source_root: Path, paths: list[Path]) -> str:
    """Compute a 16-char hash of the source tree (same as Seeder)."""
    h = hashlib.sha256()
    for p in paths:
        h.update(str(p.relative_to(source_root)).encode())
        try:
            h.update(p.read_bytes())
        except Exception:
            pass
    return h.hexdigest()[:16]
