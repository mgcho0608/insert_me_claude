"""
SeedSynthesizer — deterministic seed-integer sweep for corpus planning.

Algorithm
---------
For each strategy, sweep seed integers 1, 2, 3, ... and ask the Seeder:
"If I use this seed integer, which candidate will be selected?"

Collect candidates that satisfy diversity constraints:
  - No duplicate (file, line) pair
  - File not already over-represented (max_per_file)
  - Function not already over-represented (max_per_function)
  - Candidate score above min_candidate_score

This approach is fully deterministic: same source tree + same constraints
=> same synthesis result regardless of run environment.

The sweep terminates when:
  - Requested count is reached, OR
  - MAX_SWEEP attempts are exhausted (the target cannot supply more unique
    diverse candidates for this strategy).

Outputs
-------
SynthesisResult per strategy, containing SynthesizedCase entries.
Each SynthesizedCase can be materialised as a seed JSON file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Maximum seed integers to try per strategy before giving up.
#: 50 * requested_count provides reasonable sweep depth without being slow.
MAX_SWEEP_MULTIPLIER: int = 50

#: Absolute cap to avoid infinite loops.
MAX_SWEEP_ABS: int = 2000

#: CWE ID → vulnerability class name (required by seed.schema.json).
_CWE_VULNERABILITY_CLASS: dict[str, str] = {
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
}


@dataclass
class SynthesizedCase:
    """One planned insertion synthesised by the sweep algorithm."""
    case_id: str
    strategy: str
    cwe_id: str
    seed_integer: int
    target_file: str        # relative to source_root
    target_line: int
    function_name: str
    candidate_score: float
    pattern_type: str

    def to_seed_dict(self, source_root: str = "") -> dict:
        """Produce a seed JSON dict conforming to seed.schema.json."""
        notes = (
            f"Auto-synthesised by insert-me plan-corpus. "
            f"Target: {self.target_file}:{self.target_line} "
            f"(score={self.candidate_score:.2f})"
        )
        if source_root:
            notes += f" | source: {source_root}"
        vuln_class = _CWE_VULNERABILITY_CLASS.get(self.cwe_id, "Memory Safety")
        return {
            "schema_version": "1.0",
            "seed_id": self.case_id,
            "seed": self.seed_integer,
            "cwe_id": self.cwe_id,
            "vulnerability_class": vuln_class,
            "mutation_strategy": self.strategy,
            "target_pattern": {
                "pattern_type": self.pattern_type,
                "min_candidate_score": 0.0,
            },
            "source_constraints": {
                "max_targets": 1,
            },
            "metadata": {
                "tags": ["auto-synthesised", self.strategy, self.cwe_id.lower()],
                "notes": notes,
            },
        }


@dataclass
class SynthesisResult:
    """Synthesis output for one strategy."""
    strategy: str
    cwe_id: str
    requested: int
    synthesised: int
    cases: list[SynthesizedCase] = field(default_factory=list)
    sweep_exhausted: bool = False
    warning: str = ""


# ---------------------------------------------------------------------------
# Constraints (shared with CorpusPlanner)
# ---------------------------------------------------------------------------

@dataclass
class SweepConstraints:
    """Per-sweep diversity constraints used by SeedSynthesizer."""
    max_per_file: int = 5
    max_per_function: int = 2
    min_candidate_score: float = 0.0
    verify_patcher: bool = True  # Filter out candidates the patcher will NOOP on


# ---------------------------------------------------------------------------
# Patcher viability check
# ---------------------------------------------------------------------------

def _verify_patcher_will_mutate(
    strategy: str,
    source_root: Path,
    target_file: str,
    target_line: int,
) -> bool:
    """
    Return True if the patcher handler will produce a non-None result for this
    (strategy, file, line) triple.

    Calls the mutation handler directly on the source lines without copying any
    files — fast enough to run inside the sweep loop.  On any error (import,
    IO, exception in handler) returns True to avoid silently dropping candidates.
    """
    try:
        from insert_me.pipeline.patcher import (
            _MULTILINE_STRATEGY_HANDLERS,
            _STRATEGY_HANDLERS,
        )
        file_path = source_root / target_file
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines(
            keepends=True
        )
        line_idx = target_line - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False
        if strategy in _MULTILINE_STRATEGY_HANDLERS:
            result = _MULTILINE_STRATEGY_HANDLERS[strategy](lines, line_idx)
        else:
            handler = _STRATEGY_HANDLERS.get(strategy)
            if handler is None:
                return True  # Unknown strategy — optimistically allow
            result = handler(lines[line_idx])
        return result is not None
    except Exception:
        return True  # On error, optimistically allow


# ---------------------------------------------------------------------------
# SeedSynthesizer
# ---------------------------------------------------------------------------

class SeedSynthesizer:
    """
    Sweep seed integers to find unique, diverse candidates.

    This class is the core of the planning layer.  It wraps the Seeder
    to discover which candidate each seed integer selects, then builds a
    diverse set of cases respecting concentration constraints.
    """

    def __init__(
        self,
        source_root: Path,
        constraints: SweepConstraints | None = None,
    ) -> None:
        self._source_root = source_root
        self._constraints = constraints or SweepConstraints()

    def synthesize_for_strategy(
        self,
        strategy: str,
        cwe_id: str,
        pattern_type: str,
        requested_count: int,
        *,
        seen_targets: set[tuple[str, int]],   # shared cross-strategy dedup set
        case_id_prefix: str = "plan",
        case_id_start: int = 1,
    ) -> SynthesisResult:
        """
        Sweep seed integers for *strategy* and collect *requested_count*
        unique, diverse cases.

        Modifies *seen_targets* in-place so the caller can share it across
        strategy sweeps to guarantee global uniqueness.
        """
        from insert_me.pipeline.seeder import Seeder

        c = self._constraints
        spec: dict[str, Any] = {
            "schema_version": "1.0",
            "seed_id": f"sweep_{strategy}",
            "cwe_id": cwe_id,
            "mutation_strategy": strategy,
            "target_pattern": {
                "pattern_type": pattern_type,
                "min_candidate_score": c.min_candidate_score,
            },
            "source_constraints": {"max_targets": 1},
        }

        file_counts: dict[str, int] = {}
        func_counts: dict[str, int] = {}
        cases: list[SynthesizedCase] = []
        max_sweep = min(
            requested_count * MAX_SWEEP_MULTIPLIER,
            MAX_SWEEP_ABS,
        )
        sweep_exhausted = False
        case_num = case_id_start

        for seed_int in range(1, max_sweep + 1):
            if len(cases) >= requested_count:
                break

            try:
                ptl = Seeder(seed_int, spec, self._source_root).run()
            except Exception:
                continue

            if not ptl.targets:
                continue

            top = ptl.targets[0]
            file_key = str(top.file)
            func_key = top.context.get("function_name", "")
            target_key = (file_key, top.line)

            # Global duplicate guard
            if target_key in seen_targets:
                continue

            # Per-file concentration guard
            if file_counts.get(file_key, 0) >= c.max_per_file:
                continue

            # Per-function concentration guard
            func_global_key = f"{file_key}:{func_key}" if func_key else ""
            if func_key and func_counts.get(func_global_key, 0) >= c.max_per_function:
                continue

            # Patcher viability check — skip candidates that will produce NOOP
            if c.verify_patcher:
                if not _verify_patcher_will_mutate(
                    strategy, self._source_root, file_key, top.line
                ):
                    continue

            # Accept this candidate
            seen_targets.add(target_key)
            file_counts[file_key] = file_counts.get(file_key, 0) + 1
            if func_global_key:
                func_counts[func_global_key] = func_counts.get(func_global_key, 0) + 1

            cid = f"cwe{cwe_id.split('-')[1].lower()}_{case_id_prefix}_{case_num:03d}"
            case_num += 1
            cases.append(SynthesizedCase(
                case_id=cid,
                strategy=strategy,
                cwe_id=cwe_id,
                seed_integer=seed_int,
                target_file=file_key,
                target_line=top.line,
                function_name=func_key,
                candidate_score=top.score,
                pattern_type=pattern_type,
            ))

        else:
            # Loop completed without reaching requested_count
            sweep_exhausted = len(cases) < requested_count

        result = SynthesisResult(
            strategy=strategy,
            cwe_id=cwe_id,
            requested=requested_count,
            synthesised=len(cases),
            cases=cases,
            sweep_exhausted=sweep_exhausted,
        )
        if sweep_exhausted:
            result.warning = (
                f"Strategy {strategy}: only {len(cases)}/{requested_count} "
                f"unique diverse candidates found after {max_sweep} sweep attempts."
            )
        return result
