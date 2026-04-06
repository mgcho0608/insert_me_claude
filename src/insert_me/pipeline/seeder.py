"""
Seeder — deterministic patch target generation.

Given a seed and a vulnerability spec, the Seeder walks the C/C++ source tree,
identifies candidate locations where the specified vulnerability class can be
plausibly inserted, and returns a deterministically ordered list of targets.

Design constraints
------------------
- Fully deterministic: random.seed(seed) is the only source of ordering variation.
- No LLM calls.
- No I/O side effects beyond reading the source tree.
- Output is a pure dataclass; no file writes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PatchTarget:
    """A candidate location in the source tree for vulnerability insertion."""

    file: Path
    """Source file containing the candidate location."""

    line: int
    """1-based line number of the primary insertion point."""

    context: dict[str, Any] = field(default_factory=dict)
    """
    Structured context extracted during AST walking.
    Contents are spec-dependent (e.g. variable name, allocation size expression).
    """

    score: float = 0.0
    """
    Plausibility score from the Seeder's ranking pass.
    Higher = more plausible target for the specified vulnerability class.
    Not exposed to the Patcher directly; used only for ordering.
    """


@dataclass
class PatchTargetList:
    """Ordered list of patch targets for a single pipeline run."""

    targets: list[PatchTarget] = field(default_factory=list)
    seed: int = 0
    spec_id: str = ""
    source_root: Path = Path(".")


# ---------------------------------------------------------------------------
# Seeder
# ---------------------------------------------------------------------------

class Seeder:
    """
    Expand a seed + spec into a deterministically ordered PatchTargetList.

    Parameters
    ----------
    seed:
        Integer seed. Fully determines target ordering.
    spec:
        Parsed vulnerability spec dict (loaded from TOML by the config layer).
    source_root:
        Root of the C/C++ source tree.
    """

    def __init__(self, seed: int, spec: dict[str, Any], source_root: Path) -> None:
        self.seed = seed
        self.spec = spec
        self.source_root = source_root
        self._rng = random.Random(seed)

    def run(self) -> PatchTargetList:
        """
        Execute seed expansion.

        Returns
        -------
        PatchTargetList
            Deterministically ordered list of patch candidates.

        Raises
        ------
        NotImplementedError
            Until Phase 3 implementation.
        """
        # TODO(phase3): implement C/C++ source file discovery
        # TODO(phase3): implement AST walking (tree-sitter or libclang)
        # TODO(phase3): implement per-CWE pattern matching
        # TODO(phase3): implement score-then-seed-shuffle ordering
        raise NotImplementedError(
            "Seeder.run() is not yet implemented. See ROADMAP.md Phase 3."
        )

    def _discover_sources(self) -> list[Path]:
        """
        Discover C/C++ source files under self.source_root.

        Returns
        -------
        list[Path]
            Sorted list of .c, .cpp, .cc, .h, .hpp files.
        """
        # TODO(phase3): implement glob + exclude filter
        extensions = {".c", ".cpp", ".cc", ".h", ".hpp"}
        found = [
            p for p in self.source_root.rglob("*") if p.suffix in extensions
        ]
        return sorted(found)

    def _score_candidate(self, file: Path, line: int, context: dict) -> float:
        """
        Assign a plausibility score to a candidate location.

        Higher score = more realistic insertion point for the vulnerability class.
        Scoring is rule-based and deterministic given the spec.
        """
        # TODO(phase3): implement per-CWE scoring heuristics
        _ = file, line, context
        return 0.0
