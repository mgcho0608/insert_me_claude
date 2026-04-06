"""
Patcher — deterministic mutation application.

The Patcher takes a PatchTargetList produced by the Seeder and applies
AST-level or line-level mutations to a copy of the source tree, producing
the bad (vulnerable) and good (clean) trees side by side.

Design constraints
------------------
- Fully deterministic: mutations are rule-based transforms, not generated.
- The good tree must be a byte-identical copy of the original source tree.
- The bad tree must differ from the good tree only at the mutation sites.
- No LLM calls.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from insert_me.pipeline.seeder import PatchTargetList, PatchTarget


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Mutation:
    """Record of a single applied mutation."""

    target: PatchTarget
    """The patch target that was mutated."""

    mutation_type: str
    """String identifier for the mutation strategy (e.g. 'heap_overflow_alloc')."""

    original_fragment: str
    """The original source fragment that was replaced."""

    mutated_fragment: str
    """The replacement source fragment (the vulnerability)."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Any additional metadata useful for ground truth generation."""


@dataclass
class PatchResult:
    """Output of a Patcher run."""

    bad_root: Path
    """Root of the mutated (vulnerable) source tree."""

    good_root: Path
    """Root of the clean (original) source tree."""

    mutations: list[Mutation] = field(default_factory=list)
    """Ordered list of applied mutations."""

    skipped_targets: list[PatchTarget] = field(default_factory=list)
    """Targets that were considered but not mutated (e.g. failed preconditions)."""


# ---------------------------------------------------------------------------
# Patcher
# ---------------------------------------------------------------------------

class Patcher:
    """
    Apply mutations from a PatchTargetList to produce bad/good source trees.

    Parameters
    ----------
    targets:
        PatchTargetList produced by the Seeder.
    bad_root:
        Destination directory for the mutated tree.
    good_root:
        Destination directory for the clean copy.
    """

    def __init__(
        self,
        targets: PatchTargetList,
        bad_root: Path,
        good_root: Path,
    ) -> None:
        self.targets = targets
        self.bad_root = bad_root
        self.good_root = good_root

    def run(self) -> PatchResult:
        """
        Execute all mutations.

        Returns
        -------
        PatchResult
            Paths to bad/good trees and list of applied Mutation records.

        Raises
        ------
        NotImplementedError
            Until Phase 4 implementation.
        """
        # TODO(phase4): copy source tree to good_root (byte-identical)
        # TODO(phase4): copy source tree to bad_root
        # TODO(phase4): for each target, select mutation strategy from spec
        # TODO(phase4): apply mutation to bad_root file at target location
        # TODO(phase4): record Mutation dataclass for each applied change
        raise NotImplementedError(
            "Patcher.run() is not yet implemented. See ROADMAP.md Phase 4."
        )

    def _copy_tree(self, src: Path, dst: Path) -> None:
        """Copy entire source tree to dst, preserving structure."""
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)

    def _apply_mutation(
        self,
        target: PatchTarget,
        strategy: str,
        bad_root: Path,
    ) -> Mutation | None:
        """
        Apply a single mutation strategy at the given target location.

        Returns the Mutation record, or None if the target fails preconditions.
        """
        # TODO(phase4): dispatch to strategy implementations
        _ = target, strategy, bad_root
        return None
