"""
Patcher — deterministic mutation application.

The Patcher takes a PatchTargetList produced by the Seeder and applies
line-level mutations to a copy of the source tree, producing the bad
(vulnerable) and good (clean) trees side by side.

Phase 4 implementation scope
-----------------------------
One mutation strategy is currently implemented:

    alloc_size_undercount
        Transforms ``malloc(<expr>)`` → ``malloc((<expr>) - 1)``.
        Introduces a heap buffer overflow by allocating one byte fewer than
        required.  Applied only to the first compatible target from the
        PatchTargetList (one mutation per run in this phase).

Strategy extensibility
-----------------------
Additional strategies are registered in ``_STRATEGY_HANDLERS``.  Each
handler is a callable that receives a raw source line and returns either:
    (mutated_line, original_fragment, mutated_fragment)
or None if the strategy cannot be safely applied to that line.

Design constraints
------------------
- Fully deterministic: mutations are rule-based transforms, not generated.
- The good tree must be a byte-identical copy of the original source tree.
- The bad tree must differ from the good tree only at the mutation site(s).
- No AST parser.  No LLM calls.
- No source files outside bad_root are ever modified.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

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
    """String identifier for the mutation strategy (e.g. 'alloc_size_undercount')."""

    original_fragment: str
    """The original source fragment that was replaced (without trailing newline)."""

    mutated_fragment: str
    """The replacement source fragment (without trailing newline)."""

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
    """Applied mutations (at most one in the current Phase 4 implementation)."""

    skipped_targets: list[PatchTarget] = field(default_factory=list)
    """Targets considered but not patched (unknown strategy or unsafe line)."""


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

# Signature: (source_line: str) -> (mutated_line, original_fragment, mutated_fragment) | None
_StrategyResult = tuple[str, str, str]
_StrategyHandler = Callable[[str], _StrategyResult | None]

_STRATEGY_HANDLERS: dict[str, _StrategyHandler] = {}


def _register(name: str) -> Callable[[_StrategyHandler], _StrategyHandler]:
    """Decorator to register a mutation strategy handler by name."""
    def decorator(fn: _StrategyHandler) -> _StrategyHandler:
        _STRATEGY_HANDLERS[name] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Compiled patterns (module-level, compiled once)
# ---------------------------------------------------------------------------

#: Matches the start of a malloc() call: word-boundary + optional whitespace + '('
_MALLOC_RE: re.Pattern[str] = re.compile(r"\bmalloc\s*\(")


# ---------------------------------------------------------------------------
# Strategy: alloc_size_undercount
# ---------------------------------------------------------------------------

@_register("alloc_size_undercount")
def _mutate_alloc_size_undercount(line: str) -> _StrategyResult | None:
    """
    Transform ``malloc(<expr>)`` → ``malloc((<expr>) - 1)``.

    Introduces a one-byte undercount in the allocation, causing a heap buffer
    overflow when the caller writes the expected number of bytes.

    Returns (mutated_line, original_fragment, mutated_fragment), or None when:
    - No malloc() call is found on the line.
    - malloc() has no argument.
    - Parentheses are unbalanced on the line (conservative skip).
    """
    loc = _find_malloc_call(line)
    if loc is None:
        return None

    call_start, call_end, arg_text = loc
    if not arg_text:
        return None

    original_fragment = line[call_start:call_end].rstrip("\n")
    mutated_fragment = f"malloc(({arg_text}) - 1)"
    mutated_line = line[:call_start] + mutated_fragment + line[call_end:]
    return (mutated_line, original_fragment, mutated_fragment)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_malloc_call(line: str) -> tuple[int, int, str] | None:
    """
    Locate the first ``malloc(...)`` call in *line*.

    Uses parenthesis counting to handle nested calls such as
    ``malloc(n * sizeof(char))`` correctly.

    Returns
    -------
    (call_start, call_end_exclusive, arg_text)
        Indices into *line* for the full ``malloc(...)`` span.
        ``arg_text`` is the stripped content between the outer parens.
    None
        If no malloc call is found or parentheses are unbalanced.
    """
    m = _MALLOC_RE.search(line)
    if not m:
        return None

    call_start = m.start()   # position of 'm' in 'malloc'
    paren_start = m.end()    # position just after the opening '('

    depth = 1
    i = paren_start
    while i < len(line) and depth > 0:
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        i += 1

    if depth != 0:
        return None  # unbalanced parens on this line — skip conservatively

    call_end = i                             # exclusive end of the full call
    arg_text = line[paren_start : i - 1].strip()
    return (call_start, call_end, arg_text)


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
        Execute mutations and return a PatchResult.

        Phase 4 behaviour
        -----------------
        - If no targets are available, return an empty PatchResult (no copies made).
        - Copy source_root byte-identically to good_root.
        - Copy source_root to bad_root.
        - Attempt to patch the **first** target using its ``mutation_strategy``.
        - If the strategy is unknown or the line is unsafe, the target is moved
          to ``skipped_targets`` and bad_root remains identical to good_root.
        - At most one mutation is applied per run (Phase 4 scope).

        Returns
        -------
        PatchResult
            Contains applied mutations (0 or 1) and skipped targets.
        """
        if not self.targets.targets:
            return PatchResult(bad_root=self.bad_root, good_root=self.good_root)

        # 1. Copy source tree to good/ (byte-identical to original)
        self._copy_tree(self.targets.source_root, self.good_root)

        # 2. Copy source tree to bad/ (will receive mutations)
        self._copy_tree(self.targets.source_root, self.bad_root)

        # 3. Phase 4: attempt first target only
        first_target = self.targets.targets[0]
        mutation = self._apply_mutation(
            first_target, first_target.mutation_strategy, self.bad_root
        )

        result = PatchResult(bad_root=self.bad_root, good_root=self.good_root)
        if mutation is not None:
            result.mutations.append(mutation)
        else:
            result.skipped_targets.append(first_target)

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _copy_tree(self, src: Path, dst: Path) -> None:
        """
        Copy *src* directory tree to *dst*, replacing any existing content.

        If *src* does not exist, *dst* is created as an empty directory.
        """
        if dst.exists():
            shutil.rmtree(dst)
        if src.exists() and src.is_dir():
            shutil.copytree(src, dst)
        else:
            dst.mkdir(parents=True, exist_ok=True)

    def _apply_mutation(
        self,
        target: PatchTarget,
        strategy: str,
        bad_root: Path,
    ) -> Mutation | None:
        """
        Apply a single mutation strategy at the given target location.

        Returns the Mutation record if successful, None if the target must
        be skipped (unknown strategy, file not found, or unsafe line).
        """
        handler = _STRATEGY_HANDLERS.get(strategy)
        if handler is None:
            return None  # strategy not yet implemented

        bad_file = bad_root / target.file
        if not bad_file.exists():
            return None

        try:
            content = bad_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        lines = content.splitlines(keepends=True)
        line_idx = target.line - 1  # convert 1-based to 0-based

        if line_idx < 0 or line_idx >= len(lines):
            return None

        original_line = lines[line_idx]
        handler_result = handler(original_line)
        if handler_result is None:
            return None  # strategy cannot be applied to this line

        mutated_line, original_fragment, mutated_fragment = handler_result

        lines[line_idx] = mutated_line
        try:
            bad_file.write_text("".join(lines), encoding="utf-8")
        except OSError:
            return None

        return Mutation(
            target=target,
            mutation_type=strategy,
            original_fragment=original_fragment,
            mutated_fragment=mutated_fragment,
        )
