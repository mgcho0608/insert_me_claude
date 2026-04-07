"""
Patcher — deterministic mutation application.

The Patcher takes a PatchTargetList produced by the Seeder and applies
line-level mutations to a copy of the source tree, producing the bad
(vulnerable) and good (clean) trees side by side.

Phase 4 / Phase 8 / Phase 4c implementation scope
--------------------------------------------------
Five mutation strategies are currently implemented:

    alloc_size_undercount  (CWE-122)
        Transforms ``malloc(<expr>)`` → ``malloc((<expr>) - 1)``.
        Introduces a heap buffer overflow by allocating one byte fewer than
        required.

    insert_premature_free  (CWE-416)
        Inserts ``free(<ptr>);`` immediately before a pointer dereference,
        producing a use-after-free.  The pointer name is extracted from the
        arrow operator (``ptr->field``) or explicit dereference (``*ptr``)
        on the target line.

    insert_double_free  (CWE-415)
        Inserts a duplicate ``free(<ptr>);`` before an existing free() call,
        producing a double-free.  Matches simple identifiers and single
        arrow dereferences (``ptr->field``).

    remove_free_call  (CWE-401)
        Replaces a ``free(<ptr>);`` call with a comment, introducing a
        memory leak (missing release of memory after effective lifetime).

    remove_null_guard  (CWE-476)
        Removes a null-check guard (``if (!ptr) return;``) that precedes
        a pointer dereference, allowing a NULL dereference when the caller
        passes a null pointer.  The guard line is replaced with a comment.
        This strategy uses the multi-line handler API because the guard
        and the dereference are on different lines.

Applied only to the first compatible target from the PatchTargetList
(one mutation per run in this phase).

Strategy extensibility
-----------------------
Single-line strategies are registered in ``_STRATEGY_HANDLERS``.  Each
handler receives a raw source line and returns either:
    (mutated_line, original_fragment, mutated_fragment)
    (mutated_line, original_fragment, mutated_fragment, extra_dict)
or None if the strategy cannot be safely applied to that line.

Multi-line strategies are registered in ``_MULTILINE_STRATEGY_HANDLERS``.
Each handler receives ``(lines, line_idx)`` and returns a
``MultilineMutationResult`` (or None).  The handler may modify any line
in the file, not just the target line.

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

# Single-line handler: (source_line: str) → 3-tuple or 4-tuple (with optional
# extra metadata dict) or None when the strategy cannot be applied.
_StrategyResult = tuple[str, str, str] | tuple[str, str, str, dict[str, Any]]
_StrategyHandler = Callable[[str], _StrategyResult | None]

_STRATEGY_HANDLERS: dict[str, _StrategyHandler] = {}


def _register(name: str) -> Callable[[_StrategyHandler], _StrategyHandler]:
    """Decorator to register a single-line mutation strategy handler by name."""
    def decorator(fn: _StrategyHandler) -> _StrategyHandler:
        _STRATEGY_HANDLERS[name] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Multi-line strategy registry
# ---------------------------------------------------------------------------

@dataclass
class MultilineMutationResult:
    """
    Result from a multi-line strategy handler.

    Multi-line handlers may modify any line in the file, not just the
    target line.  Modifications are expressed as a dict of line replacements
    ``{line_idx: new_content}`` where line_idx is 0-based.

    ``original_fragment`` and ``mutated_fragment`` describe the semantic
    change for ground-truth and evaluation purposes.  ``mutated_fragment``
    must be non-empty and present in the modified file so that the
    ``bad_tree_changed`` validator check passes.
    """

    original_fragment: str
    """Text of the primary changed fragment (e.g. the guard line content)."""

    mutated_fragment: str
    """Replacement text (e.g. a comment).  Must appear in the mutated file."""

    line_replacements: dict[int, str] = field(default_factory=dict)
    """
    Map of {0-based line index → new line content (with trailing newline)}.
    Lines not listed here are left unchanged.
    """

    extra: dict[str, Any] = field(default_factory=dict)
    """Optional metadata for ground-truth generation (e.g. affected pointer)."""


# Multi-line handler signature: (lines, line_idx) → MultilineMutationResult or None.
_MultilineStrategyHandler = Callable[
    [list[str], int], MultilineMutationResult | None
]

_MULTILINE_STRATEGY_HANDLERS: dict[str, _MultilineStrategyHandler] = {}


def _register_multiline(
    name: str,
) -> Callable[[_MultilineStrategyHandler], _MultilineStrategyHandler]:
    """Decorator to register a multi-line mutation strategy handler by name."""
    def decorator(fn: _MultilineStrategyHandler) -> _MultilineStrategyHandler:
        _MULTILINE_STRATEGY_HANDLERS[name] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Compiled patterns (module-level, compiled once)
# ---------------------------------------------------------------------------

#: Matches the start of a malloc() call: word-boundary + optional whitespace + '('
_MALLOC_RE: re.Pattern[str] = re.compile(r"\bmalloc\s*\(")

#: Arrow dereference — captures the pointer variable: ptr->field → group(1)='ptr'
_ARROW_DEREF_RE: re.Pattern[str] = re.compile(r"\b(\w+)\s*->")

#: Explicit star dereference (*ptr) — negative lookbehind avoids double-stars.
_STAR_DEREF_RE: re.Pattern[str] = re.compile(r"(?<![*\w])\*\s*(\w+)")

#: C type keywords and common non-pointer identifiers to reject when extracting
#: a pointer name from a star dereference.
_C_TYPE_WORDS: frozenset[str] = frozenset(
    {"void", "int", "char", "float", "double", "NULL", "nullptr", "true", "false"}
)


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
# Strategy: insert_premature_free
# ---------------------------------------------------------------------------

@_register("insert_premature_free")
def _mutate_insert_premature_free(line: str) -> _StrategyResult | None:
    """
    Insert ``free(<ptr>);`` immediately before a pointer dereference.

    The returned ``mutated_line`` prepends the free() call (at the same
    indentation as the target line) to the original dereference line.
    After ``lines[line_idx] = mutated_line`` in ``_apply_mutation``, the
    file grows by one line: the inserted free() at the original line
    number, and the original dereference pushed one line down.

    Returns (mutated_line, original_fragment, mutated_fragment, extra), or
    None when:
    - No arrow or star dereference is found on the line.
    - The pointer name cannot be extracted (keyword, ambiguous pattern).
    """
    ptr = _patcher_extract_pointer_name(line)
    if ptr is None:
        return None

    # Preserve the target line's leading whitespace exactly.
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]

    free_line = f"{indent}free({ptr});\n"
    mutated_line = free_line + line          # prepend free; keep original deref

    original_fragment = line.rstrip("\n").rstrip("\r")
    mutated_fragment = f"free({ptr});"
    extra: dict[str, Any] = {"freed_pointer": ptr}

    return (mutated_line, original_fragment, mutated_fragment, extra)


# ---------------------------------------------------------------------------
# Strategy: insert_double_free
# ---------------------------------------------------------------------------

#: Matches a free() call statement.
#: Captures leading whitespace (group 1) and the pointer expression (group 2).
#: Handles both simple identifiers (free(ptr)) and single arrow dereferences
#: (free(ptr->field)), which are the most common patterns in C cleanup code.
_FREE_CALL_RE: re.Pattern[str] = re.compile(
    r"(\s*)free\s*\(\s*(\w+(?:\s*->\s*\w+)?)\s*\)\s*;"
)


@_register("insert_double_free")
def _mutate_insert_double_free(line: str) -> _StrategyResult | None:
    """
    Insert a duplicate ``free(<ptr>);`` immediately before an existing free() call.

    The returned ``mutated_line`` prepends an additional free() at the same
    indentation, creating a double-free (CWE-415).

    Returns (mutated_line, original_fragment, mutated_fragment, extra), or
    None when the line does not contain a bare ``free(ptr);`` statement.
    """
    m = _FREE_CALL_RE.match(line)
    if not m:
        return None

    indent = m.group(1)
    ptr = m.group(2)

    free_line = f"{indent}free({ptr});\n"
    mutated_line = free_line + line  # prepend duplicate free; keep original

    original_fragment = line.rstrip("\n").rstrip("\r")
    mutated_fragment = f"free({ptr});"
    extra: dict[str, Any] = {"freed_pointer": ptr}

    return (mutated_line, original_fragment, mutated_fragment, extra)


# ---------------------------------------------------------------------------
# Strategy: remove_free_call
# ---------------------------------------------------------------------------

@_register("remove_free_call")
def _mutate_remove_free_call(line: str) -> _StrategyResult | None:
    """
    Replace a ``free(<ptr>);`` call with a comment, introducing a memory leak (CWE-401).

    Returns (mutated_line, original_fragment, mutated_fragment, extra), or
    None when the line does not contain a bare ``free(ptr);`` statement.
    """
    m = _FREE_CALL_RE.match(line)
    if not m:
        return None

    indent = m.group(1)
    ptr = m.group(2)

    original_fragment = line.rstrip("\n").rstrip("\r")
    mutated_fragment = f"/* CWE-401: free({ptr}) removed - memory leak */"
    mutated_line = f"{indent}{mutated_fragment}\n"
    extra: dict[str, Any] = {"leaked_pointer": ptr}

    return (mutated_line, original_fragment, mutated_fragment, extra)


# ---------------------------------------------------------------------------
# Strategy: remove_size_cast  (CWE-190)
# ---------------------------------------------------------------------------

#: Matches a ``(size_t)`` cast (with optional trailing whitespace) for removal.
_SIZE_CAST_RE: re.Pattern[str] = re.compile(r"\(size_t\)\s*")


@_register("remove_size_cast")
def _mutate_remove_size_cast(line: str) -> _StrategyResult | None:
    """
    Remove a ``(size_t)`` cast from ``malloc((size_t)<expr> * sizeof(T))``,
    creating a potential integer-overflow vulnerability (CWE-190).

    When the cast is present, the multiplication is performed in ``size_t``
    (unsigned, pointer-width).  After removal, the computation uses the type
    of ``<expr>`` (typically ``int``), which can overflow before the result
    is widened, causing the allocation to receive a much smaller byte count
    than the caller expects.

    Conservative constraints:
    - Only matches when the malloc arg contains exactly one ``(size_t)`` cast.
    - That cast must appear at the start of the arg expression (immediately
      after the opening parenthesis of malloc, ignoring whitespace).

    Returns ``(mutated_line, original_fragment, mutated_fragment)``, or None when:
    - No ``malloc()`` call is found on the line.
    - The malloc arg has no ``(size_t)`` cast, or has more than one.
    - The cast is not at the start of the arg expression.
    """
    if "malloc" not in line or "(size_t)" not in line:
        return None

    loc = _find_malloc_call(line)
    if loc is None:
        return None

    call_start, call_end, arg_text = loc
    if not arg_text:
        return None

    # Conservative: exactly one (size_t) cast, positioned at the arg start
    if arg_text.count("(size_t)") != 1:
        return None
    if not arg_text.lstrip().startswith("(size_t)"):
        return None

    # Remove the leading (size_t) cast (and any whitespace that followed it)
    new_arg = _SIZE_CAST_RE.sub("", arg_text, count=1).lstrip()
    if not new_arg:
        return None

    original_fragment = line[call_start:call_end].rstrip("\n")
    mutated_fragment = f"malloc({new_arg})"
    mutated_line = line[:call_start] + mutated_fragment + line[call_end:]
    return (mutated_line, original_fragment, mutated_fragment)


# ---------------------------------------------------------------------------
# Strategy: remove_null_guard  (CWE-476, multi-line)
# ---------------------------------------------------------------------------

#: Matches a single-line null-check guard before a pointer dereference.
#: Captures the guarded pointer name from three possible forms:
#:   group(1): !ptr
#:   group(2): ptr == NULL / ptr == nullptr / ptr == 0
#:   group(3): NULL == ptr / nullptr == ptr / 0 == ptr
_NULL_GUARD_RE: re.Pattern[str] = re.compile(
    r"^\s*if\s*\(\s*"
    r"(?:!(\w+)|(\w+)\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*(\w+))"
    r"\s*\)"
)

#: How many lines above the target to scan for a null guard.
_NULL_GUARD_LOOKBACK: int = 5


def _extract_guarded_ptr(m: re.Match[str]) -> str:
    """Return the pointer name captured by _NULL_GUARD_RE."""
    return m.group(1) or m.group(2) or m.group(3) or ""


def _is_null_guard_body_line(stripped: str) -> bool:
    """
    Return True if *stripped* is a guard body statement (return/break/continue).

    Conservative: only single-statement forms ending in ';'.
    Used to skip body lines when scanning past a multiline guard.
    """
    if stripped.endswith(";") and re.match(r"^return\b", stripped):
        return True
    if stripped in ("break;", "continue;"):
        return True
    return False


#: How many lines forward from a guard to look for the protected dereference.
_NULL_GUARD_LOOKFORWARD: int = 4


@_register_multiline("remove_null_guard")
def _mutate_remove_null_guard(
    lines: list[str], line_idx: int
) -> MultilineMutationResult | None:
    """
    Replace a null-check guard with a comment, leaving the pointer dereference
    reachable with a potentially-NULL pointer (CWE-476).

    **Target line** (as provided by the Seeder's ``null_guard`` pattern):
    the ``if (!ptr)`` guard line itself.

    Supported guard forms::

        if (!ptr) return;          ← inline guard (body on same line)
        if (!ptr)                  ← multiline guard head
            return;                ← body on next line (also blanked out)
        if (ptr == NULL) return;   ← equality form
        if (NULL == ptr) return;   ← reversed equality form

    **Backward-compatibility mode**: if ``lines[line_idx]`` is a pointer
    dereference rather than a guard (e.g. seed files that target the deref
    line directly), the handler falls back to scanning backward for the guard
    as in the original single-mode design.

    Returns None when:
    - Target is neither a guard line nor a deref line.
    - No deref of the same pointer follows the guard (forward mode).
    - No guard precedes the deref (backward mode).
    - Pointer names do not match across guard and deref.
    """
    target_line = lines[line_idx]

    # -----------------------------------------------------------------------
    # Primary mode: target line IS the guard line (Seeder null_guard pattern)
    # -----------------------------------------------------------------------
    m = _NULL_GUARD_RE.match(target_line)
    if m is not None:
        return _mutate_from_guard_line(lines, line_idx, m)

    # -----------------------------------------------------------------------
    # Backward-compat mode: target line is a dereference
    # -----------------------------------------------------------------------
    target_ptr = _patcher_extract_pointer_name(target_line)
    if target_ptr is not None:
        return _mutate_from_deref_line(lines, line_idx, target_ptr)

    return None


def _mutate_from_guard_line(
    lines: list[str],
    guard_line_idx: int,
    guard_match: re.Match[str],
) -> MultilineMutationResult | None:
    """
    Mutation when the Seeder has targeted the guard line itself.

    Scans forward to verify a pointer dereference follows, then replaces the
    guard (and its body, for multiline forms) with a comment.
    """
    guard_ptr = _extract_guarded_ptr(guard_match)

    # Determine if the body is inline (same line after the closing paren)
    after_paren = lines[guard_line_idx][guard_match.end():].strip()
    inline_body = bool(after_paren)

    # Scan forward past any body lines to find the dereference
    deref_found = False
    body_indices: list[int] = []
    scan_limit = min(len(lines), guard_line_idx + _NULL_GUARD_LOOKFORWARD + 2)

    for i in range(guard_line_idx + 1, scan_limit):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if _is_null_guard_body_line(stripped):
            if not inline_body:
                body_indices.append(i)
            continue
        # First non-blank, non-comment, non-body line must be the dereference
        dm = _patcher_extract_pointer_name(lines[i])
        if dm and (not guard_ptr or dm == guard_ptr):
            deref_found = True
        break

    if not deref_found:
        return None

    guard_line = lines[guard_line_idx]
    stripped_guard = guard_line.lstrip()
    indent = guard_line[: len(guard_line) - len(stripped_guard)]
    original_fragment = guard_line.rstrip("\n").rstrip("\r")
    mutated_fragment = "/* CWE-476: null guard removed */"
    replacement = f"{indent}{mutated_fragment}\n"

    line_replacements: dict[int, str] = {guard_line_idx: replacement}
    for bi in body_indices:
        line_replacements[bi] = "\n"

    return MultilineMutationResult(
        original_fragment=original_fragment,
        mutated_fragment=mutated_fragment,
        line_replacements=line_replacements,
        extra={
            "guard_line": guard_line_idx + 1,
            "deref_line": -1,            # not precisely known (forward scan)
            "guarded_pointer": guard_ptr,
            "multiline": not inline_body,
            "body_lines": [bi + 1 for bi in body_indices],
        },
    )


def _mutate_from_deref_line(
    lines: list[str],
    deref_line_idx: int,
    target_ptr: str,
) -> MultilineMutationResult | None:
    """
    Backward-compat mutation when the seed file targets the dereference line.

    Scans backward to find the guard above the dereference, skipping guard
    body lines (return/break/continue) to support multiline guards.
    """
    search_start = max(0, deref_line_idx - _NULL_GUARD_LOOKBACK)
    guard_idx: int | None = None
    guard_ptr: str = ""
    body_indices: list[int] = []

    for i in range(deref_line_idx - 1, search_start - 1, -1):
        candidate = lines[i]
        stripped = candidate.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if _is_null_guard_body_line(stripped):
            body_indices.append(i)
            continue
        m = _NULL_GUARD_RE.match(candidate)
        if m:
            guard_ptr = _extract_guarded_ptr(m)
            guard_idx = i
            break
        break

    if guard_idx is None:
        return None

    if guard_ptr and target_ptr and guard_ptr != target_ptr:
        return None

    guard_line = lines[guard_idx]
    stripped_guard = guard_line.lstrip()
    indent = guard_line[: len(guard_line) - len(stripped_guard)]
    original_fragment = guard_line.rstrip("\n").rstrip("\r")
    mutated_fragment = "/* CWE-476: null guard removed */"
    replacement = f"{indent}{mutated_fragment}\n"

    line_replacements: dict[int, str] = {guard_idx: replacement}
    for bi in body_indices:
        line_replacements[bi] = "\n"

    return MultilineMutationResult(
        original_fragment=original_fragment,
        mutated_fragment=mutated_fragment,
        line_replacements=line_replacements,
        extra={
            "guard_line": guard_idx + 1,
            "deref_line": deref_line_idx + 1,
            "guarded_pointer": guard_ptr or target_ptr,
            "multiline": len(body_indices) > 0,
            "body_lines": [bi + 1 for bi in body_indices],
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patcher_extract_pointer_name(line: str) -> str | None:
    """
    Extract the pointer variable name from an arrow or star dereference.

    Returns the variable name from ``ptr->field`` (arrow) or ``*ptr``
    (explicit deref), or None when the name is a C type keyword or the
    line contains no recognisable dereference pattern.
    """
    m = _ARROW_DEREF_RE.search(line)
    if m:
        return m.group(1)
    m = _STAR_DEREF_RE.search(line)
    if m:
        name = m.group(1)
        if name not in _C_TYPE_WORDS:
            return name
    return None


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

        Tries multi-line handlers first (``_MULTILINE_STRATEGY_HANDLERS``),
        then falls back to single-line handlers (``_STRATEGY_HANDLERS``).

        Returns the Mutation record if successful, None if the target must
        be skipped (unknown strategy, file not found, or unsafe line).
        """
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

        # ------------------------------------------------------------------
        # Multi-line handler path
        # ------------------------------------------------------------------
        ml_handler = _MULTILINE_STRATEGY_HANDLERS.get(strategy)
        if ml_handler is not None:
            ml_result = ml_handler(lines, line_idx)
            if ml_result is None:
                return None

            for idx, new_content in ml_result.line_replacements.items():
                if 0 <= idx < len(lines):
                    lines[idx] = new_content

            try:
                bad_file.write_text("".join(lines), encoding="utf-8")
            except OSError:
                return None

            return Mutation(
                target=target,
                mutation_type=strategy,
                original_fragment=ml_result.original_fragment,
                mutated_fragment=ml_result.mutated_fragment,
                extra=ml_result.extra,
            )

        # ------------------------------------------------------------------
        # Single-line handler path
        # ------------------------------------------------------------------
        handler = _STRATEGY_HANDLERS.get(strategy)
        if handler is None:
            return None  # strategy not yet implemented

        original_line = lines[line_idx]
        handler_result = handler(original_line)
        if handler_result is None:
            return None  # strategy cannot be applied to this line

        # Handlers may return a 3-tuple or a 4-tuple (with optional extra dict).
        extra: dict[str, Any] = {}
        if len(handler_result) == 4:
            mutated_line, original_fragment, mutated_fragment, extra = (  # type: ignore[misc]
                handler_result
            )
        else:
            mutated_line, original_fragment, mutated_fragment = handler_result  # type: ignore[misc]

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
            extra=extra,
        )
