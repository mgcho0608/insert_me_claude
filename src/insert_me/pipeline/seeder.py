"""
Seeder — deterministic patch target generation via lexical source analysis.

Algorithm
---------
1.  Discover all C/C++ source files under source_root, sorted by relative path.
2.  Apply exclude_patterns from the seed's source_constraints (if any).
3.  For each file: scan line-by-line, apply the pattern regex for pattern_type.
4.  Skip lines inside block comments or starting with //.
5.  Score each match using deterministic, strategy-specific heuristics.
6.  Filter by min_candidate_score (default: 0.0 — keep all matches).
7.  Sort: score DESC, then (file, line) ASC — fully deterministic base order.
8.  Within equal-score tiers, shuffle using random.Random(seed) for diversity.
9.  Truncate to max_targets (if specified in the seed file).

Design constraints
------------------
- No AST parser. No external tools. Regex + line scanning only.
- Fully deterministic: identical seed + identical source tree → identical output.
- No file writes. No LLM calls.

Heuristic limitations (deliberately documented)
------------------------------------------------
- Block-comment tracking is approximate (no string-literal awareness).
- Function-name extraction looks up to 100 lines back for a signature.
- Scoring is additive and strategy-specific; see _score_line() for full rules.
- The "custom" pattern_type falls back to a union of all dangerous-function regexes.
"""

from __future__ import annotations

import fnmatch
import hashlib
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File extensions treated as C/C++ source or header files.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
)

#: Default glob patterns applied against each file's name and relative path.
#: Files matching any of these patterns are excluded from candidate search.
DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = (
    "*test*",
    "*_test.*",
    "*mock*",
    "*stub*",
)

#: C/C++ keywords that may appear before '(' but are NOT function names.
_C_KEYWORDS: frozenset[str] = frozenset(
    {
        "if", "else", "for", "while", "do", "switch", "case", "return",
        "break", "continue", "goto", "typedef", "sizeof", "struct", "enum",
        "union", "const", "volatile", "extern", "static", "inline",
        "namespace", "class", "new", "delete", "try", "catch", "throw",
    }
)

# ---------------------------------------------------------------------------
# Compiled pattern regexes (module-level, compiled once)
# ---------------------------------------------------------------------------

#: Maps target_pattern.pattern_type → compiled regex.
#: Each regex identifies lines that are plausible candidates for the given
#: vulnerability class. Applied line-by-line after comment filtering.
PATTERN_REGEXES: dict[str, re.Pattern[str]] = {
    # Heap allocation
    "malloc_call":  re.compile(r"\bmalloc\s*\("),
    "calloc_call":  re.compile(r"\bcalloc\s*\("),
    "realloc_call": re.compile(r"\brealloc\s*\("),
    # Heap release
    "free_call":    re.compile(r"\bfree\s*\("),
    # Pointer dereference (explicit deref or arrow operator)
    "pointer_deref": re.compile(r"(?:\*\s*\w+|\b\w+\s*->\s*\w+)"),
    # Array subscript access
    "array_index":  re.compile(r"\b\w+\s*\["),
    # Integer multiplication — common in buffer-size calculations
    "integer_arithmetic": re.compile(r"\b\w+\s*\*\s*(?:sizeof\s*\(|\w+)"),
    # Dangerous string/memory operations (unbounded or size-unaware)
    "string_operation": re.compile(
        r"\b(?:strcpy|strncpy|strcat|strncat|sprintf|gets|scanf"
        r"|memcpy|memmove|read|recv|recvfrom)\s*\("
    ),
    # Format-string functions
    "format_string": re.compile(
        r"\b(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf)\s*\("
    ),
    # Null-check guard lines (CWE-476 — guard removal)
    "null_guard": re.compile(
        r"^\s*if\s*\(\s*"
        r"(?:!\w+|\w+\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*\w+)"
        r"\s*\)"
    ),
    # Loop headers (for-loop off-by-one candidates)
    "loop_bound": re.compile(r"\bfor\s*\("),
    # Fallback: union of the most dangerous patterns
    "custom": re.compile(
        r"\b(?:malloc|calloc|realloc|free|strcpy|strncpy|strcat|strncat|"
        r"sprintf|gets|scanf|printf|fprintf|snprintf|vprintf|vfprintf|"
        r"memcpy|memmove|read|recv|recvfrom)\s*\("
        r"|\b\w+\s*->\s*\w+"
        r"|\bfor\s*\("
    ),
}

# ---------------------------------------------------------------------------
# Pointer-deref helpers (used for pointer_deref scoring enrichment)
# ---------------------------------------------------------------------------

#: Matches an arrow dereference and captures the pointer variable: ptr->field
_PTR_ARROW_RE: re.Pattern[str] = re.compile(r"\b(\w+)\s*->")

#: Matches an explicit star dereference (*ptr) — negative lookbehind prevents
#: matching double stars (**ptr) or pointer-type annotations (int *p).
_PTR_STAR_RE: re.Pattern[str] = re.compile(r"(?<![*\w])\*\s*(\w+)")

#: Matches a heap allocation assigned to a named pointer variable:
#:   ptr = malloc(...)  or  ptr = (SomeType *) malloc(...)
_MALLOC_ASSIGN_RE: re.Pattern[str] = re.compile(
    r"\b(\w+)\s*=\s*(?:\(\s*[\w\s*]+\*?\s*\)\s*)?(?:malloc|calloc|realloc)\s*\("
)


# Simple C/C++ function signature pattern.
# Group 1 captures the function name.
# Intentionally broad; false-positives are filtered via _C_KEYWORDS.
#
# The negative lookahead after ^\s* prevents C control-flow keywords from
# being matched as the leading "return-type" word.  Without it, the [\w_]+
# alternative can backtrack to a single character (e.g. 'i' from 'if'),
# leaving the rest of the keyword (e.g. 'f') to be captured as the
# "function name", producing spurious one-character names like 'f' or 'y'.
_FUNC_SIG_RE: re.Pattern[str] = re.compile(
    r"^\s*"
    r"(?!(?:if|while|for|switch|return|break|continue|do|else|goto"
    r"|typedef|sizeof|free|memcpy|memmove|memset|strcpy|strcat)\b)"
    r"(?:(?:static|extern|inline|const|volatile|unsigned|signed|long|short)\s+)*"
    r"(?:"
    r"struct\s+\w+|enum\s+\w+|"
    r"(?:void|int|char|float|double|size_t|bool|BOOL|DWORD|HANDLE|HRESULT"
    r"|u?int(?:8|16|32|64)_t)\s*\**"
    r"|[\w_]+\s*\**"
    r")\s*\**\s*"
    r"(\w+)\s*\(",
)

# Single-line comment indicator
_LINE_COMMENT_RE: re.Pattern[str] = re.compile(r"^\s*//")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PatchTarget:
    """A candidate location in the source tree for vulnerability insertion."""

    file: Path
    """Relative path to the source file (relative to source_root)."""

    line: int
    """1-based line number of the primary insertion point."""

    mutation_strategy: str = ""
    """Strategy identifier carried from the seed's mutation_strategy field."""

    context: dict[str, Any] = field(default_factory=dict)
    """
    Structured context extracted during source scanning.

    Standard keys:
        expression:     the matched source line (stripped)
        function_name:  enclosing function name ('' if not found)
    """

    score: float = 0.0
    """
    Plausibility score (0.0–1.0) from the Seeder's ranking pass.
    Higher = more plausible insertion point for the vulnerability class.
    """


@dataclass
class PatchTargetList:
    """Ordered list of patch targets for a single pipeline run."""

    targets: list[PatchTarget] = field(default_factory=list)
    seed: int = 0
    spec_id: str = ""
    source_root: Path = field(default_factory=lambda: Path("."))
    skipped_count: int = 0
    """Candidates found but filtered out (below min_score or beyond max_targets)."""
    source_hash: str = "no-sources"
    """16-char hex hash of the discovered source file set (sorted paths + contents)."""


# ---------------------------------------------------------------------------
# Seeder
# ---------------------------------------------------------------------------


class Seeder:
    """
    Expand a seed + spec into a deterministically ordered PatchTargetList.

    Parameters
    ----------
    seed:
        Integer seed used for within-tier shuffle ordering.
    spec:
        Parsed seed artifact dict (validated against seed.schema.json).
    source_root:
        Root of the C/C++ source tree to search.
    """

    def __init__(self, seed: int, spec: dict[str, Any], source_root: Path) -> None:
        self.seed = seed
        self.spec = spec
        self.source_root = source_root
        self._rng = random.Random(seed)
        self._pattern_type: str = (
            spec.get("target_pattern", {}).get("pattern_type", "custom")
        )
        self._mutation_strategy: str = spec.get("mutation_strategy", "unknown")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> PatchTargetList:
        """
        Execute seed expansion.

        Returns
        -------
        PatchTargetList
            Deterministically ordered candidate targets.
            Empty if source_root does not exist or contains no matching files.
        """
        spec_id = self.spec.get("seed_id", "")

        # 1. Discover source files
        source_files = self._discover_sources()

        # 2. Compute lightweight content hash
        src_hash = _compute_source_hash(self.source_root, source_files)

        result = PatchTargetList(
            seed=self.seed,
            spec_id=spec_id,
            source_root=self.source_root,
            source_hash=src_hash,
        )

        if not source_files:
            return result

        # 3. Extract all candidates
        all_candidates: list[PatchTarget] = []
        for src_file in source_files:
            all_candidates.extend(self._extract_candidates(src_file))

        total_raw = len(all_candidates)

        # 4. Filter by min_candidate_score
        min_score: float = float(
            self.spec.get("target_pattern", {}).get("min_candidate_score", 0.0)
        )
        passing = [c for c in all_candidates if c.score >= min_score]

        # 5. Order deterministically (score DESC, then file+line, then seed shuffle)
        ordered = self._order_targets(passing)

        # 6. Truncate to max_targets
        max_targets: int | None = self.spec.get("source_constraints", {}).get(
            "max_targets"
        )
        skipped_by_cap = 0
        if max_targets is not None and len(ordered) > max_targets:
            skipped_by_cap = len(ordered) - max_targets
            ordered = ordered[:max_targets]

        result.targets = ordered
        result.skipped_count = (total_raw - len(passing)) + skipped_by_cap
        return result

    # ------------------------------------------------------------------
    # Source discovery
    # ------------------------------------------------------------------

    def _discover_sources(self) -> list[Path]:
        """
        Return all C/C++ source files under source_root in deterministic order.

        Ordering: lexicographic sort by relative path string (OS-independent).
        Exclude patterns (from seed's source_constraints) are matched against
        both the filename and the relative path string.
        """
        if not self.source_root.exists() or not self.source_root.is_dir():
            return []

        exclude_patterns: list[str] = list(
            self.spec.get("source_constraints", {}).get(
                "exclude_patterns", list(DEFAULT_EXCLUDE_PATTERNS)
            )
        )

        def _is_excluded(path: Path) -> bool:
            rel_str = str(path.relative_to(self.source_root))
            return any(
                fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel_str, pat)
                for pat in exclude_patterns
            )

        candidates = (
            p
            for p in self.source_root.rglob("*")
            if p.is_file() and p.suffix in SOURCE_EXTENSIONS
        )

        return sorted(
            (p for p in candidates if not _is_excluded(p)),
            key=lambda p: str(p.relative_to(self.source_root)),
        )

    # ------------------------------------------------------------------
    # Candidate extraction
    # ------------------------------------------------------------------

    def _extract_candidates(self, source_file: Path) -> list[PatchTarget]:
        """
        Extract candidate patch targets from one source file using line scanning.

        Skips lines that are inside block comments or start with //.
        """
        regex = PATTERN_REGEXES.get(self._pattern_type, PATTERN_REGEXES["custom"])

        try:
            content = source_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = content.splitlines()
        candidates: list[PatchTarget] = []
        in_block_comment = False
        rel_path = source_file.relative_to(self.source_root)

        for lineno, line in enumerate(lines, start=1):
            # --- Block comment state machine ---
            if "/*" in line:
                # Enter block comment if no closing */ on the same line
                after_open = line[line.index("/*") + 2:]
                if "*/" not in after_open:
                    in_block_comment = True
                else:
                    # Both /* and */ on the same line: strip the comment and continue
                    # (may still have code outside the comment)
                    pass
            if "*/" in line:
                in_block_comment = False
                # Skip the rest of this line conservatively
                continue
            if in_block_comment:
                continue

            # --- Single-line comments ---
            if _LINE_COMMENT_RE.match(line):
                continue

            # --- Empty lines ---
            if not line.strip():
                continue

            # --- Pattern match ---
            if not regex.search(line):
                continue

            score = self._score_line(line)
            context = self._extract_context(lines, lineno - 1, line)

            candidate = PatchTarget(
                file=rel_path,
                line=lineno,
                mutation_strategy=self._mutation_strategy,
                context=context,
                score=score,
            )

            # For pointer_deref: extract pointer name and apply multi-line
            # scoring signals that require looking at surrounding lines.
            if self._pattern_type == "pointer_deref":
                ptr_name = _extract_pointer_name(line)
                if ptr_name:
                    candidate.context["pointer_name"] = ptr_name
                    from_idx = lineno - 1  # 0-based index of this line
                    if _has_prior_malloc_in_scope(lines, from_idx, ptr_name):
                        candidate.score = min(candidate.score + 0.25, 1.0)
                        # Penalise if an existing free() sits between malloc and
                        # this dereference — that pointer is already freed.
                        malloc_idx = _find_malloc_line(lines, from_idx, ptr_name)
                        if malloc_idx is not None and _has_free_between(
                            lines, malloc_idx, from_idx, ptr_name
                        ):
                            candidate.score = max(candidate.score - 0.20, 0.0)

                # Penalise pointer dereferences that appear inside a conditional
                # expression (if/while/for guard).  Inserting free() before a
                # null-check creates a double-free risk and violates the
                # single-primary-flaw principle.
                if re.match(r"\s*(?:if|while|for)\s*\(", line):
                    candidate.score = max(candidate.score - 0.30, 0.0)

                # Penalise dereferences that are inside a loop body.  Inserting
                # free(ptr) before a line inside while(cur){...} causes the free
                # to execute on *every* iteration, which is a severe secondary
                # flaw beyond the intended single UAF.
                if ptr_name and _is_inside_loop_body(lines, lineno - 1):
                    candidate.score = max(candidate.score - 0.40, 0.0)

                # Penalise sub-allocation lines: ptr->field = malloc(...).
                # Inserting free(ptr) just before such a line is problematic
                # because the subsequent null-check error handler typically
                # contains free(ptr) — creating a double-free on the error path.
                if re.search(
                    r"\b\w+\s*->\s*\w+\s*=\s*(?:malloc|calloc|realloc)\s*\(",
                    line,
                ):
                    candidate.score = max(candidate.score - 0.35, 0.0)

            # For null_guard: bonus when a pointer dereference of the guarded
            # variable follows within _NULL_GUARD_LOOKFORWARD lines.
            if self._pattern_type == "null_guard":
                from insert_me.pipeline.patcher import (
                    _NULL_GUARD_RE as _NG_RE,
                    _extract_guarded_ptr as _eg_ptr,
                )
                ng_m = _NG_RE.match(line)
                if ng_m:
                    guarded_ptr = _eg_ptr(ng_m)
                    candidate.context["guarded_pointer"] = guarded_ptr
                    # Check if dereference of same pointer follows
                    look_end = min(lineno + 5, len(lines))  # lineno is 1-based
                    deref_pat = re.compile(
                        rf"\b{re.escape(guarded_ptr)}\s*->"
                        rf"|(?<![*\w])\*\s*{re.escape(guarded_ptr)}\b"
                    ) if guarded_ptr else None
                    if deref_pat:
                        for j in range(lineno, look_end):  # lines[lineno] is next line
                            if deref_pat.search(lines[j]):
                                candidate.score = min(candidate.score + 0.25, 1.0)
                                break

            # For free_call: penalise targets that are inside loop bodies or
            # conditional guard expressions.  These produce secondary flaws
            # (loop-multiplied free, or double-free in null-check error path).
            if self._pattern_type == "free_call":
                # Penalise free() calls that are the guard expression itself.
                if re.match(r"\s*(?:if|while|for)\s*\(", line):
                    candidate.score = max(candidate.score - 0.20, 0.0)

                # Penalise free() calls inside a loop body — the free would
                # execute on every iteration instead of once.
                if _is_inside_loop_body(lines, lineno - 1):
                    candidate.score = max(candidate.score - 0.30, 0.0)

                # Penalise free() calls with complex argument expressions:
                # free((*ptr)->field) or free(arr[i]) cannot be matched by
                # the patcher's simple identifier regex and will produce a
                # NOOP mutation.  Strongly penalise to prefer simple args.
                if re.search(r"\bfree\s*\(\s*[(\[]", line):
                    candidate.score = max(candidate.score - 0.50, 0.0)

            candidates.append(candidate)

        return candidates

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_line(self, line: str) -> float:
        """
        Assign a deterministic plausibility score to a matched line.

        Base score: 0.4 (any non-comment pattern match).
        Pattern-specific additive boosts documented inline.
        Result is capped at 1.0.

        Scoring rules by pattern_type
        ------------------------------
        malloc_call:
            +0.35  size expression contains arithmetic (e.g. n * sizeof(T))
            +0.15  size expression is sizeof only
            +0.05  other

        calloc_call / realloc_call:
            +0.25  always (two-argument alloc — inherently interesting)

        free_call:
            +0.15  unconditional

        string_operation:
            +0.55  gets()          — unbounded, always dangerous
            +0.45  read()/recv()/recvfrom() — unchecked length from external source
            +0.35  strcpy()/memcpy()/memmove() — destination overflow risk
            +0.25  strcat()
            +0.20  sprintf()
            +0.10  others

        format_string:
            +0.45  printf/fprintf with bare variable as format arg
            +0.20  printf/fprintf with variable in any position
            +0.10  others

        integer_arithmetic:
            +0.40  multiplication involving sizeof()
            +0.20  involves unsigned or size_t (wraparound risk)
            +0.10  others

        array_index:
            +0.30  arithmetic expression inside subscript
            +0.15  simple variable subscript
            +0.05  others

        loop_bound:
            +0.35  for-loop with <= comparison (off-by-one pattern)
            +0.15  other for-loop

        pointer_deref:
            +0.20  arrow operator (struct member via pointer)
            +0.10  explicit dereference
            +0.25  prior malloc of same pointer visible in scope (applied after
                   _score_line, in _extract_candidates)
            -0.20  free() on same pointer exists between malloc and deref
                   (existing free reduces plausibility as UAF insertion site)
            -0.30  dereference is inside a conditional expression (if/while/for)
                   — inserting free() before a null-check risks double-free and
                   violates single-primary-flaw discipline
            -0.40  dereference is inside a loop body (while/for)
                   — inserting free() causes the free to execute on every
                   iteration, violating the single-primary-flaw principle
            -0.35  line is a sub-allocation: ptr->field = malloc(...)
                   — the subsequent null-check error handler typically frees
                   the parent pointer, creating a double-free on the error path

        custom / fallback:
            +0.55  gets()
            +0.30  strcpy or sprintf
            +0.25  malloc with arithmetic
            +0.10  others
        """
        score = 0.4  # base
        pt = self._pattern_type

        if pt == "malloc_call":
            if re.search(r"malloc\s*\([^)]*[+\-*][^)]*\)", line):
                score += 0.35
            elif re.search(r"malloc\s*\(\s*sizeof\s*\(", line):
                score += 0.15
            else:
                score += 0.05

        elif pt in ("calloc_call", "realloc_call"):
            score += 0.25

        elif pt == "free_call":
            score += 0.15

        elif pt == "string_operation":
            if re.search(r"\bgets\s*\(", line):
                score += 0.55
            elif re.search(r"\b(?:read|recv|recvfrom)\s*\(", line):
                score += 0.45
            elif re.search(r"\b(?:strcpy|memcpy|memmove)\s*\(", line):
                score += 0.35
            elif re.search(r"\bstrcat\s*\(", line):
                score += 0.25
            elif re.search(r"\bsprintf\s*\(", line):
                score += 0.20
            else:
                score += 0.10

        elif pt == "format_string":
            # Bare variable as format arg — most suspicious
            if re.search(r"\b(?:printf|fprintf)\s*\(\s*\w+\s*\)", line):
                score += 0.45
            elif re.search(r"\b(?:printf|fprintf)\s*\(\s*\w+", line):
                score += 0.20
            else:
                score += 0.10

        elif pt == "integer_arithmetic":
            if re.search(r"\*\s*sizeof\s*\(", line):
                score += 0.40
            elif re.search(r"\bunsigned\b|\bsize_t\b", line):
                score += 0.20
            else:
                score += 0.10

        elif pt == "array_index":
            if re.search(r"\w+\s*\[\s*\w+\s*[+\-*]\s*\w+", line):
                score += 0.30
            elif re.search(r"\w+\s*\[\s*\w+\s*\]", line):
                score += 0.15
            else:
                score += 0.05

        elif pt == "null_guard":
            # Single-line guards (if (!ptr) return;) score higher than
            # guards with complex bodies.
            if re.search(r"\)\s*return\b[^;]*;", line):
                score += 0.40   # immediate single-line return guard
            elif re.search(r"\)\s*(?:goto\s+\w+\s*;|\{[^}]*\})", line):
                score += 0.25   # goto or single-statement block
            else:
                score += 0.15   # multi-line body — harder to remove safely

        elif pt == "loop_bound":
            if re.search(r"\bfor\s*\([^;]*;[^;]*<=", line):
                score += 0.35
            else:
                score += 0.15

        elif pt == "pointer_deref":
            if re.search(r"\b\w+\s*->\s*\w+", line):
                score += 0.20
            else:
                score += 0.10

        elif pt == "custom":
            if re.search(r"\bgets\s*\(", line):
                score += 0.55
            elif re.search(r"\b(?:read|recv|recvfrom)\s*\(", line):
                score += 0.45
            elif re.search(r"\b(?:strcpy|memcpy|memmove)\s*\(|\bsprintf\s*\(", line):
                score += 0.30
            elif re.search(r"malloc\s*\([^)]*[+\-*][^)]*\)", line):
                score += 0.25
            else:
                score += 0.10

        return min(score, 1.0)

    # ------------------------------------------------------------------
    # Context extraction
    # ------------------------------------------------------------------

    def _extract_context(
        self, lines: list[str], match_idx: int, matched_line: str
    ) -> dict[str, Any]:
        """Return a context dict for the given match."""
        return {
            "expression": matched_line.strip(),
            "function_name": _find_enclosing_function(lines, match_idx),
        }

    # ------------------------------------------------------------------
    # Ordering
    # ------------------------------------------------------------------

    def _order_targets(self, candidates: list[PatchTarget]) -> list[PatchTarget]:
        """
        Order candidates deterministically.

        Step 1 — primary sort: score DESC, then (file, line) ASC.
                 This gives a fully deterministic ordering independent of seed.

        Step 2 — within-tier shuffle: candidates with the same score (rounded
                 to 6 decimal places) are shuffled using self._rng, so different
                 seed integers explore different candidates first.
        """
        candidates.sort(key=lambda t: (-t.score, str(t.file), t.line))

        result: list[PatchTarget] = []
        i = 0
        while i < len(candidates):
            j = i + 1
            tier_score = round(candidates[i].score, 6)
            while (
                j < len(candidates)
                and round(candidates[j].score, 6) == tier_score
            ):
                j += 1
            tier = candidates[i:j]
            if len(tier) > 1:
                self._rng.shuffle(tier)
            result.extend(tier)
            i = j

        return result


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _extract_pointer_name(line: str) -> str | None:
    """
    Extract the pointer variable name from a dereference expression.

    Tries arrow operator first (``ptr->field``), then explicit star
    dereference (``*ptr``).  Returns None when the name is a C keyword or
    cannot be identified from the line.
    """
    m = _PTR_ARROW_RE.search(line)
    if m:
        return m.group(1)
    m = _PTR_STAR_RE.search(line)
    if m:
        name = m.group(1)
        if name not in _C_KEYWORDS:
            return name
    return None


def _has_prior_malloc_in_scope(
    lines: list[str], from_idx: int, ptr_name: str
) -> bool:
    """
    Return True if ``ptr_name = malloc(...)`` (or calloc/realloc) appears in
    the same function scope before *from_idx* (0-based).

    Scope boundary detection: scanning stops when a bare ``}`` at column 0 is
    encountered (standard C function-closing-brace), preventing false matches
    from the same variable name in a preceding function.

    Best-effort lexical heuristic; may still produce false positives for
    deeply-nested code or non-standard formatting.
    """
    pattern = re.compile(
        rf"\b{re.escape(ptr_name)}\s*=\s*"
        rf"(?:\(\s*[\w\s*]+\*?\s*\)\s*)?(?:malloc|calloc|realloc)\s*\("
    )
    search_start = max(0, from_idx - 100)
    for i in range(from_idx - 1, search_start - 1, -1):
        raw = lines[i]
        # Stop at a bare closing brace at column 0 — function boundary
        if raw.startswith("}") and raw.rstrip() in ("}", "};"):
            break
        if pattern.search(raw):
            return True
    return False


def _find_malloc_line(
    lines: list[str], from_idx: int, ptr_name: str
) -> int | None:
    """
    Return the 0-based index of the most recent malloc/calloc/realloc
    assignment to *ptr_name* before *from_idx*.  Returns None if not found.

    Uses the same function-boundary detection as _has_prior_malloc_in_scope.
    """
    pattern = re.compile(
        rf"\b{re.escape(ptr_name)}\s*=\s*"
        rf"(?:\(\s*[\w\s*]+\*?\s*\)\s*)?(?:malloc|calloc|realloc)\s*\("
    )
    search_start = max(0, from_idx - 100)
    for i in range(from_idx - 1, search_start - 1, -1):
        raw = lines[i]
        if raw.startswith("}") and raw.rstrip() in ("}", "};"):
            break
        if pattern.search(raw):
            return i
    return None


def _has_free_between(
    lines: list[str], malloc_idx: int, deref_idx: int, ptr_name: str
) -> bool:
    """
    Return True if ``free(ptr_name)`` appears between *malloc_idx* and
    *deref_idx* (exclusive, 0-based indices).  Used to detect existing frees
    that would make the candidate a less useful UAF insertion site.
    """
    pattern = re.compile(rf"\bfree\s*\(\s*{re.escape(ptr_name)}\s*\)")
    for i in range(malloc_idx + 1, deref_idx):
        if pattern.search(lines[i]):
            return True
    return False


def _is_inside_loop_body(lines: list[str], from_idx: int) -> bool:
    """
    Return True if the line at *from_idx* (0-based) is directly inside a
    ``while`` or ``for`` loop body.

    Algorithm: scan backward counting net brace depth (closing braces go up,
    opening braces go down).  When the depth first goes negative we have found
    the ``{`` that opens the block enclosing *from_idx*.  If that opener appears
    on a line that contains ``while (`` or ``for (``, we are inside a loop.
    A multi-line loop header (header line before the ``{`` line) is also
    checked by looking up to 3 lines above the opener.

    Stops at a bare ``}`` at column 0 (function boundary).
    """
    brace_depth = 0
    search_start = max(0, from_idx - 100)
    for i in range(from_idx - 1, search_start - 1, -1):
        raw = lines[i]
        # Stop at function boundary
        if raw.startswith("}") and raw.rstrip() in ("}", "};"):
            break
        opens = raw.count("{")
        closes = raw.count("}")
        # Scanning backward: each } encountered is an outer-scope close (+1
        # depth away from from_idx), each { brings us shallower (-1).
        brace_depth += closes - opens
        if brace_depth < 0:
            # raw contains the { that opens the immediate enclosing block
            if re.search(r"\b(?:while|for)\s*\(", raw):
                return True
            # Multi-line header: check lines just above for while/for condition
            for j in range(i - 1, max(i - 4, -1), -1):
                stripped = lines[j].strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if re.search(r"\b(?:while|for)\s*\(", lines[j]):
                    return True
                # Hit something else (if/else/function body): stop
                break
            return False
    return False


def _find_enclosing_function(lines: list[str], from_idx: int) -> str:
    """
    Scan backward from from_idx (0-based) to find the enclosing function name.

    Uses _FUNC_SIG_RE, searches up to 100 lines back.
    Returns '' if no function signature is found.
    """
    search_start = max(0, from_idx - 100)
    for i in range(from_idx, search_start - 1, -1):
        m = _FUNC_SIG_RE.match(lines[i])
        if m and m.group(1) not in _C_KEYWORDS:
            return m.group(1)
    return ""


def _compute_source_hash(source_root: Path, source_files: list[Path]) -> str:
    """
    Compute a deterministic 16-char hex hash over the given source file set.

    Hash input: sorted relative path strings + file byte contents (in order).
    Returns 'no-sources' if source_files is empty.
    """
    if not source_files:
        return "no-sources"
    h = hashlib.sha256()
    for f in source_files:  # already sorted by relative path
        rel = str(f.relative_to(source_root))
        h.update(rel.encode("utf-8"))
        try:
            h.update(f.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]
