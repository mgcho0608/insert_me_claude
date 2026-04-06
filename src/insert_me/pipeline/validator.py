"""
Validator — rule-based plausibility checking of patch results.

Phase 5 implementation: five deterministic, compiler-free checks that
verify an applied mutation is structurally sound and semantically plausible.

Checks
------
mutation_applied
    PASS when at least one mutation record was produced by the Patcher.
    FAIL when the Patcher ran but applied zero mutations.

good_tree_integrity
    PASS when the mutated file in good/ is byte-identical to the original source.
    FAIL when good/ was tampered or the copy is missing.

bad_tree_changed
    PASS when bad/ contains the expected mutated_fragment and differs from good/.
    FAIL when bad/ is identical to good/ or the mutated_fragment is absent.

mutation_scope
    PASS when exactly one file differs between bad/ and good/ (Phase 4a invariant).
    FAIL when zero or more than one file differs.

simple_syntax_sanity
    PASS when the mutated line has balanced parentheses and the file is non-empty.
    FAIL when parentheses are unbalanced or the file is empty.

Design constraints
------------------
- Fully deterministic: all checks are rule-based.
- No compiler invocation, no external tools.
- Does not modify any files.
- LLM soft-scoring is an optional extension, not a core check.
- A ValidationVerdict is always produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from insert_me.pipeline.patcher import PatchResult


# ---------------------------------------------------------------------------
# Verdict structures
# ---------------------------------------------------------------------------

class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    reason: str = ""


@dataclass
class ValidationVerdict:
    """Aggregated result of all plausibility checks."""

    checks: list[CheckResult] = field(default_factory=list)
    notes: str = ""

    @property
    def overall(self) -> str:
        """
        Aggregate verdict derived from individual checks.

        SKIP  — no checks were run (dry-run or no patch result).
        FAIL  — at least one check has status FAIL or ERROR.
        PASS  — at least one check has status PASS and none have FAIL/ERROR.
        SKIP  — all enabled checks are SKIP (no meaningful verdict).
        """
        if not self.checks:
            return "SKIP"
        statuses = {c.status for c in self.checks}
        if CheckStatus.FAIL in statuses or CheckStatus.ERROR in statuses:
            return "FAIL"
        if CheckStatus.PASS in statuses:
            return "PASS"
        return "SKIP"

    @property
    def passed(self) -> bool:
        """True only when overall == 'PASS'."""
        return self.overall == "PASS"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class Validator:
    """
    Run plausibility checks on a PatchResult.

    Parameters
    ----------
    patch_result:
        PatchResult from the Patcher, or None in dry-run mode.
    source_root:
        Path to the original source tree (used for good_tree_integrity).
    dry_run:
        When True, returns an empty SKIP verdict without running any checks.
    """

    def __init__(
        self,
        patch_result: PatchResult | None,
        source_root: Path,
        *,
        dry_run: bool = False,
    ) -> None:
        self.patch_result = patch_result
        self.source_root = source_root
        self.dry_run = dry_run

    def run(self) -> ValidationVerdict:
        """
        Execute all checks and return a ValidationVerdict.

        In dry-run mode (or when patch_result is None), returns immediately
        with an empty SKIP verdict so that downstream callers receive a
        well-formed result without performing any file I/O.
        """
        if self.dry_run or self.patch_result is None:
            return ValidationVerdict(
                notes="Validation skipped (dry-run or no patch result)."
            )

        checks: list[CheckResult] = []

        # Check 1: did the Patcher actually apply a mutation?
        checks.append(self._check_mutation_applied())

        # Remaining checks are only meaningful when at least one mutation exists.
        if self.patch_result.mutations:
            checks.append(self._check_good_tree_integrity())
            checks.append(self._check_bad_tree_changed())
            checks.append(self._check_mutation_scope())
            checks.append(self._check_simple_syntax_sanity())

        return ValidationVerdict(checks=checks)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_mutation_applied(self) -> CheckResult:
        """PASS when the Patcher produced at least one mutation record."""
        assert self.patch_result is not None
        n = len(self.patch_result.mutations)
        if n > 0:
            return CheckResult(
                "mutation_applied",
                CheckStatus.PASS,
                f"{n} mutation(s) applied.",
            )
        skipped = len(self.patch_result.skipped_targets)
        return CheckResult(
            "mutation_applied",
            CheckStatus.FAIL,
            f"Patcher ran but applied 0 mutations "
            f"({skipped} target(s) skipped — incompatible line or unknown strategy).",
        )

    def _check_good_tree_integrity(self) -> CheckResult:
        """PASS when good/ copy of the mutated file is byte-identical to source."""
        assert self.patch_result is not None
        mutation = self.patch_result.mutations[0]
        rel = mutation.target.file
        src_file = self.source_root / rel
        good_file = self.patch_result.good_root / rel

        if not good_file.exists():
            return CheckResult(
                "good_tree_integrity",
                CheckStatus.FAIL,
                f"File missing from good/: {rel}",
            )
        if not src_file.exists():
            return CheckResult(
                "good_tree_integrity",
                CheckStatus.SKIP,
                f"Original source file not found (cannot verify): {rel}",
            )
        if src_file.read_bytes() != good_file.read_bytes():
            return CheckResult(
                "good_tree_integrity",
                CheckStatus.FAIL,
                f"good/{rel} differs from the original source — good tree may have been tampered.",
            )
        return CheckResult(
            "good_tree_integrity",
            CheckStatus.PASS,
            f"good/{rel} is byte-identical to the original source.",
        )

    def _check_bad_tree_changed(self) -> CheckResult:
        """PASS when bad/ contains the expected mutated_fragment and differs from good/."""
        assert self.patch_result is not None
        mutation = self.patch_result.mutations[0]
        rel = mutation.target.file
        bad_file = self.patch_result.bad_root / rel
        good_file = self.patch_result.good_root / rel

        if not bad_file.exists():
            return CheckResult(
                "bad_tree_changed",
                CheckStatus.FAIL,
                f"Mutated file missing from bad/: {rel}",
            )
        if not good_file.exists():
            return CheckResult(
                "bad_tree_changed",
                CheckStatus.SKIP,
                f"good/{rel} not found — cannot compare.",
            )
        if bad_file.read_bytes() == good_file.read_bytes():
            return CheckResult(
                "bad_tree_changed",
                CheckStatus.FAIL,
                f"bad/{rel} is byte-identical to good/{rel} — mutation was not written.",
            )
        bad_text = bad_file.read_text(encoding="utf-8", errors="replace")
        if mutation.mutated_fragment not in bad_text:
            return CheckResult(
                "bad_tree_changed",
                CheckStatus.FAIL,
                f"mutated_fragment {mutation.mutated_fragment!r} not found in bad/{rel}.",
            )
        return CheckResult(
            "bad_tree_changed",
            CheckStatus.PASS,
            f"bad/{rel} contains the expected mutation and differs from good/.",
        )

    def _check_mutation_scope(self) -> CheckResult:
        """PASS when exactly one file differs between bad/ and good/ (Phase 4a invariant)."""
        assert self.patch_result is not None
        changed: list[Path] = []
        try:
            for good_file in sorted(self.patch_result.good_root.rglob("*")):
                if good_file.is_file():
                    rel = good_file.relative_to(self.patch_result.good_root)
                    bad_file = self.patch_result.bad_root / rel
                    if not bad_file.exists() or bad_file.read_bytes() != good_file.read_bytes():
                        changed.append(rel)
        except OSError as exc:
            return CheckResult(
                "mutation_scope",
                CheckStatus.ERROR,
                f"Could not traverse bad/good trees: {exc}",
            )

        if len(changed) == 1:
            return CheckResult(
                "mutation_scope",
                CheckStatus.PASS,
                f"Exactly 1 file changed: {changed[0]}",
            )
        return CheckResult(
            "mutation_scope",
            CheckStatus.FAIL,
            f"{len(changed)} file(s) differ between bad/ and good/ "
            f"(expected exactly 1): {[str(c) for c in changed]}",
        )

    def _check_simple_syntax_sanity(self) -> CheckResult:
        """
        PASS when the mutated line has balanced parentheses and the file is non-empty.

        This is a lightweight heuristic: it does not invoke a compiler or parser.
        It catches the most obvious structural breakage (unbalanced parens from a
        failed mutation) without requiring any external tooling.
        """
        assert self.patch_result is not None
        mutation = self.patch_result.mutations[0]
        rel = mutation.target.file
        bad_file = self.patch_result.bad_root / rel

        if not bad_file.exists():
            return CheckResult(
                "simple_syntax_sanity",
                CheckStatus.SKIP,
                f"Mutated file not found: {rel}",
            )
        try:
            lines = bad_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return CheckResult(
                "simple_syntax_sanity",
                CheckStatus.FAIL,
                f"Could not read mutated file {rel}: {exc}",
            )
        if not lines:
            return CheckResult(
                "simple_syntax_sanity",
                CheckStatus.FAIL,
                f"Mutated file {rel} is empty.",
            )

        line_idx = mutation.target.line - 1
        if 0 <= line_idx < len(lines):
            line = lines[line_idx]
            open_count = line.count("(")
            close_count = line.count(")")
            if open_count != close_count:
                return CheckResult(
                    "simple_syntax_sanity",
                    CheckStatus.FAIL,
                    f"Unbalanced parentheses on line {mutation.target.line} "
                    f"({open_count} open, {close_count} close): {line.strip()!r}",
                )

        return CheckResult(
            "simple_syntax_sanity",
            CheckStatus.PASS,
            f"Mutated line {mutation.target.line} has balanced parentheses.",
        )
