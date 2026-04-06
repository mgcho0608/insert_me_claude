"""
Validator — rule-based plausibility checking of patch results.

The Validator confirms that an applied mutation:
    1. Leaves the file syntactically well-formed (as far as can be determined
       without a full compile).
    2. Is non-trivial (the mutation actually changes something meaningful).
    3. Does not introduce obvious disqualifying artifacts.

Design constraints
------------------
- Fully deterministic: all checks are rule-based.
- Does not modify any files.
- LLM soft-scoring is an optional extension, not a core check.
- A ValidationVerdict is always produced, regardless of LLM availability.
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
    SKIP = "skip"  # check was disabled in config


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    reason: str = ""


@dataclass
class ValidationVerdict:
    """Aggregated result of all plausibility checks."""

    passed: bool
    """True if all enabled checks passed."""

    checks: list[CheckResult] = field(default_factory=list)
    """Individual check results."""

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)
        if result.status == CheckStatus.FAIL:
            self.passed = False


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class Validator:
    """
    Run plausibility checks on a PatchResult.

    Parameters
    ----------
    result:
        PatchResult from the Patcher.
    check_syntax:
        Enable syntactic well-formedness check.
    check_trivial:
        Enable non-triviality check.
    check_scope:
        Enable file-scope sanity check.
    """

    def __init__(
        self,
        result: PatchResult,
        check_syntax: bool = True,
        check_trivial: bool = True,
        check_scope: bool = True,
    ) -> None:
        self.result = result
        self.check_syntax = check_syntax
        self.check_trivial = check_trivial
        self.check_scope = check_scope

    def run(self) -> ValidationVerdict:
        """
        Execute all enabled checks and return a ValidationVerdict.

        Raises
        ------
        NotImplementedError
            Until Phase 5 implementation.
        """
        # TODO(phase5): implement _check_syntax (clang-format or simple bracket balance)
        # TODO(phase5): implement _check_trivial (diff is non-empty and substantive)
        # TODO(phase5): implement _check_scope (mutation is within a function body)
        raise NotImplementedError(
            "Validator.run() is not yet implemented. See ROADMAP.md Phase 5."
        )

    def _check_syntax(self, file: Path) -> CheckResult:
        """Check that a mutated file is syntactically plausible."""
        # TODO(phase5): run clang-format --dry-run or similar lightweight check
        _ = file
        return CheckResult(name="syntax", status=CheckStatus.SKIP, reason="not implemented")

    def _check_trivial(self) -> CheckResult:
        """Check that at least one substantive mutation was applied."""
        # TODO(phase5): verify self.result.mutations is non-empty and has non-empty fragments
        return CheckResult(name="non_trivial", status=CheckStatus.SKIP, reason="not implemented")

    def _check_scope(self, file: Path, line: int) -> CheckResult:
        """Check that the mutation target is within a valid scope (e.g. function body)."""
        # TODO(phase5): implement scope check via AST or heuristic
        _ = file, line
        return CheckResult(name="scope", status=CheckStatus.SKIP, reason="not implemented")
