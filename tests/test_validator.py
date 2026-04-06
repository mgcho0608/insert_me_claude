"""
Validator tests — Phase 5 rule-based plausibility checks.

Coverage
--------
- ValidationVerdict.overall: SKIP (empty checks), PASS, FAIL, SKIP (all-skip checks)
- ValidationVerdict.passed property
- Validator.run() in dry-run mode → empty SKIP verdict
- Validator.run() in real mode with no mutations → FAIL on mutation_applied
- Individual check: mutation_applied (pass/fail)
- Individual check: good_tree_integrity (pass/fail/skip)
- Individual check: bad_tree_changed (pass/fail)
- Individual check: mutation_scope (pass/fail)
- Individual check: simple_syntax_sanity (pass/fail)
- Full real-mode integration via pipeline: demo fixture → all checks PASS
- Validation_result.json schema conformance after Validator wired into pipeline
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from insert_me.pipeline.patcher import Mutation, PatchResult, PatchTarget, PatchTargetList
from insert_me.pipeline.validator import (
    CheckResult,
    CheckStatus,
    ValidationVerdict,
    Validator,
)

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(file: str = "foo.c", line: int = 1, strategy: str = "alloc_size_undercount") -> PatchTarget:
    return PatchTarget(
        file=Path(file),
        line=line,
        score=0.75,
        mutation_strategy=strategy,
        context={"expression": "malloc(n)", "function_name": "test_fn"},
    )


def _make_patch_result(bad_root: Path, good_root: Path, mutations=None, skipped=None) -> PatchResult:
    return PatchResult(
        bad_root=bad_root,
        good_root=good_root,
        mutations=mutations or [],
        skipped_targets=skipped or [],
    )


def _write_c_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_mutation(target: PatchTarget, original: str, mutated: str) -> Mutation:
    return Mutation(
        target=target,
        mutation_type="alloc_size_undercount",
        original_fragment=original,
        mutated_fragment=mutated,
    )


# ---------------------------------------------------------------------------
# ValidationVerdict.overall property
# ---------------------------------------------------------------------------

class TestValidationVerdictOverall:
    def test_empty_checks_is_skip(self):
        v = ValidationVerdict(checks=[])
        assert v.overall == "SKIP"

    def test_all_pass_is_pass(self):
        v = ValidationVerdict(checks=[
            CheckResult("a", CheckStatus.PASS),
            CheckResult("b", CheckStatus.PASS),
        ])
        assert v.overall == "PASS"

    def test_any_fail_is_fail(self):
        v = ValidationVerdict(checks=[
            CheckResult("a", CheckStatus.PASS),
            CheckResult("b", CheckStatus.FAIL, "broken"),
        ])
        assert v.overall == "FAIL"

    def test_all_skip_is_skip(self):
        v = ValidationVerdict(checks=[
            CheckResult("a", CheckStatus.SKIP),
            CheckResult("b", CheckStatus.SKIP),
        ])
        assert v.overall == "SKIP"

    def test_error_counts_as_fail(self):
        v = ValidationVerdict(checks=[
            CheckResult("a", CheckStatus.ERROR, "io error"),
        ])
        assert v.overall == "FAIL"

    def test_passed_property_true_on_pass(self):
        v = ValidationVerdict(checks=[CheckResult("a", CheckStatus.PASS)])
        assert v.passed is True

    def test_passed_property_false_on_fail(self):
        v = ValidationVerdict(checks=[CheckResult("a", CheckStatus.FAIL, "x")])
        assert v.passed is False

    def test_passed_property_false_on_skip(self):
        v = ValidationVerdict(checks=[])
        assert v.passed is False


# ---------------------------------------------------------------------------
# Validator.run() — dry-run mode
# ---------------------------------------------------------------------------

class TestValidatorDryRun:
    def test_dry_run_returns_skip(self, tmp_path):
        v = Validator(patch_result=None, source_root=tmp_path, dry_run=True)
        verdict = v.run()
        assert verdict.overall == "SKIP"
        assert verdict.checks == []

    def test_dry_run_with_patch_result_still_skips(self, tmp_path):
        pr = _make_patch_result(tmp_path / "bad", tmp_path / "good")
        v = Validator(patch_result=pr, source_root=tmp_path, dry_run=True)
        verdict = v.run()
        assert verdict.overall == "SKIP"
        assert verdict.checks == []

    def test_none_patch_result_returns_skip(self, tmp_path):
        v = Validator(patch_result=None, source_root=tmp_path, dry_run=False)
        verdict = v.run()
        assert verdict.overall == "SKIP"
        assert verdict.checks == []


# ---------------------------------------------------------------------------
# Check: mutation_applied
# ---------------------------------------------------------------------------

class TestCheckMutationApplied:
    def test_pass_when_mutations_present(self, tmp_path):
        target = _make_target()
        mutation = _make_mutation(target, "malloc(n)", "malloc((n) - 1)")
        pr = _make_patch_result(tmp_path / "bad", tmp_path / "good", mutations=[mutation])
        v = Validator(patch_result=pr, source_root=tmp_path, dry_run=False)
        verdict = v.run()
        applied = next(c for c in verdict.checks if c.name == "mutation_applied")
        assert applied.status == CheckStatus.PASS

    def test_fail_when_no_mutations(self, tmp_path):
        target = _make_target()
        pr = _make_patch_result(tmp_path / "bad", tmp_path / "good", skipped=[target])
        v = Validator(patch_result=pr, source_root=tmp_path, dry_run=False)
        verdict = v.run()
        assert verdict.overall == "FAIL"
        applied = next(c for c in verdict.checks if c.name == "mutation_applied")
        assert applied.status == CheckStatus.FAIL
        # Only mutation_applied check runs when mutations list is empty
        assert len(verdict.checks) == 1


# ---------------------------------------------------------------------------
# Check: good_tree_integrity
# ---------------------------------------------------------------------------

class TestCheckGoodTreeIntegrity:
    def _setup(self, tmp_path, *, tamper_good: bool = False, missing_good: bool = False):
        source_root = tmp_path / "src"
        good_root = tmp_path / "good"
        bad_root = tmp_path / "bad"

        original_content = 'char *buf = malloc(n * sizeof(char));\n'
        _write_c_file(source_root / "foo.c", original_content)

        if not missing_good:
            if tamper_good:
                _write_c_file(good_root / "foo.c", "TAMPERED\n")
            else:
                _write_c_file(good_root / "foo.c", original_content)

        mutated_content = 'char *buf = malloc((n * sizeof(char)) - 1);\n'
        _write_c_file(bad_root / "foo.c", mutated_content)

        target = _make_target("foo.c", 1)
        mutation = _make_mutation(target, "malloc(n * sizeof(char))", "malloc((n * sizeof(char)) - 1)")
        pr = PatchResult(bad_root=bad_root, good_root=good_root, mutations=[mutation])
        return pr, source_root

    def test_pass_when_good_matches_source(self, tmp_path):
        pr, source_root = self._setup(tmp_path)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "good_tree_integrity")
        assert check.status == CheckStatus.PASS

    def test_fail_when_good_tampered(self, tmp_path):
        pr, source_root = self._setup(tmp_path, tamper_good=True)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "good_tree_integrity")
        assert check.status == CheckStatus.FAIL

    def test_fail_when_good_file_missing(self, tmp_path):
        pr, source_root = self._setup(tmp_path, missing_good=True)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "good_tree_integrity")
        assert check.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Check: bad_tree_changed
# ---------------------------------------------------------------------------

class TestCheckBadTreeChanged:
    def _setup(self, tmp_path, *, bad_content: str | None = None):
        source_root = tmp_path / "src"
        good_root = tmp_path / "good"
        bad_root = tmp_path / "bad"

        original = 'char *buf = malloc(n * sizeof(char));\n'
        mutated = 'char *buf = malloc((n * sizeof(char)) - 1);\n'

        _write_c_file(source_root / "foo.c", original)
        _write_c_file(good_root / "foo.c", original)
        _write_c_file(bad_root / "foo.c", bad_content if bad_content is not None else mutated)

        target = _make_target("foo.c", 1)
        mutation = _make_mutation(target, "malloc(n * sizeof(char))", "malloc((n * sizeof(char)) - 1)")
        pr = PatchResult(bad_root=bad_root, good_root=good_root, mutations=[mutation])
        return pr, source_root

    def test_pass_when_mutated_fragment_present(self, tmp_path):
        pr, source_root = self._setup(tmp_path)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "bad_tree_changed")
        assert check.status == CheckStatus.PASS

    def test_fail_when_bad_identical_to_good(self, tmp_path):
        original = 'char *buf = malloc(n * sizeof(char));\n'
        pr, source_root = self._setup(tmp_path, bad_content=original)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "bad_tree_changed")
        assert check.status == CheckStatus.FAIL

    def test_fail_when_mutated_fragment_absent(self, tmp_path):
        pr, source_root = self._setup(tmp_path, bad_content='char *buf = malloc(n);\n')
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "bad_tree_changed")
        assert check.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Check: mutation_scope
# ---------------------------------------------------------------------------

class TestCheckMutationScope:
    def _setup(self, tmp_path, extra_changed: bool = False):
        source_root = tmp_path / "src"
        good_root = tmp_path / "good"
        bad_root = tmp_path / "bad"

        original = 'char *buf = malloc(n * sizeof(char));\n'
        mutated = 'char *buf = malloc((n * sizeof(char)) - 1);\n'

        _write_c_file(source_root / "foo.c", original)
        _write_c_file(good_root / "foo.c", original)
        _write_c_file(bad_root / "foo.c", mutated)

        if extra_changed:
            _write_c_file(good_root / "bar.c", "int x = 0;\n")
            _write_c_file(bad_root / "bar.c", "int x = 999;\n")  # also changed

        target = _make_target("foo.c", 1)
        mutation = _make_mutation(target, "malloc(n * sizeof(char))", "malloc((n * sizeof(char)) - 1)")
        pr = PatchResult(bad_root=bad_root, good_root=good_root, mutations=[mutation])
        return pr, source_root

    def test_pass_when_exactly_one_file_changed(self, tmp_path):
        pr, source_root = self._setup(tmp_path)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "mutation_scope")
        assert check.status == CheckStatus.PASS

    def test_fail_when_multiple_files_changed(self, tmp_path):
        pr, source_root = self._setup(tmp_path, extra_changed=True)
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "mutation_scope")
        assert check.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Check: simple_syntax_sanity
# ---------------------------------------------------------------------------

class TestCheckSimpleSyntaxSanity:
    def _setup(self, tmp_path, line_content: str):
        source_root = tmp_path / "src"
        good_root = tmp_path / "good"
        bad_root = tmp_path / "bad"

        original = 'char *buf = malloc(n * sizeof(char));\n'
        _write_c_file(source_root / "foo.c", original)
        _write_c_file(good_root / "foo.c", original)
        _write_c_file(bad_root / "foo.c", line_content)

        target = _make_target("foo.c", 1)
        mutation = _make_mutation(target, "malloc(n * sizeof(char))", "malloc((n * sizeof(char)) - 1)")
        pr = PatchResult(bad_root=bad_root, good_root=good_root, mutations=[mutation])
        return pr, source_root

    def test_pass_when_parens_balanced(self, tmp_path):
        pr, source_root = self._setup(tmp_path, 'char *buf = malloc((n * sizeof(char)) - 1);\n')
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "simple_syntax_sanity")
        assert check.status == CheckStatus.PASS

    def test_fail_when_parens_unbalanced(self, tmp_path):
        pr, source_root = self._setup(tmp_path, 'char *buf = malloc((n * sizeof(char) - 1;\n')
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "simple_syntax_sanity")
        assert check.status == CheckStatus.FAIL

    def test_fail_when_file_empty(self, tmp_path):
        pr, source_root = self._setup(tmp_path, '')
        v = Validator(patch_result=pr, source_root=source_root, dry_run=False)
        verdict = v.run()
        check = next(c for c in verdict.checks if c.name == "simple_syntax_sanity")
        assert check.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Integration: demo fixture through the full pipeline
# ---------------------------------------------------------------------------

class TestValidatorPipelineIntegration:
    """Run the real pipeline against the demo fixture and verify Validator output."""

    def test_real_mode_validation_passes(self, tmp_path):
        """Real mode with demo fixture: all Validator checks should PASS."""
        from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
        from insert_me.pipeline import run_pipeline

        cfg = Config(
            pipeline=PipelineConfig(
                seed_file=DEMO_SEED,
                source_path=DEMO_SOURCE,
                output_root=tmp_path / "output",
            ),
            llm=LLMConfig(),
            validator=ValidatorConfig(),
            auditor=AuditorConfig(),
        )
        bundle = run_pipeline(cfg, dry_run=False)

        with open(bundle.validation_result, encoding="utf-8") as fh:
            vr = json.load(fh)

        assert vr["overall"] == "PASS", (
            f"Expected PASS, got {vr['overall']}. checks: {vr['checks']}"
        )
        assert len(vr["checks"]) == 5
        for check in vr["checks"]:
            assert check["status"] == "pass", f"Check {check['name']} failed: {check}"

    def test_real_mode_ground_truth_validation_passed(self, tmp_path):
        """ground_truth.json validation_passed must be True when Validator passes."""
        from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
        from insert_me.pipeline import run_pipeline

        cfg = Config(
            pipeline=PipelineConfig(
                seed_file=DEMO_SEED,
                source_path=DEMO_SOURCE,
                output_root=tmp_path / "output",
            ),
            llm=LLMConfig(),
            validator=ValidatorConfig(),
            auditor=AuditorConfig(),
        )
        bundle = run_pipeline(cfg, dry_run=False)

        with open(bundle.ground_truth, encoding="utf-8") as fh:
            gt = json.load(fh)

        assert gt["validation_passed"] is True

    def test_real_mode_audit_result_classification_valid(self, tmp_path):
        """audit_result.json classification must be VALID when Validator passes."""
        from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
        from insert_me.pipeline import run_pipeline

        cfg = Config(
            pipeline=PipelineConfig(
                seed_file=DEMO_SEED,
                source_path=DEMO_SOURCE,
                output_root=tmp_path / "output",
            ),
            llm=LLMConfig(),
            validator=ValidatorConfig(),
            auditor=AuditorConfig(),
        )
        bundle = run_pipeline(cfg, dry_run=False)

        with open(bundle.audit_result, encoding="utf-8") as fh:
            ar = json.load(fh)

        assert ar["classification"] == "VALID"

    def test_dry_run_validation_result_is_skip_empty(self, tmp_path):
        """Dry-run mode: validation_result must have overall=SKIP and checks=[]."""
        from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
        from insert_me.pipeline import run_pipeline

        cfg = Config(
            pipeline=PipelineConfig(
                seed_file=DEMO_SEED,
                source_path=DEMO_SOURCE,
                output_root=tmp_path / "output",
            ),
            llm=LLMConfig(),
            validator=ValidatorConfig(),
            auditor=AuditorConfig(),
        )
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.validation_result, encoding="utf-8") as fh:
            vr = json.load(fh)

        assert vr["overall"] == "SKIP"
        assert vr["checks"] == []

    def test_real_mode_validate_bundle_passes(self, tmp_path):
        """validate-bundle must exit 0 on a real-mode bundle after Phase 5."""
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli", "run",
                "--seed-file", str(DEMO_SEED),
                "--source", str(DEMO_SOURCE),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"CLI run failed:\n{result.stdout}\n{result.stderr}"
        )
        bundle = next((tmp_path / "output").iterdir())
        result2 = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle)],
            capture_output=True,
            text=True,
        )
        assert result2.returncode == 0, (
            f"validate-bundle failed:\n{result2.stdout}\n{result2.stderr}"
        )
