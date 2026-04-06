"""
Phase 4b tests — insert_premature_free strategy (CWE-416 Use After Free).

Coverage
--------
Unit (patcher):
  - _patcher_extract_pointer_name: arrow op, star deref, no-match cases
  - _mutate_insert_premature_free: correct free line, indentation, extra dict, None cases
  - Mutation record fields (mutation_type, fragments, extra)

Unit (seeder helpers):
  - _extract_pointer_name: arrow, star, none
  - _has_prior_malloc_in_scope: found, not found
  - _has_free_between: free present, free absent

Pipeline integration:
  - Real mode on uaf_demo.c fixture → APPLIED / VALID
  - bad/ contains free(rec); before the dereference
  - good/ is byte-identical to source
  - ground_truth mutation record is accurate
  - audit.json validation_verdict.passed = True
  - dry-run → NOOP classification, sources unmodified
  - validate-bundle exits 0 on real-mode bundle
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED_CWE416 = REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(tmp_path, seed_file=DEMO_SEED_CWE416, source=DEMO_SOURCE):
    from insert_me.config import Config, PipelineConfig, LLMConfig, ValidatorConfig, AuditorConfig
    return Config(
        pipeline=PipelineConfig(
            seed_file=seed_file,
            source_path=source,
            output_root=tmp_path / "output",
        ),
        llm=LLMConfig(),
        validator=ValidatorConfig(),
        auditor=AuditorConfig(),
    )


# ---------------------------------------------------------------------------
# Unit: patcher pointer name extraction
# ---------------------------------------------------------------------------

class TestPatcherExtractPointerName:
    def _fn(self, line):
        from insert_me.pipeline.patcher import _patcher_extract_pointer_name
        return _patcher_extract_pointer_name(line)

    def test_arrow_operator_simple(self):
        assert self._fn("    rec->id = id;") == "rec"

    def test_arrow_operator_in_printf(self):
        assert self._fn('    printf("%d", node->value);') == "node"

    def test_star_deref(self):
        assert self._fn("    *ptr = 0;") == "ptr"

    def test_star_deref_with_indent(self):
        assert self._fn("        *cursor = value;") == "cursor"

    def test_no_deref_returns_none(self):
        assert self._fn("    int x = 5;") is None

    def test_plain_assignment_no_deref(self):
        assert self._fn("    buf = malloc(n);") is None

    def test_c_keyword_star_returns_none(self):
        # NULL, void, etc. should not be treated as pointer names
        assert self._fn("    *NULL = 0;") is None

    def test_arrow_takes_priority_over_star(self):
        # Both patterns present: arrow wins
        assert self._fn("    *p = rec->value;") == "rec"


# ---------------------------------------------------------------------------
# Unit: _mutate_insert_premature_free handler
# ---------------------------------------------------------------------------

class TestMutateInsertPrematureFree:
    def _fn(self, line):
        from insert_me.pipeline.patcher import _mutate_insert_premature_free
        return _mutate_insert_premature_free(line)

    def test_inserts_free_line_before_deref(self):
        result = self._fn("    rec->id = id;\n")
        assert result is not None
        mutated_line, orig, frag, extra = result
        # mutated_line should be two lines: free + original
        lines = mutated_line.splitlines()
        assert lines[0].strip() == "free(rec);"
        assert lines[1].strip() == "rec->id = id;"

    def test_preserves_indentation(self):
        result = self._fn("        node->data = 42;\n")
        assert result is not None
        mutated_line = result[0]
        # Inserted line must have same leading whitespace
        assert mutated_line.startswith("        free(node);")

    def test_original_fragment_is_original_line_stripped(self):
        result = self._fn("    rec->value = v;\n")
        assert result is not None
        _, orig, _, _ = result
        assert orig == "    rec->value = v;"

    def test_mutated_fragment_is_free_call(self):
        result = self._fn("    rec->value = v;\n")
        assert result is not None
        _, _, frag, _ = result
        assert frag == "free(rec);"

    def test_extra_contains_freed_pointer(self):
        result = self._fn("    node->next = NULL;\n")
        assert result is not None
        _, _, _, extra = result
        assert extra["freed_pointer"] == "node"

    def test_no_deref_returns_none(self):
        assert self._fn("    int x = malloc(4);\n") is None

    def test_returns_none_for_plain_assignment(self):
        assert self._fn("    x = 42;\n") is None


# ---------------------------------------------------------------------------
# Unit: seeder pointer-deref helpers
# ---------------------------------------------------------------------------

class TestSeederPointerDerefHelpers:
    def test_extract_pointer_name_arrow(self):
        from insert_me.pipeline.seeder import _extract_pointer_name
        assert _extract_pointer_name("    rec->id = id;") == "rec"

    def test_extract_pointer_name_star(self):
        from insert_me.pipeline.seeder import _extract_pointer_name
        assert _extract_pointer_name("    *p = 0;") == "p"

    def test_extract_pointer_name_none(self):
        from insert_me.pipeline.seeder import _extract_pointer_name
        assert _extract_pointer_name("    int x = 5;") is None

    def test_has_prior_malloc_in_scope_found(self):
        from insert_me.pipeline.seeder import _has_prior_malloc_in_scope
        lines = [
            "void fn() {",
            "    Record *rec = malloc(sizeof(Record));",
            "    if (!rec) return;",
            "    rec->id = 1;",
        ]
        assert _has_prior_malloc_in_scope(lines, 3, "rec") is True

    def test_has_prior_malloc_in_scope_not_found(self):
        from insert_me.pipeline.seeder import _has_prior_malloc_in_scope
        lines = [
            "void fn(Record *rec) {",
            "    rec->id = 1;",
        ]
        assert _has_prior_malloc_in_scope(lines, 1, "rec") is False

    def test_has_free_between_absent(self):
        from insert_me.pipeline.seeder import _has_free_between
        lines = [
            "    Record *rec = malloc(sizeof(Record));",  # idx 0
            "    if (!rec) return;",                       # idx 1
            "    rec->id = 1;",                            # idx 2
        ]
        assert _has_free_between(lines, 0, 2, "rec") is False

    def test_has_free_between_present(self):
        from insert_me.pipeline.seeder import _has_free_between
        lines = [
            "    Record *rec = malloc(sizeof(Record));",  # idx 0
            "    free(rec);",                              # idx 1  ← intervening free
            "    rec->id = 1;",                            # idx 2
        ]
        assert _has_free_between(lines, 0, 2, "rec") is True


# ---------------------------------------------------------------------------
# Pipeline integration: real mode
# ---------------------------------------------------------------------------

class TestCWE416PipelineRealMode:
    def test_patch_plan_status_applied(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        pp = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        assert pp["status"] == "APPLIED", f"Expected APPLIED, got {pp['status']}"

    def test_mutation_type_is_insert_premature_free(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert len(gt["mutations"]) == 1
        assert gt["mutations"][0]["mutation_type"] == "insert_premature_free"

    def test_mutated_fragment_is_free_call(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        frag = gt["mutations"][0]["mutated_fragment"]
        assert frag.startswith("free(") and frag.endswith(");")

    def test_extra_records_freed_pointer(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert "freed_pointer" in gt["mutations"][0]["extra"]

    def test_bad_file_contains_free_line(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        rel_file = gt["mutations"][0]["file"]
        bad_text = (bundle.bad_dir / rel_file).read_text(encoding="utf-8")
        freed_ptr = gt["mutations"][0]["extra"]["freed_pointer"]
        assert f"free({freed_ptr});" in bad_text

    def test_good_file_identical_to_source(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        rel_file = gt["mutations"][0]["file"]
        src_bytes = (DEMO_SOURCE / rel_file).read_bytes()
        good_bytes = (bundle.good_dir / rel_file).read_bytes()
        assert src_bytes == good_bytes, "good/ must be byte-identical to source"

    def test_bad_and_good_differ(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        rel_file = gt["mutations"][0]["file"]
        bad_bytes = (bundle.bad_dir / rel_file).read_bytes()
        good_bytes = (bundle.good_dir / rel_file).read_bytes()
        assert bad_bytes != good_bytes

    def test_bad_has_one_extra_line(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        rel_file = gt["mutations"][0]["file"]
        bad_lines = (bundle.bad_dir / rel_file).read_text(encoding="utf-8").splitlines()
        good_lines = (bundle.good_dir / rel_file).read_text(encoding="utf-8").splitlines()
        assert len(bad_lines) == len(good_lines) + 1, (
            "insert_premature_free should add exactly one line"
        )

    def test_audit_result_valid(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "VALID"

    def test_validation_passed(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        au = json.loads(bundle.audit.read_text(encoding="utf-8"))
        assert au["validation_verdict"]["passed"] is True

    def test_cwe_id_in_ground_truth(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=False)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["cwe_id"] == "CWE-416"

    def test_validate_bundle_exits_zero(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, "-m", "insert_me.cli", "run",
                "--seed-file", str(DEMO_SEED_CWE416),
                "--source", str(DEMO_SOURCE),
                "--output", str(tmp_path / "output"),
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"CLI run failed:\n{result.stderr}"
        )
        bundle_dir = next((tmp_path / "output").iterdir())
        r2 = subprocess.run(
            [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle_dir)],
            capture_output=True, text=True,
        )
        assert r2.returncode == 0, (
            f"validate-bundle failed:\n{r2.stdout}\n{r2.stderr}"
        )


# ---------------------------------------------------------------------------
# Pipeline integration: dry-run
# ---------------------------------------------------------------------------

class TestCWE416DryRun:
    def test_dry_run_classification_noop(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=True)
        ar = json.loads(bundle.audit_result.read_text(encoding="utf-8"))
        assert ar["classification"] == "NOOP"

    def test_dry_run_mutations_empty(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        bundle = run_pipeline(_make_config(tmp_path), dry_run=True)
        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["mutations"] == []

    def test_dry_run_source_unmodified(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        before = {
            f: f.stat().st_mtime
            for f in DEMO_SOURCE.rglob("*") if f.is_file()
        }
        run_pipeline(_make_config(tmp_path), dry_run=True)
        after = {
            f: f.stat().st_mtime
            for f in DEMO_SOURCE.rglob("*") if f.is_file()
        }
        assert before == after, "dry-run must not modify source files"


# ---------------------------------------------------------------------------
# Seeder: CWE-416 seed finds pointer_deref candidates in uaf_demo.c
# ---------------------------------------------------------------------------

class TestCWE416Seeder:
    def test_seeder_finds_candidates_in_uaf_demo(self):
        import json
        from insert_me.pipeline.seeder import Seeder
        seed_data = json.loads(DEMO_SEED_CWE416.read_text(encoding="utf-8"))
        seeder = Seeder(
            seed=seed_data["seed"],
            spec=seed_data,
            source_root=DEMO_SOURCE,
        )
        target_list = seeder.run()
        # uaf_demo.c should produce at least one pointer_deref candidate
        uaf_targets = [
            t for t in target_list.targets
            if "uaf_demo" in str(t.file)
        ]
        assert len(uaf_targets) > 0, (
            "Seeder should find pointer_deref candidates in uaf_demo.c"
        )

    def test_uaf_demo_candidates_above_min_score(self):
        import json
        from insert_me.pipeline.seeder import Seeder
        seed_data = json.loads(DEMO_SEED_CWE416.read_text(encoding="utf-8"))
        min_score = seed_data["target_pattern"]["min_candidate_score"]
        seeder = Seeder(
            seed=seed_data["seed"],
            spec=seed_data,
            source_root=DEMO_SOURCE,
        )
        target_list = seeder.run()
        for t in target_list.targets:
            assert t.score >= min_score, (
                f"Candidate {t.file}:{t.line} has score {t.score} < min {min_score}"
            )

    def test_uaf_demo_candidate_has_pointer_name_in_context(self):
        import json
        from insert_me.pipeline.seeder import Seeder
        seed_data = json.loads(DEMO_SEED_CWE416.read_text(encoding="utf-8"))
        seeder = Seeder(
            seed=seed_data["seed"],
            spec=seed_data,
            source_root=DEMO_SOURCE,
        )
        target_list = seeder.run()
        uaf_targets = [t for t in target_list.targets if "uaf_demo" in str(t.file)]
        for t in uaf_targets:
            assert "pointer_name" in t.context, (
                "pointer_deref candidates should have pointer_name in context"
            )
            assert t.context["pointer_name"] == "rec"
