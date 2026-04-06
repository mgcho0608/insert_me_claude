"""
Patcher tests for insert_me.

Coverage
--------
- _find_malloc_call: argument extraction with various malloc patterns
- _mutate_alloc_size_undercount: the mutation rule
- Patcher.run(): source tree copy, mutation application, skip behaviour
- good/ byte-identical to original; bad/ differs only at mutation site
- Mutation record fields (original_fragment, mutated_fragment)
- Incompatible targets (no malloc, unknown strategy) → skipped
- Empty target list → no copies made
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from insert_me.pipeline.patcher import (
    Mutation,
    Patcher,
    PatchResult,
    _find_malloc_call,
    _mutate_alloc_size_undercount,
    _STRATEGY_HANDLERS,
)
from insert_me.pipeline.seeder import PatchTarget, PatchTargetList


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(
    file: str,
    line: int,
    strategy: str = "alloc_size_undercount",
    score: float = 0.75,
) -> PatchTarget:
    return PatchTarget(
        file=Path(file),
        line=line,
        mutation_strategy=strategy,
        context={"expression": "", "function_name": ""},
        score=score,
    )


def _make_target_list(
    source_root: Path,
    targets: list[PatchTarget],
) -> PatchTargetList:
    return PatchTargetList(
        targets=targets,
        seed=42,
        spec_id="test",
        source_root=source_root,
        skipped_count=0,
        source_hash="test-hash",
    )


def _write_c(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Unit tests: _find_malloc_call
# ---------------------------------------------------------------------------


class TestFindMallocCall:
    def test_simple_malloc(self):
        result = _find_malloc_call("char *p = malloc(64);")
        assert result is not None
        start, end, arg = result
        assert arg == "64"
        assert "malloc(64)" in "char *p = malloc(64);"[start:end]

    def test_malloc_with_variable(self):
        _, _, arg = _find_malloc_call("void *p = malloc(n);")
        assert arg == "n"

    def test_malloc_with_arithmetic(self):
        _, _, arg = _find_malloc_call("char *buf = malloc(n * sizeof(char));")
        assert arg == "n * sizeof(char)"

    def test_malloc_with_sizeof_in_nested_parens(self):
        _, _, arg = _find_malloc_call("p = malloc(rows * cols * sizeof(double));")
        assert arg == "rows * cols * sizeof(double)"

    def test_no_malloc_returns_none(self):
        assert _find_malloc_call("free(ptr);") is None
        assert _find_malloc_call("int x = n * sizeof(char);") is None
        # Note: comment filtering is the Seeder's responsibility.
        # _find_malloc_call only receives lines the Seeder has already passed.

    def test_calloc_not_matched(self):
        assert _find_malloc_call("p = calloc(n, sizeof(int));") is None

    def test_malloc_with_expression_arithmetic(self):
        _, _, arg = _find_malloc_call("void *p = malloc(len + 1);")
        assert arg == "len + 1"

    def test_span_covers_whole_call(self):
        line = "    char *p = malloc(user_len * sizeof(char));"
        result = _find_malloc_call(line)
        assert result is not None
        start, end, arg = result
        assert line[start:end] == "malloc(user_len * sizeof(char))"


# ---------------------------------------------------------------------------
# Unit tests: _mutate_alloc_size_undercount
# ---------------------------------------------------------------------------


class TestAllocSizeUndercountStrategy:
    def test_simple_transform(self):
        result = _mutate_alloc_size_undercount("char *p = malloc(64);\n")
        assert result is not None
        mutated_line, orig, mutated = result
        assert orig == "malloc(64)"
        assert mutated == "malloc((64) - 1)"
        assert "malloc((64) - 1)" in mutated_line

    def test_arithmetic_arg_transform(self):
        line = "    char *buf = malloc(n * sizeof(char));\n"
        result = _mutate_alloc_size_undercount(line)
        assert result is not None
        mutated_line, orig, mutated = result
        assert orig == "malloc(n * sizeof(char))"
        assert mutated == "malloc((n * sizeof(char)) - 1)"
        assert "malloc((n * sizeof(char)) - 1)" in mutated_line

    def test_indentation_preserved(self):
        line = "    char *buf = malloc(n * sizeof(char));\n"
        result = _mutate_alloc_size_undercount(line)
        assert result is not None
        mutated_line, _, _ = result
        assert mutated_line.startswith("    ")

    def test_suffix_preserved(self):
        line = "    char *buf = malloc(n);\n"
        result = _mutate_alloc_size_undercount(line)
        assert result is not None
        mutated_line, _, _ = result
        assert mutated_line.endswith(";\n") or mutated_line.endswith(";")

    def test_no_malloc_returns_none(self):
        assert _mutate_alloc_size_undercount("free(ptr);\n") is None
        assert _mutate_alloc_size_undercount("int x = 5;\n") is None

    def test_strategy_registered(self):
        assert "alloc_size_undercount" in _STRATEGY_HANDLERS


# ---------------------------------------------------------------------------
# Integration tests: Patcher.run()
# ---------------------------------------------------------------------------


class TestPatcherCopies:
    def test_good_is_byte_identical_to_original(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        c_file = src / "foo.c"
        original_content = "void f(int n) { char *p = malloc(n * sizeof(char)); }\n"
        _write_c(c_file, original_content)

        target = _make_target("foo.c", 1)
        tlist = _make_target_list(src, [target])

        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        patcher.run()

        good_file = tmp_path / "good" / "foo.c"
        assert good_file.exists()
        assert good_file.read_text(encoding="utf-8") == original_content

    def test_bad_differs_at_mutation_site(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        c_file = src / "foo.c"
        _write_c(c_file, "void f(int n) { char *p = malloc(n * sizeof(char)); }\n")

        target = _make_target("foo.c", 1)
        tlist = _make_target_list(src, [target])

        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 1
        bad_content = (tmp_path / "bad" / "foo.c").read_text(encoding="utf-8")
        good_content = (tmp_path / "good" / "foo.c").read_text(encoding="utf-8")
        assert bad_content != good_content
        assert "malloc((n * sizeof(char)) - 1)" in bad_content
        assert "malloc(n * sizeof(char))" in good_content

    def test_good_unchanged_after_bad_written(self, tmp_path):
        """Mutation of bad/ must not affect good/."""
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "x.c", "char *p = malloc(len);\n")

        tlist = _make_target_list(src, [_make_target("x.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        patcher.run()

        good = (tmp_path / "good" / "x.c").read_text(encoding="utf-8")
        assert "malloc(len)" in good
        assert "- 1" not in good

    def test_multiple_files_all_copied(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "a.c", "void fa(int n) { char *p = malloc(n); }\n")
        _write_c(src / "b.c", "void fb(void) { return; }\n")

        tlist = _make_target_list(src, [_make_target("a.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        patcher.run()

        # Both files copied to good/ and bad/
        assert (tmp_path / "good" / "a.c").exists()
        assert (tmp_path / "good" / "b.c").exists()
        assert (tmp_path / "bad" / "a.c").exists()
        assert (tmp_path / "bad" / "b.c").exists()

        # Only a.c is mutated in bad/; b.c is byte-identical in both
        bad_b = (tmp_path / "bad" / "b.c").read_text(encoding="utf-8")
        good_b = (tmp_path / "good" / "b.c").read_text(encoding="utf-8")
        assert bad_b == good_b


class TestMutationRecord:
    def test_mutation_record_fields(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "m.c", "void g(int n) { char *p = malloc(n * sizeof(int)); }\n")

        tlist = _make_target_list(src, [_make_target("m.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 1
        m = result.mutations[0]
        assert m.mutation_type == "alloc_size_undercount"
        assert "malloc(n * sizeof(int))" in m.original_fragment
        assert "malloc((n * sizeof(int)) - 1)" in m.mutated_fragment
        assert m.target.line == 1

    def test_mutation_record_does_not_contain_newline(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "n.c", "char *p = malloc(sz);\n")

        tlist = _make_target_list(src, [_make_target("n.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        m = result.mutations[0]
        assert "\n" not in m.original_fragment
        assert "\n" not in m.mutated_fragment

    def test_result_has_no_skipped_targets_on_success(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "ok.c", "char *p = malloc(n);\n")

        tlist = _make_target_list(src, [_make_target("ok.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 1
        assert len(result.skipped_targets) == 0


class TestSkippedTargets:
    def test_no_malloc_on_line_skips_target(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "nope.c", "int x = 5;\n")

        tlist = _make_target_list(src, [_make_target("nope.c", 1)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 1

    def test_unknown_strategy_skips_target(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "unk.c", "char *p = malloc(n);\n")

        target = _make_target("unk.c", 1, strategy="insert_premature_free")
        tlist = _make_target_list(src, [target])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 1
        # Source trees are still copied even when mutation is skipped
        assert (tmp_path / "good" / "unk.c").exists()
        assert (tmp_path / "bad" / "unk.c").exists()

    def test_out_of_range_line_skips_target(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "short.c", "int x = 1;\n")

        tlist = _make_target_list(src, [_make_target("short.c", 99)])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 1

    def test_only_first_target_attempted(self, tmp_path):
        """Phase 4: only first target is tried, rest are not attempted."""
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "t.c", "char *a = malloc(n);\nchar *b = malloc(m);\n")

        targets = [_make_target("t.c", 1), _make_target("t.c", 2)]
        tlist = _make_target_list(src, targets)
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        # Only first target is tried; second is not attempted at all
        assert len(result.mutations) == 1
        assert result.mutations[0].target.line == 1
        # Second target does not appear in skipped (it was never tried)
        assert len(result.skipped_targets) == 0

        # Line 2 in bad/ should be unchanged
        bad_lines = (tmp_path / "bad" / "t.c").read_text(encoding="utf-8").splitlines()
        assert "malloc(m)" in bad_lines[1]  # line 2 unchanged


class TestEmptyTargets:
    def test_no_targets_returns_empty_result(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        _write_c(src / "empty.c", "int main() { return 0; }\n")

        tlist = _make_target_list(src, [])
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()

        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 0
        # No copies made when targets list is empty
        assert not (tmp_path / "good").exists() or not any((tmp_path / "good").iterdir())

    def test_nonexistent_source_root_returns_empty(self, tmp_path):
        tlist = _make_target_list(
            tmp_path / "no_such_dir",
            [_make_target("x.c", 1)],
        )
        patcher = Patcher(targets=tlist, bad_root=tmp_path / "bad", good_root=tmp_path / "good")
        result = patcher.run()
        # Copies are attempted but source doesn't exist → good/bad are empty dirs
        assert len(result.mutations) == 0


# ---------------------------------------------------------------------------
# Integration: pipeline run_pipeline with real patching
# ---------------------------------------------------------------------------


class TestPipelineRealMode:
    """Test run_pipeline with dry_run=False against the demo fixture."""

    def _make_config(self, tmp_path: Path, seed_file: Path, source_path: Path):
        from insert_me.config import Config
        cfg = Config()
        cfg.pipeline.seed_file = seed_file
        cfg.pipeline.source_path = source_path
        cfg.pipeline.output_root = tmp_path / "output"
        return cfg

    def test_real_mode_produces_applied_status(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        repo_root = Path(__file__).parent.parent
        seed_file = repo_root / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = repo_root / "examples" / "demo" / "src"

        cfg = self._make_config(tmp_path, seed_file, source)
        bundle = run_pipeline(cfg, dry_run=False)

        import json
        plan = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        assert plan["status"] == "APPLIED"

    def test_real_mode_ground_truth_has_mutation(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        repo_root = Path(__file__).parent.parent
        seed_file = repo_root / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = repo_root / "examples" / "demo" / "src"

        cfg = self._make_config(tmp_path, seed_file, source)
        bundle = run_pipeline(cfg, dry_run=False)

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert len(gt["mutations"]) == 1
        m = gt["mutations"][0]
        assert m["mutation_type"] == "alloc_size_undercount"
        assert "malloc(" in m["original_fragment"]
        assert "- 1)" in m["mutated_fragment"]

    def test_real_mode_bad_and_good_dirs_written(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        repo_root = Path(__file__).parent.parent
        seed_file = repo_root / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = repo_root / "examples" / "demo" / "src"

        cfg = self._make_config(tmp_path, seed_file, source)
        bundle = run_pipeline(cfg, dry_run=False)

        # Both trees written
        assert bundle.bad_dir.is_dir()
        assert bundle.good_dir.is_dir()
        bad_files = list(bundle.bad_dir.rglob("*.c"))
        good_files = list(bundle.good_dir.rglob("*.c"))
        assert len(bad_files) > 0
        assert len(good_files) > 0

    def test_real_mode_bad_differs_from_good(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        repo_root = Path(__file__).parent.parent
        seed_file = repo_root / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = repo_root / "examples" / "demo" / "src"

        cfg = self._make_config(tmp_path, seed_file, source)
        bundle = run_pipeline(cfg, dry_run=False)

        bad_c = next(bundle.bad_dir.rglob("*.c"))
        good_c = bundle.good_dir / bad_c.relative_to(bundle.bad_dir)

        bad_text = bad_c.read_text(encoding="utf-8")
        good_text = good_c.read_text(encoding="utf-8")

        assert bad_text != good_text
        assert "- 1)" in bad_text
        assert "- 1)" not in good_text

    def test_dry_run_mode_no_mutation(self, tmp_path):
        from insert_me.pipeline import run_pipeline
        repo_root = Path(__file__).parent.parent
        seed_file = repo_root / "examples" / "seeds" / "cwe122_heap_overflow.json"
        source = repo_root / "examples" / "demo" / "src"

        cfg = self._make_config(tmp_path, seed_file, source)
        bundle = run_pipeline(cfg, dry_run=True)

        gt = json.loads(bundle.ground_truth.read_text(encoding="utf-8"))
        assert gt["mutations"] == []

        plan = json.loads(bundle.patch_plan.read_text(encoding="utf-8"))
        assert plan["status"] == "PLANNED"
