"""
Seeder tests for insert_me.

Coverage
--------
- Source file discovery: ordering, extension filtering, exclude patterns
- Candidate extraction from fixture C files (per pattern_type)
- Deterministic target ordering across repeated runs
- Seed integer affects ordering within equal-score tiers
- patch_plan.json contains real targets when source fixtures are available
- validate-bundle succeeds on a bundle generated from fixture source
- Empty source tree → empty patch_plan with status PENDING
- Strict validate_bundle catches missing core artifacts
"""

from __future__ import annotations

import json
import copy
from pathlib import Path

import pytest

from insert_me.artifacts import BundlePaths
from insert_me.config import Config
from insert_me.pipeline import run_pipeline
from insert_me.pipeline.seeder import (
    DEFAULT_EXCLUDE_PATTERNS,
    PATTERN_REGEXES,
    SOURCE_EXTENSIONS,
    PatchTarget,
    PatchTargetList,
    Seeder,
    _compute_source_hash,
    _find_enclosing_function,
)
from insert_me.schema import (
    SCHEMA_PATCH_PLAN,
    load_example,
    validate_artifact_file,
    validate_bundle,
)


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "c_src"

SEED_CWE122 = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
SEED_CWE416 = REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json"
SEED_CWE190 = REPO_ROOT / "examples" / "seeds" / "cwe190_integer_overflow.json"


def _load_seed(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _make_seeder(seed_path: Path, source_root: Path) -> Seeder:
    spec = _load_seed(seed_path)
    return Seeder(seed=spec["seed"], spec=spec, source_root=source_root)


def _make_config(tmp_path: Path, seed_file: Path, source_path: Path) -> Config:
    cfg = Config()
    cfg.pipeline.seed_file = seed_file
    cfg.pipeline.source_path = source_path
    cfg.pipeline.output_root = tmp_path / "output"
    return cfg


# ---------------------------------------------------------------------------
# Source file discovery
# ---------------------------------------------------------------------------


class TestSourceDiscovery:
    def test_discovers_c_files(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        files = seeder._discover_sources()
        assert len(files) >= 3
        names = {f.name for f in files}
        assert "heap_ops.c" in names
        assert "string_ops.c" in names
        assert "ptr_ops.c" in names

    def test_only_c_cpp_extensions(self, tmp_path):
        (tmp_path / "foo.c").write_text("int x;")
        (tmp_path / "bar.py").write_text("x = 1")
        (tmp_path / "baz.txt").write_text("hello")
        (tmp_path / "qux.h").write_text("void f();")
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        files = seeder._discover_sources()
        names = {f.name for f in files}
        assert "foo.c" in names
        assert "qux.h" in names
        assert "bar.py" not in names
        assert "baz.txt" not in names

    def test_ordering_is_lexicographic(self, tmp_path):
        """Files must be returned in deterministic lexicographic order."""
        (tmp_path / "z_last.c").write_text("")
        (tmp_path / "a_first.c").write_text("")
        (tmp_path / "m_middle.c").write_text("")
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        files = seeder._discover_sources()
        names = [f.name for f in files]
        assert names == sorted(names)

    def test_ordering_is_stable_across_runs(self):
        """Same discovery called twice must return the same order."""
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        files1 = seeder._discover_sources()
        files2 = seeder._discover_sources()
        assert [str(f) for f in files1] == [str(f) for f in files2]

    def test_exclude_test_files(self, tmp_path):
        (tmp_path / "real.c").write_text("int x;")
        (tmp_path / "test_foo.c").write_text("void test_x() {}")
        (tmp_path / "foo_test.c").write_text("void test_y() {}")
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        files = seeder._discover_sources()
        names = {f.name for f in files}
        assert "real.c" in names
        assert "test_foo.c" not in names
        assert "foo_test.c" not in names

    def test_custom_exclude_patterns_respected(self, tmp_path):
        (tmp_path / "keep.c").write_text("int x;")
        (tmp_path / "skip_me.c").write_text("int y;")
        spec = _load_seed(SEED_CWE122)
        spec.setdefault("source_constraints", {})["exclude_patterns"] = ["skip_*.c"]
        seeder = Seeder(seed=42, spec=spec, source_root=tmp_path)
        files = seeder._discover_sources()
        names = {f.name for f in files}
        assert "keep.c" in names
        assert "skip_me.c" not in names

    def test_nonexistent_source_root_returns_empty(self, tmp_path):
        seeder = _make_seeder(SEED_CWE122, tmp_path / "no_such_dir")
        assert seeder._discover_sources() == []

    def test_all_source_extensions_accepted(self, tmp_path):
        for ext in SOURCE_EXTENSIONS:
            (tmp_path / f"file{ext}").write_text("void f() {}")
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        exts_found = {f.suffix for f in seeder._discover_sources()}
        assert exts_found == SOURCE_EXTENSIONS


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------


class TestCandidateExtraction:
    def test_malloc_candidates_from_heap_ops(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        assert len(candidates) > 0, "Expected malloc candidates in heap_ops.c"
        # All should match malloc pattern
        for c in candidates:
            assert PATTERN_REGEXES["malloc_call"].search(c.context["expression"])

    def test_string_candidates_from_string_ops(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        # Manually override pattern type for this test
        seeder._pattern_type = "string_operation"
        candidates = seeder._extract_candidates(FIXTURES_DIR / "string_ops.c")
        assert len(candidates) > 0
        exprs = [c.context["expression"] for c in candidates]
        # Gets() and strcpy() should be in the results
        assert any("strcpy" in e or "gets" in e or "strcat" in e for e in exprs)

    def test_format_string_candidates(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        seeder._pattern_type = "format_string"
        candidates = seeder._extract_candidates(FIXTURES_DIR / "string_ops.c")
        assert len(candidates) > 0
        exprs = [c.context["expression"] for c in candidates]
        assert any("printf" in e or "fprintf" in e or "sprintf" in e for e in exprs)

    def test_pointer_deref_candidates(self):
        seeder = _make_seeder(SEED_CWE416, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "ptr_ops.c")
        assert len(candidates) > 0

    def test_loop_bound_candidates(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        seeder._pattern_type = "loop_bound"
        candidates = seeder._extract_candidates(FIXTURES_DIR / "ptr_ops.c")
        assert len(candidates) > 0
        assert all("for" in c.context["expression"] for c in candidates)

    def test_integer_arithmetic_candidates(self):
        seeder = _make_seeder(SEED_CWE190, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        assert len(candidates) > 0

    def test_file_field_is_relative_path(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        assert len(candidates) > 0
        for c in candidates:
            assert not c.file.is_absolute(), f"Expected relative path, got {c.file}"
            assert c.file.name == "heap_ops.c"

    def test_line_numbers_are_1_based(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        for c in candidates:
            assert c.line >= 1

    def test_comment_lines_excluded(self, tmp_path):
        c_file = tmp_path / "commented.c"
        c_file.write_text(
            "// malloc(n * sizeof(char)) - this is a comment\n"
            "char *p = malloc(n);\n"
            "/* malloc(big_n) also in block comment */\n",
            encoding="utf-8",
        )
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        candidates = seeder._extract_candidates(c_file)
        # Only the non-comment malloc call should be found
        assert len(candidates) == 1
        assert "malloc(n)" in candidates[0].context["expression"]

    def test_context_has_expression_and_function_name(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        for c in candidates:
            assert "expression" in c.context
            assert "function_name" in c.context
            assert isinstance(c.context["expression"], str)
            assert isinstance(c.context["function_name"], str)

    def test_function_name_extracted(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        candidates = seeder._extract_candidates(FIXTURES_DIR / "heap_ops.c")
        # Most malloc calls should have an enclosing function name
        names = [c.context["function_name"] for c in candidates]
        assert any(n != "" for n in names), "Expected at least one function_name"

    def test_nonexistent_file_returns_empty(self, tmp_path):
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        candidates = seeder._extract_candidates(tmp_path / "no_such_file.c")
        assert candidates == []


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestScoring:
    def test_malloc_with_arithmetic_scores_higher(self, tmp_path):
        c_file = tmp_path / "score.c"
        c_file.write_text(
            "void f1(int n) { char *a = malloc(n * sizeof(char)); }\n"
            "void f2(int n) { char *b = malloc(64); }\n"
        )
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 2
        # Arithmetic malloc should score higher
        arith = next(c for c in candidates if "sizeof" in c.context["expression"])
        plain = next(c for c in candidates if "64" in c.context["expression"])
        assert arith.score > plain.score

    def test_gets_scores_highest_for_string_pattern(self, tmp_path):
        c_file = tmp_path / "score2.c"
        c_file.write_text(
            "void g1(char *s) { char buf[64]; strcpy(buf, s); }\n"
            "void g2(char *s) { gets(s); }\n"
        )
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        seeder._pattern_type = "string_operation"
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 2
        gets_c = next(c for c in candidates if "gets" in c.context["expression"])
        strcpy_c = next(c for c in candidates if "strcpy" in c.context["expression"])
        assert gets_c.score > strcpy_c.score

    def test_scores_in_valid_range(self):
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        result = seeder.run()
        for t in result.targets:
            assert 0.0 <= t.score <= 1.0, f"Score {t.score} out of range"

    def test_loop_with_le_scores_higher(self, tmp_path):
        c_file = tmp_path / "loops.c"
        c_file.write_text(
            "void f1(int n) { for (int i = 0; i <= n; i++) {} }\n"
            "void f2(int n) { for (int i = 0; i < n; i++) {} }\n"
        )
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        seeder._pattern_type = "loop_bound"
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 2
        le = next(c for c in candidates if "<=" in c.context["expression"])
        lt = next(c for c in candidates if "<=" not in c.context["expression"])
        assert le.score > lt.score


# ---------------------------------------------------------------------------
# Deterministic ordering
# ---------------------------------------------------------------------------


class TestDeterministicOrdering:
    def test_same_run_same_order(self):
        """Same seed + same source → identical target list."""
        seeder1 = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        result1 = seeder1.run()

        seeder2 = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        result2 = seeder2.run()

        assert len(result1.targets) == len(result2.targets)
        for t1, t2 in zip(result1.targets, result2.targets):
            assert t1.file == t2.file
            assert t1.line == t2.line
            assert t1.score == t2.score

    def test_different_seed_may_differ_in_equal_score_tiers(self, tmp_path):
        """Different seed integers should produce potentially different orderings
        within equal-score tiers (different RNG shuffle)."""
        # Create multiple files with identical patterns (same score).
        # Use malloc with arithmetic so score > 0.5 and passes any min_candidate_score.
        for i in range(5):
            (tmp_path / f"file{i:02d}.c").write_text(
                f"void func{i}(int n) {{ char *p = malloc(n * sizeof(char)); }}\n",
                encoding="utf-8",
            )
        # Build a spec without max_targets and without min_candidate_score
        # so all 5 candidates are kept
        spec = _load_seed(SEED_CWE122)
        spec.pop("source_constraints", None)  # remove max_targets=1 limit
        spec["target_pattern"].pop("min_candidate_score", None)

        orderings = []
        for seed_int in [1, 2, 3, 42, 137]:
            spec_copy = copy.deepcopy(spec)
            spec_copy["seed"] = seed_int
            seeder = Seeder(seed=seed_int, spec=spec_copy, source_root=tmp_path)
            result = seeder.run()
            orderings.append(tuple(str(t.file) for t in result.targets))

        # At least two different orderings should exist (very likely with 5 files,
        # all in the same score tier being shuffled differently per seed)
        assert len(set(orderings)) > 1, (
            "Expected at least two distinct orderings across different seeds"
        )

    def test_ordering_score_descending(self):
        """Targets must appear in non-increasing score order."""
        seeder = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        result = seeder.run()
        scores = [t.score for t in result.targets]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Score not descending at index {i}: {scores[i]} < {scores[i+1]}"
            )

    def test_source_hash_deterministic(self):
        seeder1 = _make_seeder(SEED_CWE122, FIXTURES_DIR)
        r1 = seeder1.run()

        seeder2 = _make_seeder(SEED_CWE416, FIXTURES_DIR)
        r2 = seeder2.run()

        # Same source tree → same hash regardless of seed
        assert r1.source_hash == r2.source_hash


# ---------------------------------------------------------------------------
# memcpy / read / recv heuristics
# ---------------------------------------------------------------------------


class TestMemcpyReadRecvHeuristics:
    """Verify that memcpy, memmove, read, recv, recvfrom are detected and scored."""

    IO_FIXTURE = FIXTURES_DIR / "io_ops.c"

    def _string_seeder(self, source_root: Path) -> Seeder:
        """Return a Seeder configured for string_operation pattern."""
        spec = _load_seed(SEED_CWE122)
        spec["target_pattern"]["pattern_type"] = "string_operation"
        spec["target_pattern"].pop("min_candidate_score", None)
        spec.pop("source_constraints", None)
        return Seeder(seed=spec["seed"], spec=spec, source_root=source_root)

    def test_memcpy_detected_in_fixture(self):
        seeder = self._string_seeder(FIXTURES_DIR)
        candidates = seeder._extract_candidates(self.IO_FIXTURE)
        exprs = [c.context["expression"] for c in candidates]
        assert any("memcpy" in e for e in exprs), (
            f"Expected memcpy candidate in io_ops.c; got: {exprs}"
        )

    def test_memmove_detected_in_fixture(self):
        seeder = self._string_seeder(FIXTURES_DIR)
        candidates = seeder._extract_candidates(self.IO_FIXTURE)
        exprs = [c.context["expression"] for c in candidates]
        assert any("memmove" in e for e in exprs), (
            f"Expected memmove candidate in io_ops.c; got: {exprs}"
        )

    def test_read_detected_in_fixture(self):
        seeder = self._string_seeder(FIXTURES_DIR)
        candidates = seeder._extract_candidates(self.IO_FIXTURE)
        exprs = [c.context["expression"] for c in candidates]
        assert any("read(" in e for e in exprs), (
            f"Expected read() candidate in io_ops.c; got: {exprs}"
        )

    def test_recv_detected_in_fixture(self):
        seeder = self._string_seeder(FIXTURES_DIR)
        candidates = seeder._extract_candidates(self.IO_FIXTURE)
        exprs = [c.context["expression"] for c in candidates]
        assert any("recv(" in e for e in exprs), (
            f"Expected recv() candidate in io_ops.c; got: {exprs}"
        )

    def test_recvfrom_detected_in_fixture(self):
        seeder = self._string_seeder(FIXTURES_DIR)
        candidates = seeder._extract_candidates(self.IO_FIXTURE)
        exprs = [c.context["expression"] for c in candidates]
        assert any("recvfrom(" in e for e in exprs), (
            f"Expected recvfrom() candidate in io_ops.c; got: {exprs}"
        )

    def test_recv_scores_higher_than_memcpy(self, tmp_path):
        """recv/read score 0.85, memcpy/strcpy score 0.75 — recv ranks first."""
        c_file = tmp_path / "test.c"
        c_file.write_text(
            "void f1(int fd, char *buf) { read(fd, buf, 256); }\n"
            "void f2(char *dst, char *src) { memcpy(dst, src, 256); }\n",
            encoding="utf-8",
        )
        seeder = self._string_seeder(tmp_path)
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 2
        read_c = next(c for c in candidates if "read(" in c.context["expression"])
        memcpy_c = next(c for c in candidates if "memcpy" in c.context["expression"])
        assert read_c.score > memcpy_c.score

    def test_gets_still_highest(self, tmp_path):
        """gets() must still outscore read/recv."""
        c_file = tmp_path / "test.c"
        c_file.write_text(
            "void f1(int fd, char *buf) { recv(fd, buf, 256, 0); }\n"
            "void f2(char *s) { gets(s); }\n",
            encoding="utf-8",
        )
        seeder = self._string_seeder(tmp_path)
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 2
        gets_c = next(c for c in candidates if "gets(" in c.context["expression"])
        recv_c = next(c for c in candidates if "recv(" in c.context["expression"])
        assert gets_c.score > recv_c.score

    def test_custom_pattern_detects_recv(self, tmp_path):
        """The 'custom' fallback pattern should also pick up recv calls."""
        c_file = tmp_path / "test.c"
        c_file.write_text(
            "void f(int s, char *buf) { recv(s, buf, 512, 0); }\n",
            encoding="utf-8",
        )
        spec = _load_seed(SEED_CWE122)
        spec["target_pattern"]["pattern_type"] = "custom"
        spec["target_pattern"].pop("min_candidate_score", None)
        spec.pop("source_constraints", None)
        seeder = Seeder(seed=spec["seed"], spec=spec, source_root=tmp_path)
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 1
        assert "recv(" in candidates[0].context["expression"]

    def test_custom_pattern_detects_memcpy(self, tmp_path):
        """The 'custom' fallback pattern should also pick up memcpy calls."""
        c_file = tmp_path / "test.c"
        c_file.write_text(
            "void f(char *dst, char *src, int n) { memcpy(dst, src, n); }\n",
            encoding="utf-8",
        )
        spec = _load_seed(SEED_CWE122)
        spec["target_pattern"]["pattern_type"] = "custom"
        spec["target_pattern"].pop("min_candidate_score", None)
        spec.pop("source_constraints", None)
        seeder = Seeder(seed=spec["seed"], spec=spec, source_root=tmp_path)
        candidates = seeder._extract_candidates(c_file)
        assert len(candidates) == 1
        assert "memcpy" in candidates[0].context["expression"]

    def test_pattern_regex_keys_present(self):
        """Ensure PATTERN_REGEXES contains 'string_operation' and 'custom' with new patterns."""
        import re
        assert "string_operation" in PATTERN_REGEXES
        assert "custom" in PATTERN_REGEXES
        # Verify new functions match
        for func in ("memcpy", "memmove", "read", "recv", "recvfrom"):
            line = f"    {func}(dst, src, len);"
            assert PATTERN_REGEXES["string_operation"].search(line), (
                f"string_operation regex did not match '{func}'"
            )
            assert PATTERN_REGEXES["custom"].search(line), (
                f"custom regex did not match '{func}'"
            )

    def test_source_hash_changes_with_content(self, tmp_path):
        (tmp_path / "f.c").write_text("void a() { malloc(1); }")
        s1 = _make_seeder(SEED_CWE122, tmp_path)
        h1 = s1.run().source_hash

        (tmp_path / "f.c").write_text("void a() { malloc(2); }")
        s2 = _make_seeder(SEED_CWE122, tmp_path)
        h2 = s2.run().source_hash

        assert h1 != h2


# ---------------------------------------------------------------------------
# Empty source tree
# ---------------------------------------------------------------------------


class TestEmptyOrMissingSource:
    def test_empty_dir_returns_no_targets(self, tmp_path):
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        result = seeder.run()
        assert result.targets == []
        assert result.source_hash == "no-sources"

    def test_missing_source_dir_returns_no_targets(self, tmp_path):
        seeder = _make_seeder(SEED_CWE122, tmp_path / "nonexistent")
        result = seeder.run()
        assert result.targets == []

    def test_no_c_files_returns_no_targets(self, tmp_path):
        (tmp_path / "readme.txt").write_text("docs")
        (tmp_path / "script.py").write_text("pass")
        seeder = _make_seeder(SEED_CWE122, tmp_path)
        result = seeder.run()
        assert result.targets == []
        assert result.source_hash == "no-sources"


# ---------------------------------------------------------------------------
# Pipeline integration: patch_plan with real targets
# ---------------------------------------------------------------------------


class TestPipelineWithFixtures:
    def test_patch_plan_has_real_targets_from_fixtures(self, tmp_path):
        """When source files exist, patch_plan.json must have targets > 0."""
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)

        assert plan["status"] == "PLANNED"
        assert len(plan["targets"]) > 0

    def test_patch_plan_target_structure(self, tmp_path):
        """Each target must have the required schema fields."""
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)

        for t in plan["targets"]:
            assert "target_id" in t
            assert "file" in t
            assert "line" in t and t["line"] >= 1
            assert "mutation_strategy" in t
            assert "candidate_score" in t
            assert 0.0 <= t["candidate_score"] <= 1.0
            assert "context" in t
            assert "expression" in t["context"]

    def test_patch_plan_validates_against_schema(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)
        validate_artifact_file(bundle.patch_plan, SCHEMA_PATCH_PLAN)

    def test_validate_bundle_succeeds_on_fixture_run(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)
        errors = validate_bundle(bundle.root)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_audit_json_has_real_source_hash(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.audit, encoding="utf-8") as fh:
            audit = json.load(fh)

        assert audit["source_hash"] != "no-sources"
        assert audit["source_hash"] != "dry-run"
        assert len(audit["source_hash"]) == 16

    def test_patch_plan_targets_reference_existing_files(self, tmp_path):
        """All target file paths must point to files that exist in FIXTURES_DIR."""
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)

        for t in plan["targets"]:
            file_path = FIXTURES_DIR / t["file"]
            assert file_path.exists(), f"Target file not found: {file_path}"

    def test_empty_source_produces_pending_patch_plan(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122, tmp_path / "empty_src")
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)

        assert plan["status"] == "PENDING"
        assert plan["targets"] == []

    def test_deterministic_output_repeated_runs(self, tmp_path):
        """Same inputs → same patch_plan targets across two runs."""
        cfg1 = _make_config(tmp_path / "run1", SEED_CWE122, FIXTURES_DIR)
        cfg1.pipeline.output_root = tmp_path / "out1"
        b1 = run_pipeline(cfg1, dry_run=True)

        cfg2 = _make_config(tmp_path / "run2", SEED_CWE122, FIXTURES_DIR)
        cfg2.pipeline.output_root = tmp_path / "out2"
        b2 = run_pipeline(cfg2, dry_run=True)

        with open(b1.patch_plan, encoding="utf-8") as fh:
            p1 = json.load(fh)
        with open(b2.patch_plan, encoding="utf-8") as fh:
            p2 = json.load(fh)

        assert p1["targets"] == p2["targets"]
        assert p1["run_id"] == p2["run_id"]

    def test_max_targets_respected(self, tmp_path):
        spec = _load_seed(SEED_CWE122)
        spec.setdefault("source_constraints", {})["max_targets"] = 1

        seed_file = tmp_path / "seed_limited.json"
        seed_file.write_text(json.dumps(spec))

        cfg = _make_config(tmp_path, seed_file, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.patch_plan, encoding="utf-8") as fh:
            plan = json.load(fh)

        assert len(plan["targets"]) <= 1

    def test_audit_result_evidence_mentions_candidate_count(self, tmp_path):
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        with open(bundle.audit_result, encoding="utf-8") as fh:
            ar = json.load(fh)

        obs = ar["evidence"][0]["observation"]
        assert "candidate" in obs.lower() or "target" in obs.lower()


# ---------------------------------------------------------------------------
# validate_bundle strict mode
# ---------------------------------------------------------------------------


class TestValidateBundleStrict:
    def test_strict_empty_dir_still_no_errors(self, tmp_path):
        """strict=True on a completely empty dir should not error.
        Strict mode only activates when at least one core artifact is present."""
        errors = validate_bundle(tmp_path, strict=True)
        assert errors == [], f"Unexpected errors on empty dir: {errors}"

    def test_auto_strict_when_audit_present_missing_core_artifact(self, tmp_path):
        """If audit.json is present but patch_plan.json is not, auto-strict catches it."""
        # Write minimal valid audit.json
        import json as _json
        from insert_me import ARTIFACT_SCHEMA_VERSION
        from insert_me.artifacts import write_json_artifact

        audit = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "run_id": "aabbccddeeff0011",
            "seed": 42,
            "spec_path": "examples/seeds/cwe122.json",
            "spec_hash": "abc",
            "source_root": ".",
            "source_hash": "no-sources",
            "pipeline_version": "0.1.0.dev0",
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "validation_verdict": {"passed": False, "checks": []},
        }
        write_json_artifact(tmp_path / "audit.json", audit)

        errors = validate_bundle(tmp_path)
        # Should report missing core artifacts (patch_plan, validation_result, etc.)
        assert len(errors) > 0
        assert any("patch_plan.json" in e for e in errors)

    def test_complete_bundle_no_errors(self, tmp_path):
        """A complete dry-run bundle should pass strict validation."""
        cfg = _make_config(tmp_path, SEED_CWE122, FIXTURES_DIR)
        bundle = run_pipeline(cfg, dry_run=True)

        errors = validate_bundle(bundle.root, strict=True)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_strict_flag_forces_missing_errors(self, tmp_path):
        """strict=True should report missing core artifacts even without audit.json."""
        # Put only patch_plan in an otherwise empty dir
        from insert_me import ARTIFACT_SCHEMA_VERSION
        from insert_me.artifacts import write_json_artifact

        plan = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "plan_id": "plan-aabbccdd11223344",
            "run_id": "aabbccdd11223344",
            "seed_id": "test",
            "seed": 42,
            "status": "PENDING",
            "created_at": "2026-01-01T00:00:00Z",
            "targets": [],
        }
        write_json_artifact(tmp_path / "patch_plan.json", plan)

        errors = validate_bundle(tmp_path, strict=True)
        # Other core artifacts are missing
        assert any("validation_result.json" in e for e in errors)
        assert any("audit.json" in e for e in errors)
