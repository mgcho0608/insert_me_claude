"""
Tests for the remove_null_guard strategy (CWE-476) and multi-line mutation
infrastructure.

Coverage
--------
MultilineMutationResult dataclass
_register_multiline decorator
_MULTILINE_STRATEGY_HANDLERS registry

remove_null_guard handler:
  - Simple !ptr guard matched and replaced with comment
  - ptr == NULL guard matched and replaced with comment
  - NULL == ptr (reversed) guard matched
  - Guard with a non-matching pointer is skipped (returns None)
  - No guard in preceding lines returns None
  - Blank lines between guard and deref are skipped
  - Non-guard code line between guard and deref blocks match

Patcher._apply_mutation with multi-line strategy:
  - Guard line replaced in bad/ file; good/ file unchanged
  - Mutation record carries correct original/mutated fragments
  - extra dict contains guard_line, deref_line, guarded_pointer

Seeder null_guard pattern type:
  - Matches !ptr guard lines
  - Matches ptr == NULL guard lines
  - Does not match a plain if() with arithmetic condition
  - Scoring: single-line return guard scores higher than fallback
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from insert_me.pipeline.patcher import (
    MultilineMutationResult,
    Patcher,
    _MULTILINE_STRATEGY_HANDLERS,
    _mutate_remove_null_guard,
)
from insert_me.pipeline.seeder import PATTERN_REGEXES, Seeder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lines(src: str) -> list[str]:
    """Convert a source snippet to a list of lines with keepends=True."""
    return src.splitlines(keepends=True)


# ---------------------------------------------------------------------------
# MultilineMutationResult dataclass
# ---------------------------------------------------------------------------

class TestMultilineMutationResult:
    def test_default_fields(self):
        r = MultilineMutationResult(
            original_fragment="if (!ptr) return;",
            mutated_fragment="/* CWE-476: null guard removed */",
        )
        assert r.line_replacements == {}
        assert r.extra == {}

    def test_custom_fields(self):
        r = MultilineMutationResult(
            original_fragment="orig",
            mutated_fragment="mutated",
            line_replacements={3: "/* x */\n"},
            extra={"guard_line": 4, "guarded_pointer": "p"},
        )
        assert r.line_replacements == {3: "/* x */\n"}
        assert r.extra["guarded_pointer"] == "p"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestMultilineRegistry:
    def test_remove_null_guard_registered(self):
        assert "remove_null_guard" in _MULTILINE_STRATEGY_HANDLERS

    def test_not_in_single_line_registry(self):
        from insert_me.pipeline.patcher import _STRATEGY_HANDLERS
        assert "remove_null_guard" not in _STRATEGY_HANDLERS


# ---------------------------------------------------------------------------
# _mutate_remove_null_guard handler
# ---------------------------------------------------------------------------

class TestRemoveNullGuardHandler:

    def _call(self, src: str, deref_line_1based: int) -> MultilineMutationResult | None:
        """Helper: parse src and call handler at the given 1-based deref line."""
        lines = _lines(src)
        return _mutate_remove_null_guard(lines, deref_line_1based - 1)

    # --- Positive cases ---

    def test_bang_ptr_guard_matched(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        r = self._call(src, 3)  # line 3 is ptr->value
        assert r is not None
        assert "if (!ptr) return;" in r.original_fragment
        assert "/* CWE-476: null guard removed */" in r.mutated_fragment
        assert 1 in r.line_replacements  # guard is at line index 1 (0-based)

    def test_ptr_eq_null_guard_matched(self):
        src = textwrap.dedent("""\
            void f(Node *p) {
                if (p == NULL) return;
                p->val = 42;
            }
        """)
        r = self._call(src, 3)
        assert r is not None
        assert "p == NULL" in r.original_fragment

    def test_null_eq_ptr_reversed_guard_matched(self):
        src = textwrap.dedent("""\
            void f(Node *node) {
                if (NULL == node) return;
                node->next = NULL;
            }
        """)
        r = self._call(src, 3)
        assert r is not None
        assert "NULL == node" in r.original_fragment

    def test_nullptr_guard_matched(self):
        src = textwrap.dedent("""\
            void f(Node *p) {
                if (p == nullptr) return;
                p->data = 0;
            }
        """)
        r = self._call(src, 3)
        assert r is not None

    def test_extra_dict_populated(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        r = self._call(src, 3)
        assert r is not None
        assert r.extra["guarded_pointer"] == "ptr"
        assert r.extra["guard_line"] == 2   # 1-based line number of guard
        assert r.extra["deref_line"] == 3   # 1-based line number of deref

    def test_replacement_has_correct_line_index(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        lines = _lines(src)
        r = _mutate_remove_null_guard(lines, 2)  # 0-based index of deref line
        assert r is not None
        # Guard is at index 1 (0-based)
        assert 1 in r.line_replacements
        replacement = r.line_replacements[1]
        assert "/* CWE-476: null guard removed */" in replacement

    def test_indentation_preserved_in_replacement(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        lines = _lines(src)
        r = _mutate_remove_null_guard(lines, 2)
        assert r is not None
        replacement = r.line_replacements[1]
        assert replacement.startswith("    ")   # 4-space indent preserved

    # --- Blank line skipped ---

    def test_blank_line_between_guard_and_deref_is_skipped(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;

                ptr->value = 1;
            }
        """)
        r = self._call(src, 4)  # deref is at line 4 (after blank line 3)
        assert r is not None
        assert "if (!ptr) return;" in r.original_fragment

    # --- Negative cases ---

    def test_no_guard_returns_none(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                int x = 0;
                ptr->value = 1;
            }
        """)
        r = self._call(src, 3)
        assert r is None

    def test_mismatched_pointer_returns_none(self):
        src = textwrap.dedent("""\
            void f(Node *a, Node *b) {
                if (!a) return;
                b->value = 1;
            }
        """)
        r = self._call(src, 3)
        assert r is None

    def test_non_guard_code_blocks_match(self):
        """An intervening code line between guard and deref should block the match."""
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                log("using ptr");
                ptr->value = 1;
            }
        """)
        r = self._call(src, 4)
        assert r is None

    def test_no_dereference_on_target_line_returns_none(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                int x = 5;
            }
        """)
        r = self._call(src, 3)
        assert r is None

    def test_guard_at_first_line_no_crash(self):
        """When target is at line 0 there's no preceding line — should return None."""
        src = "    ptr->value = 1;\n"
        lines = _lines(src)
        r = _mutate_remove_null_guard(lines, 0)
        assert r is None


# ---------------------------------------------------------------------------
# Patcher integration: _apply_mutation with remove_null_guard
# ---------------------------------------------------------------------------

class TestPatcherRemoveNullGuard:
    C_SRC = textwrap.dedent("""\
        #include <stdlib.h>

        typedef struct { int value; } Node;

        void update(Node *ptr, int v) {
            if (!ptr) return;
            ptr->value = v;
        }
    """)

    def _make_src(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir()
        (src / "update.c").write_text(self.C_SRC, encoding="utf-8")
        return src

    def _make_target(self, source_root: Path):
        from insert_me.pipeline.seeder import PatchTarget
        return PatchTarget(
            file=Path("update.c"),
            line=7,              # ptr->value = v;  (1-based)
            mutation_strategy="remove_null_guard",
            score=0.65,
        )

    def test_guard_replaced_in_bad_file(self, tmp_path):
        src = self._make_src(tmp_path)
        bad = tmp_path / "bad"
        good = tmp_path / "good"

        from insert_me.pipeline.seeder import PatchTargetList
        target = self._make_target(src)
        ptl = PatchTargetList(targets=[target], source_root=src)
        patcher = Patcher(ptl, bad, good)
        result = patcher.run()

        assert len(result.mutations) == 1
        m = result.mutations[0]
        assert m.mutation_type == "remove_null_guard"

        bad_text = (bad / "update.c").read_text(encoding="utf-8")
        assert "/* CWE-476: null guard removed */" in bad_text
        assert "if (!ptr) return;" not in bad_text

    def test_good_file_unchanged(self, tmp_path):
        src = self._make_src(tmp_path)
        bad = tmp_path / "bad"
        good = tmp_path / "good"

        from insert_me.pipeline.seeder import PatchTargetList
        target = self._make_target(src)
        ptl = PatchTargetList(targets=[target], source_root=src)
        patcher = Patcher(ptl, bad, good)
        patcher.run()

        good_text = (good / "update.c").read_text(encoding="utf-8")
        assert good_text == self.C_SRC

    def test_mutation_record_fields(self, tmp_path):
        src = self._make_src(tmp_path)
        bad = tmp_path / "bad"
        good = tmp_path / "good"

        from insert_me.pipeline.seeder import PatchTargetList
        target = self._make_target(src)
        ptl = PatchTargetList(targets=[target], source_root=src)
        patcher = Patcher(ptl, bad, good)
        result = patcher.run()

        m = result.mutations[0]
        assert "if (!ptr) return;" in m.original_fragment
        assert "/* CWE-476: null guard removed */" in m.mutated_fragment
        assert m.extra["guarded_pointer"] == "ptr"

    def test_validator_passes(self, tmp_path):
        """Full pipeline check: Validator should report PASS for a CWE-476 mutation."""
        src = self._make_src(tmp_path)
        bad = tmp_path / "bad"
        good = tmp_path / "good"

        from insert_me.pipeline.seeder import PatchTargetList
        from insert_me.pipeline.validator import Validator

        target = self._make_target(src)
        ptl = PatchTargetList(targets=[target], source_root=src)
        patcher = Patcher(ptl, bad, good)
        result = patcher.run()

        validator = Validator(result, src)
        verdict = validator.run()
        assert verdict.overall == "PASS", [c.reason for c in verdict.checks]


# ---------------------------------------------------------------------------
# Seeder: null_guard pattern type
# ---------------------------------------------------------------------------

class TestSeederNullGuard:
    def test_pattern_type_registered(self):
        assert "null_guard" in PATTERN_REGEXES

    def test_matches_bang_ptr(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert pat.search("    if (!ptr) return;")

    def test_matches_ptr_eq_null(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert pat.search("    if (ptr == NULL) return;")

    def test_matches_null_eq_ptr(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert pat.search("    if (NULL == ptr) return;")

    def test_matches_nullptr(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert pat.search("    if (ptr == nullptr) return;")

    def test_does_not_match_arithmetic_condition(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert not pat.search("    if (n > MAX) return;")

    def test_does_not_match_assignment(self):
        pat = PATTERN_REGEXES["null_guard"]
        assert not pat.search("    ptr = malloc(n);")

    def test_seeder_finds_null_guard_targets(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "test.c").write_text(
            textwrap.dedent("""\
                void f(int *p) {
                    if (!p) return;
                    *p = 42;
                }
                void g(int *q) {
                    if (q == NULL) return;
                    *q = 0;
                }
            """),
            encoding="utf-8",
        )
        spec = {
            "seed_id": "test-476",
            "seed": 1,
            "cwe_id": "CWE-476",
            "mutation_strategy": "remove_null_guard",
            "target_pattern": {"pattern_type": "null_guard"},
            "source_constraints": {"file_patterns": ["*.c"], "exclude_patterns": []},
        }
        seeder = Seeder(seed=1, spec=spec, source_root=src)
        result = seeder.run()
        assert len(result.targets) >= 2
        # All targets should be null_guard lines
        (src / "test.c").read_text()
        for t in result.targets:
            assert t.mutation_strategy == "remove_null_guard"

    def test_return_guard_scores_higher_than_no_return(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "test.c").write_text(
            textwrap.dedent("""\
                void f(int *p) {
                    if (!p) return;
                }
                void g(int *q) {
                    if (!q) { int x = 0; }
                }
            """),
            encoding="utf-8",
        )
        spec = {
            "seed_id": "test-score",
            "seed": 1,
            "mutation_strategy": "remove_null_guard",
            "target_pattern": {"pattern_type": "null_guard", "min_candidate_score": 0.0},
            "source_constraints": {"file_patterns": ["*.c"], "exclude_patterns": []},
        }
        seeder = Seeder(seed=1, spec=spec, source_root=src)
        result = seeder.run()
        scores = {t.line: t.score for t in result.targets}
        # Line 2 (return guard) should score >= line 5 (block guard)
        assert scores.get(2, 0) >= scores.get(5, 0)


# ---------------------------------------------------------------------------
# Primary mode: guard line as target (Seeder-provided null_guard lines)
# ---------------------------------------------------------------------------

class TestRemoveNullGuardGuardLineMode:
    """Tests for _mutate_from_guard_line — the primary path where line_idx
    points at the null-guard head, not the dereference."""

    def _call_guard(self, src: str, guard_line_1based: int):
        """Call handler with the guard line as target (Seeder primary mode)."""
        lines = src.splitlines(keepends=True)
        return _mutate_remove_null_guard(lines, guard_line_1based - 1)

    # --- Inline guard (single line: if (!ptr) return;) ---

    def test_inline_guard_returns_result(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        r = self._call_guard(src, 2)  # guard is line 2
        assert r is not None
        assert "/* CWE-476: null guard removed */" in r.mutated_fragment

    def test_inline_guard_extra_fields(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        assert r.extra["guard_line"] == 2
        assert r.extra["guarded_pointer"] == "ptr"
        assert r.extra["multiline"] is False

    def test_inline_guard_only_guard_replaced(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                ptr->value = 1;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        # Guard at 0-based index 1 replaced; deref line untouched
        assert 1 in r.line_replacements
        assert 2 not in r.line_replacements

    def test_inline_guard_null_eq_ptr_form(self):
        src = textwrap.dedent("""\
            void g(Node *p) {
                if (NULL == p) return;
                p->next = NULL;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        assert r.extra["guarded_pointer"] == "p"

    def test_inline_guard_ptr_eq_null_form(self):
        src = textwrap.dedent("""\
            void g(Node *p) {
                if (p == NULL) return;
                p->next = NULL;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None

    # --- Multiline guard: body on next line ---

    def test_multiline_guard_return_null_form(self):
        src = textwrap.dedent("""\
            Node *f(Node *ptr) {
                if (!ptr)
                    return NULL;
                ptr->value = 1;
                return ptr;
            }
        """)
        r = self._call_guard(src, 2)  # guard head at line 2
        assert r is not None
        assert "/* CWE-476: null guard removed */" in r.mutated_fragment

    def test_multiline_guard_body_lines_blanked(self):
        src = textwrap.dedent("""\
            Node *f(Node *ptr) {
                if (!ptr)
                    return NULL;
                ptr->value = 1;
                return ptr;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        # Guard head at 0-based 1, body at 0-based 2 → both in replacements
        assert 1 in r.line_replacements
        assert 2 in r.line_replacements
        assert r.line_replacements[2] == "\n"  # body blanked to empty line

    def test_multiline_guard_extra_multiline_true(self):
        src = textwrap.dedent("""\
            Node *f(Node *ptr) {
                if (!ptr)
                    return NULL;
                ptr->value = 1;
                return ptr;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        assert r.extra["multiline"] is True
        assert 3 in r.extra["body_lines"]  # body is at 1-based line 3

    def test_multiline_guard_break_form(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr)
                    break;
                ptr->value = 0;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is not None
        assert r.extra["multiline"] is True

    # --- No-deref-following → should return None ---

    def test_guard_with_no_deref_following_returns_none(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                int x = 5;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is None

    def test_guard_with_intervening_code_returns_none(self):
        src = textwrap.dedent("""\
            void f(Node *ptr) {
                if (!ptr) return;
                log("msg");
                ptr->value = 1;
            }
        """)
        r = self._call_guard(src, 2)
        assert r is None

    # --- Patcher integration: guard line used as PatchTarget ---

    def test_patcher_with_guard_line_target(self, tmp_path):
        c_src = textwrap.dedent("""\
            #include <stdlib.h>
            typedef struct { int val; } Node;
            Node *process(Node *ptr) {
                if (!ptr)
                    return NULL;
                ptr->val = 42;
                return ptr;
            }
        """)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "node.c").write_text(c_src, encoding="utf-8")
        bad = tmp_path / "bad"
        good = tmp_path / "good"

        from insert_me.pipeline.seeder import PatchTarget, PatchTargetList

        # Guard head is at line 4 (1-based): "    if (!ptr)"
        target = PatchTarget(
            file=Path("node.c"),
            line=4,
            mutation_strategy="remove_null_guard",
            score=0.7,
        )
        ptl = PatchTargetList(targets=[target], source_root=src_dir)
        patcher = Patcher(ptl, bad, good)
        result = patcher.run()

        assert len(result.mutations) == 1
        bad_text = (bad / "node.c").read_text(encoding="utf-8")
        assert "/* CWE-476: null guard removed */" in bad_text
        assert "if (!ptr)" not in bad_text
        # Body line (return NULL;) should be gone
        assert "return NULL;" not in bad_text
