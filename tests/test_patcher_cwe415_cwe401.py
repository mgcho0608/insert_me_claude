"""
Patcher tests for CWE-415 (insert_double_free) and CWE-401 (remove_free_call).

Coverage
--------
- _mutate_insert_double_free: recognised free() patterns, extra dict
- _mutate_remove_free_call: recognised free() patterns, extra dict
- Lines without free() -> None
- Patcher.run() end-to-end for each new strategy
- seeder.py free_call quality penalties (conditional guard, loop body)
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from insert_me.pipeline.patcher import (
    _STRATEGY_HANDLERS,
    _mutate_insert_double_free,
    _mutate_remove_free_call,
    Patcher,
)
from insert_me.pipeline.seeder import PatchTarget, PatchTargetList, Seeder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(
    file: str,
    line: int,
    strategy: str,
) -> PatchTarget:
    return PatchTarget(
        file=Path(file),
        line=line,
        mutation_strategy=strategy,
        context={"expression": "", "function_name": ""},
        score=0.55,
    )


def _make_ptlist(source_root: Path, target: PatchTarget) -> PatchTargetList:
    return PatchTargetList(
        targets=[target],
        seed=42,
        spec_id="test",
        source_root=source_root,
        skipped_count=0,
        source_hash="test-hash",
    )


def _make_seeder(tmp_path: Path, source_root: Path, pattern_type: str, strategy: str) -> Seeder:
    spec = {
        "schema_version": "1.0",
        "seed_id": "test-seed",
        "seed": 42,
        "cwe_id": "CWE-415",
        "mutation_strategy": strategy,
        "target_pattern": {
            "pattern_type": pattern_type,
            "min_candidate_score": 0.0,
        },
        "source_constraints": {
            "file_patterns": ["*.c"],
            "exclude_patterns": [],  # override default *test* exclusion
        },
    }
    seed_file = tmp_path / "seed.json"
    seed_file.write_text(json.dumps(spec), encoding="utf-8")
    return Seeder(seed=42, spec=spec, source_root=source_root)


# ---------------------------------------------------------------------------
# Unit tests: _mutate_insert_double_free
# ---------------------------------------------------------------------------

class TestInsertDoubleFree:
    def test_simple_free(self):
        line = "    free(ptr);\n"
        result = _mutate_insert_double_free(line)
        assert result is not None
        mutated_line, orig_frag, mut_frag, extra = result
        # prepended free should carry same indent
        assert mutated_line == "    free(ptr);\n    free(ptr);\n"
        assert mut_frag == "free(ptr);"
        assert extra["freed_pointer"] == "ptr"

    def test_preserves_indentation(self):
        line = "\t\tfree(node);\n"
        result = _mutate_insert_double_free(line)
        assert result is not None
        mutated_line, _, _, extra = result
        assert mutated_line.startswith("\t\tfree(node);\n")
        assert extra["freed_pointer"] == "node"

    def test_no_free_returns_none(self):
        assert _mutate_insert_double_free("    da->items[i] = NULL;\n") is None

    def test_free_with_spaces_in_args(self):
        line = "    free( buf );\n"
        result = _mutate_insert_double_free(line)
        assert result is not None
        _, _, _, extra = result
        assert extra["freed_pointer"] == "buf"

    def test_no_trailing_newline(self):
        line = "    free(x);"
        result = _mutate_insert_double_free(line)
        assert result is not None

    def test_original_fragment_no_newline(self):
        line = "    free(ptr);\n"
        _, orig_frag, _, _ = _mutate_insert_double_free(line)
        assert "\n" not in orig_frag
        assert orig_frag == "    free(ptr);"

    def test_registered(self):
        assert "insert_double_free" in _STRATEGY_HANDLERS

    def test_double_count_in_output(self):
        line = "    free(obj);\n"
        mutated_line, _, _, _ = _mutate_insert_double_free(line)
        assert mutated_line.count("free(obj);") == 2


# ---------------------------------------------------------------------------
# Unit tests: _mutate_remove_free_call
# ---------------------------------------------------------------------------

class TestRemoveFreeCall:
    def test_simple_free(self):
        line = "    free(ptr);\n"
        result = _mutate_remove_free_call(line)
        assert result is not None
        mutated_line, orig_frag, mut_frag, extra = result
        assert "CWE-401" in mutated_line
        assert "free(ptr) removed" in mutated_line
        assert extra["leaked_pointer"] == "ptr"

    def test_preserves_indentation(self):
        line = "\t\tfree(node);\n"
        result = _mutate_remove_free_call(line)
        assert result is not None
        mutated_line, _, _, extra = result
        assert mutated_line.startswith("\t\t/*")
        assert extra["leaked_pointer"] == "node"

    def test_no_free_returns_none(self):
        assert _mutate_remove_free_call("    ptr->size = 0;\n") is None

    def test_mutated_fragment_is_comment(self):
        line = "    free(data);\n"
        _, _, mut_frag, _ = _mutate_remove_free_call(line)
        assert mut_frag.startswith("/*")
        assert mut_frag.endswith("*/")
        assert "data" in mut_frag

    def test_original_fragment_no_newline(self):
        line = "    free(ptr);\n"
        _, orig_frag, _, _ = _mutate_remove_free_call(line)
        assert "\n" not in orig_frag

    def test_free_absent_from_bad(self):
        line = "    free(buf);\n"
        mutated_line, _, _, _ = _mutate_remove_free_call(line)
        # mutated line must not contain an active free() call
        assert "free(buf);" not in mutated_line

    def test_registered(self):
        assert "remove_free_call" in _STRATEGY_HANDLERS


# ---------------------------------------------------------------------------
# End-to-end: Patcher.run() with insert_double_free
# ---------------------------------------------------------------------------

class TestPatcherInsertDoubleFree:
    def test_double_free_applied(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        c_file = src / "test.c"
        c_file.write_text(
            "void cleanup(MyObj *obj) {\n"
            "    free(obj->buf);\n"
            "    free(obj);\n"
            "}\n",
            encoding="utf-8",
        )
        target = _make_target("test.c", 3, "insert_double_free")
        ptlist = _make_ptlist(src, target)

        bad_root = tmp_path / "bad"
        good_root = tmp_path / "good"
        result = Patcher(ptlist, bad_root, good_root).run()

        assert len(result.mutations) == 1
        assert result.mutations[0].mutation_type == "insert_double_free"
        assert result.mutations[0].extra["freed_pointer"] == "obj"

        bad_content = (bad_root / "test.c").read_text(encoding="utf-8")
        good_content = (good_root / "test.c").read_text(encoding="utf-8")

        # bad should have two free(obj) calls
        assert bad_content.count("free(obj)") == 2
        # good is byte-identical to original
        assert good_content == c_file.read_text(encoding="utf-8")

    def test_non_free_line_skipped(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        c_file = src / "test.c"
        c_file.write_text("    ptr->size = 0;\n", encoding="utf-8")
        target = _make_target("test.c", 1, "insert_double_free")
        ptlist = _make_ptlist(src, target)
        result = Patcher(ptlist, tmp_path / "bad", tmp_path / "good").run()
        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 1


# ---------------------------------------------------------------------------
# End-to-end: Patcher.run() with remove_free_call
# ---------------------------------------------------------------------------

class TestPatcherRemoveFreeCall:
    def test_remove_free_applied(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        c_file = src / "test.c"
        # Target line 3: free(b) — plain identifier, matched by _FREE_CALL_RE
        c_file.write_text(
            "void destroy(Buffer *b) {\n"
            "    free(b->data);\n"
            "    free(b);\n"
            "}\n",
            encoding="utf-8",
        )
        target = _make_target("test.c", 3, "remove_free_call")
        ptlist = _make_ptlist(src, target)

        bad_root = tmp_path / "bad"
        good_root = tmp_path / "good"
        result = Patcher(ptlist, bad_root, good_root).run()

        assert len(result.mutations) == 1
        assert result.mutations[0].mutation_type == "remove_free_call"
        assert result.mutations[0].extra["leaked_pointer"] == "b"

        bad_content = (bad_root / "test.c").read_text(encoding="utf-8")
        good_content = (good_root / "test.c").read_text(encoding="utf-8")

        assert "CWE-401" in bad_content
        # The free(b) line should now be a comment, not an active call
        lines = bad_content.splitlines()
        assert "free(b);" not in lines[2]  # line index 2 = original line 3
        # good is byte-identical to original
        assert good_content == c_file.read_text(encoding="utf-8")

    def test_non_free_line_skipped(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "test.c").write_text("    ptr->size = 0;\n", encoding="utf-8")
        target = _make_target("test.c", 1, "remove_free_call")
        ptlist = _make_ptlist(src, target)
        result = Patcher(ptlist, tmp_path / "bad", tmp_path / "good").run()
        assert len(result.mutations) == 0
        assert len(result.skipped_targets) == 1


# ---------------------------------------------------------------------------
# Seeder free_call quality penalties
# ---------------------------------------------------------------------------

class TestSeederFreeCallPenalties:
    """Verify that the seeder penalises free_call targets in loop bodies."""

    def test_loop_body_free_penalised(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        src_content = textwrap.dedent("""\
            void process(List *lst) {
                Node *cur = lst->head;
                while (cur) {
                    free(cur);
                    cur = cur->next;
                }
                free(lst);
            }
        """)
        (src / "test.c").write_text(src_content, encoding="utf-8")
        seeder = _make_seeder(tmp_path, src, "free_call", "insert_double_free")
        ptlist = seeder.run()
        scores = {t.line: t.score for t in ptlist.targets}

        # line 4 = free(cur) inside while loop, line 7 = free(lst) outside
        loop_score = scores.get(4, 1.0)
        outer_score = scores.get(7, 0.0)
        assert outer_score > loop_score, (
            f"Expected loop-body free (score={loop_score}) < outer free (score={outer_score})"
        )

    def test_plain_free_not_penalised(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        src_content = textwrap.dedent("""\
            void cleanup(Obj *obj) {
                free(obj->buf);
                free(obj);
            }
        """)
        (src / "test.c").write_text(src_content, encoding="utf-8")
        seeder = _make_seeder(tmp_path, src, "free_call", "insert_double_free")
        ptlist = seeder.run()
        # Both plain free() calls should score at baseline 0.55 (no penalties)
        for t in ptlist.targets:
            assert t.score >= 0.50, f"Plain free() at line {t.line} scored too low: {t.score}"
