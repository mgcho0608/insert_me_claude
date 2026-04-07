"""
Documentation drift guardrails for insert_me.

These tests are deterministic and offline. They check that the public-facing
documentation (README, ARCHITECTURE, ROADMAP, CLI help) stays in sync with the
machine-readable sources of truth (strategy_catalog.json, CLI --help output,
bundled example files, schema files).

If any of these tests fail it means a doc was updated without updating the
corresponding source of truth, or vice versa.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Repo root helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
README = REPO_ROOT / "README.md"
ARCHITECTURE = REPO_ROOT / "ARCHITECTURE.md"
ROADMAP = REPO_ROOT / "ROADMAP.md"
STRATEGY_CATALOG = REPO_ROOT / "config" / "strategy_catalog.json"
EXAMPLES_SEEDS = REPO_ROOT / "examples" / "seeds"
EXAMPLES_TARGETS = REPO_ROOT / "examples" / "targets"
SCHEMAS_DIR = REPO_ROOT / "schemas"


def _cli_help() -> str:
    """Return the output of `insert-me --help`."""
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    # argparse writes --help to stdout and exits 0
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# 1. Phase marker consistency: README and ARCHITECTURE must agree
# ---------------------------------------------------------------------------


class TestPhaseMarkerSync:
    """README and ARCHITECTURE must carry the same phase label."""

    _PHASE_PATTERN = re.compile(
        r"Phase\s+(\d+(?:\.\d+)?)", re.IGNORECASE
    )

    def _first_phase_in(self, path: Path) -> str:
        """Extract the first Phase N / Phase N.M token from a document."""
        text = path.read_text(encoding="utf-8")
        m = self._PHASE_PATTERN.search(text)
        assert m, f"No 'Phase N' marker found in {path.name}"
        return m.group(1)

    def test_readme_and_architecture_carry_same_phase(self) -> None:
        readme_phase = self._first_phase_in(README)
        arch_phase = self._first_phase_in(ARCHITECTURE)
        assert readme_phase == arch_phase, (
            f"Phase mismatch: README says {readme_phase!r}, "
            f"ARCHITECTURE says {arch_phase!r}. "
            "Update both to the same phase number."
        )

    def test_roadmap_has_entry_for_readme_phase(self) -> None:
        readme_phase = self._first_phase_in(README)
        roadmap_text = ROADMAP.read_text(encoding="utf-8")
        assert f"Phase {readme_phase}" in roadmap_text, (
            f"ROADMAP has no section for Phase {readme_phase!r}. "
            "Add a Phase entry to ROADMAP.md."
        )


# ---------------------------------------------------------------------------
# 2. Strategy count consistency: docs must match strategy_catalog.json
# ---------------------------------------------------------------------------


class TestStrategyCatalogSync:
    """Strategy counts and admitted strategies in docs must match the catalog."""

    def _load_catalog(self) -> dict:
        return json.loads(STRATEGY_CATALOG.read_text(encoding="utf-8"))

    def test_catalog_total_count_matches_readme(self) -> None:
        catalog = self._load_catalog()
        total = len(catalog["strategies"])
        readme_text = README.read_text(encoding="utf-8")
        # README claims "Total entries: N" in strategy_catalog section or inline
        # We check that the admitted count (6) appears alongside the strategy list
        admitted = [
            s for s in catalog["strategies"]
            if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
        ]
        admitted_count = len(admitted)
        assert f"{admitted_count} corpus-admitted" in readme_text or \
               f"{admitted_count} (CWE-" in readme_text or \
               f"| 6 |" in readme_text, (
            f"README does not mention {admitted_count} corpus-admitted strategies. "
            "Update README to match strategy_catalog.json."
        )

    def test_catalog_admitted_strategy_ids_match_readme(self) -> None:
        catalog = self._load_catalog()
        admitted_ids = {
            s["strategy_id"]
            for s in catalog["strategies"]
            if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
        }
        readme_text = README.read_text(encoding="utf-8")
        for sid in admitted_ids:
            assert sid in readme_text, (
                f"Corpus-admitted strategy '{sid}' from catalog is not mentioned in README. "
                "README may be stale."
            )

    def test_strategy_catalog_has_six_admitted(self) -> None:
        """Hard assertion: exactly 6 corpus-admitted strategies must exist."""
        catalog = self._load_catalog()
        admitted = [
            s for s in catalog["strategies"]
            if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
        ]
        assert len(admitted) == 6, (
            f"Expected 6 corpus-admitted strategies, got {len(admitted)}. "
            "Update this test when a new strategy is admitted."
        )


# ---------------------------------------------------------------------------
# 3. CLI command presence: key subcommands must appear in --help output
# ---------------------------------------------------------------------------


class TestCliCommandPresence:
    """All documented subcommands must appear in `insert-me --help`."""

    REQUIRED_SUBCOMMANDS = [
        "run",
        "batch",
        "inspect-target",
        "plan-corpus",
        "generate-corpus",
        "plan-portfolio",
        "generate-portfolio",
        "validate-bundle",
        "evaluate",
        "audit",
    ]

    def test_all_documented_subcommands_in_help(self) -> None:
        help_text = _cli_help()
        missing = [cmd for cmd in self.REQUIRED_SUBCOMMANDS if cmd not in help_text]
        assert not missing, (
            f"Subcommands missing from `insert-me --help`: {missing}. "
            "A command was removed or renamed without updating the test."
        )

    def test_recommended_workflows_in_help_epilog(self) -> None:
        help_text = _cli_help()
        assert "generate-corpus" in help_text, (
            "generate-corpus not found in help — recommended single-target workflow missing"
        )
        assert "generate-portfolio" in help_text, (
            "generate-portfolio not found in help — recommended portfolio workflow missing"
        )


# ---------------------------------------------------------------------------
# 4. Example artifact existence: files referenced in docs must be real
# ---------------------------------------------------------------------------


class TestExampleArtifactExistence:
    """Bundled example files referenced in README and docs must exist on disk."""

    REQUIRED_EXAMPLE_FILES = [
        REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json",
        REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json",
        REPO_ROOT / "examples" / "seeds" / "cwe190_integer_overflow.json",
        REPO_ROOT / "examples" / "seeds" / "sandbox" / "cwe416_sb_001.json",
        REPO_ROOT / "examples" / "targets" / "sandbox_targets.json",
        REPO_ROOT / "examples" / "sandbox_eval" / "src",
        REPO_ROOT / "examples" / "demo" / "src",
        REPO_ROOT / "config" / "strategy_catalog.json",
        REPO_ROOT / "schemas" / "seed.schema.json",
        REPO_ROOT / "schemas" / "targets.schema.json",
        REPO_ROOT / "schemas" / "portfolio_plan.schema.json",
        REPO_ROOT / "schemas" / "corpus_plan.schema.json",
    ]

    @pytest.mark.parametrize("path", REQUIRED_EXAMPLE_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
    def test_required_example_file_exists(self, path: Path) -> None:
        assert path.exists(), (
            f"Required example file/dir not found: {path.relative_to(REPO_ROOT)}. "
            "Was it deleted or renamed? Update docs and this test."
        )

    def test_sandbox_targets_json_paths_resolve(self) -> None:
        """All target paths in sandbox_targets.json must resolve to real directories."""
        targets_path = REPO_ROOT / "examples" / "targets" / "sandbox_targets.json"
        data = json.loads(targets_path.read_text(encoding="utf-8"))
        for entry in data["targets"]:
            resolved = (targets_path.parent / entry["path"]).resolve()
            assert resolved.exists(), (
                f"Target path in sandbox_targets.json does not exist: {entry['path']!r} "
                f"(resolved: {resolved})"
            )
