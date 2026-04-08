"""
Documentation drift guardrails for insert_me.

All stable claims are sourced from ``config/project_status.json``.
Tests in this module fail when public-facing docs (README, ARCHITECTURE,
ROADMAP, docs/ headers, CLI help) disagree with the manifest.

Design principles:
- Every check loads the manifest first; no literal expected values in test bodies.
- Volatile metrics (test count, corpus seed counts) are NOT checked against docs
  because they change too often.  They are tracked in the manifest only.
- Checks cover the stability_policy fields marked "STABLE" in the manifest.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Repo root helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
MANIFEST_PATH = REPO_ROOT / "config" / "project_status.json"

README = REPO_ROOT / "README.md"
ARCHITECTURE = REPO_ROOT / "ARCHITECTURE.md"
ROADMAP = REPO_ROOT / "ROADMAP.md"

DOCS = {
    "repro_runbook":      REPO_ROOT / "docs" / "repro_runbook.md",
    "local_target_pilot": REPO_ROOT / "docs" / "local_target_pilot.md",
    "corpus_quality_gate":REPO_ROOT / "docs" / "corpus_quality_gate.md",
    "strategy_catalog":   REPO_ROOT / "docs" / "strategy_catalog.md",
}

STRATEGY_CATALOG = REPO_ROOT / "config" / "strategy_catalog.json"
EXAMPLES_SEEDS   = REPO_ROOT / "examples" / "seeds"
SCHEMAS_DIR      = REPO_ROOT / "schemas"


def _manifest() -> dict[str, Any]:
    """Load and return the project status manifest."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _cli_help() -> str:
    """Return the text of `insert-me --help`."""
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# 1. Manifest integrity — manifest is self-consistent with strategy_catalog.json
# ---------------------------------------------------------------------------


class TestManifestIntegrity:
    """The manifest must agree with the machine-readable strategy catalog."""

    def test_manifest_exists(self) -> None:
        assert MANIFEST_PATH.exists(), "config/project_status.json not found"

    def test_manifest_is_valid_json(self) -> None:
        _manifest()  # raises if invalid

    def test_admitted_count_matches_catalog(self) -> None:
        m = _manifest()
        catalog = json.loads(STRATEGY_CATALOG.read_text(encoding="utf-8"))
        catalog_admitted = [
            s for s in catalog["strategies"]
            if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
        ]
        assert m["admitted_strategy_count"] == len(catalog_admitted), (
            f"Manifest admitted_strategy_count={m['admitted_strategy_count']} "
            f"but catalog has {len(catalog_admitted)} admitted strategies. "
            "Update config/project_status.json."
        )

    def test_admitted_ids_match_catalog(self) -> None:
        m = _manifest()
        catalog = json.loads(STRATEGY_CATALOG.read_text(encoding="utf-8"))
        catalog_ids = {
            s["strategy_id"]
            for s in catalog["strategies"]
            if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
        }
        manifest_ids = set(m["admitted_strategy_ids"])
        assert manifest_ids == catalog_ids, (
            f"Manifest admitted_strategy_ids={sorted(manifest_ids)} "
            f"but catalog admitted IDs={sorted(catalog_ids)}. "
            "Update config/project_status.json."
        )

    def test_total_count_matches_catalog(self) -> None:
        m = _manifest()
        catalog = json.loads(STRATEGY_CATALOG.read_text(encoding="utf-8"))
        assert m["total_strategy_count"] == len(catalog["strategies"]), (
            f"Manifest total_strategy_count={m['total_strategy_count']} "
            f"but catalog has {len(catalog['strategies'])} entries."
        )


# ---------------------------------------------------------------------------
# 2. Phase marker — README, ARCHITECTURE, ROADMAP, and all docs/ headers
#    must carry the phase from the manifest
# ---------------------------------------------------------------------------


class TestPhaseMarkerSync:
    """Every public doc must carry the current phase from the manifest."""

    _PHASE_PATTERN = re.compile(r"Phase\s+(\d+(?:\.\d+)?)", re.IGNORECASE)

    def _first_phase_in(self, path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        m = self._PHASE_PATTERN.search(text)
        assert m, f"No 'Phase N[.M]' marker found in {path.name}"
        return m.group(1)

    def test_readme_phase_matches_manifest(self) -> None:
        expected = _manifest()["phase"]
        found = self._first_phase_in(README)
        assert found == expected, (
            f"README phase={found!r} but manifest phase={expected!r}. "
            "Update README or config/project_status.json."
        )

    def test_readme_current_status_heading_has_manifest_phase(self) -> None:
        """The '## Current Status' heading must explicitly carry the manifest phase."""
        phase = _manifest()["phase"]
        text = README.read_text(encoding="utf-8")
        heading_re = re.compile(
            r"##\s+Current Status[^\n]*Phase\s+(\d+(?:\.\d+)?)", re.IGNORECASE
        )
        m = heading_re.search(text)
        assert m, (
            "README '## Current Status' heading not found or has no 'Phase N' marker. "
            "The heading must read '## Current Status — Phase N (label)'."
        )
        assert m.group(1) == phase, (
            f"README '## Current Status' heading shows Phase {m.group(1)!r} "
            f"but manifest says Phase {phase!r}. Update the heading."
        )

    def test_readme_quick_reference_maturity_has_manifest_phase(self) -> None:
        """The 'Current maturity' cell in the Internal Quick Reference must carry the manifest phase."""
        phase = _manifest()["phase"]
        text = README.read_text(encoding="utf-8")
        maturity_pos = text.find("Current maturity")
        assert maturity_pos >= 0, (
            "README 'Internal Reuse — Quick Reference' table is missing a 'Current maturity' row."
        )
        # Look for the phase within the cell content (~300 chars after the label)
        context = text[maturity_pos : maturity_pos + 300]
        assert f"Phase {phase}" in context, (
            f"README 'Current maturity' cell does not contain 'Phase {phase}'. "
            "This cell must be kept in sync with config/project_status.json."
        )

    def test_architecture_phase_matches_manifest(self) -> None:
        expected = _manifest()["phase"]
        found = self._first_phase_in(ARCHITECTURE)
        assert found == expected, (
            f"ARCHITECTURE phase={found!r} but manifest phase={expected!r}."
        )

    def test_roadmap_has_entry_for_manifest_phase(self) -> None:
        expected = _manifest()["phase"]
        roadmap_text = ROADMAP.read_text(encoding="utf-8")
        assert f"Phase {expected}" in roadmap_text, (
            f"ROADMAP has no section for Phase {expected!r}. "
            "Add a Phase entry to ROADMAP.md."
        )

    @pytest.mark.parametrize("doc_name,doc_path", list(DOCS.items()))
    def test_doc_header_phase_matches_manifest(
        self, doc_name: str, doc_path: Path
    ) -> None:
        expected = _manifest()["phase"]
        text = doc_path.read_text(encoding="utf-8")
        # Doc headers use either "Phase: X" or "Phase X" patterns
        assert expected in text, (
            f"docs/{doc_path.name} does not contain phase {expected!r}. "
            "Update the Phase header in this doc."
        )


# ---------------------------------------------------------------------------
# 3. Strategy count and IDs — README must reflect manifest admitted count/IDs
# ---------------------------------------------------------------------------


class TestStrategyCatalogSync:
    """README must mention the admitted strategy count and all admitted IDs."""

    def test_admitted_count_in_readme(self) -> None:
        m = _manifest()
        count = m["admitted_strategy_count"]
        readme_text = README.read_text(encoding="utf-8")
        assert str(count) in readme_text, (
            f"README does not mention admitted strategy count {count}. "
            "Update README status table to match manifest."
        )

    def test_admitted_strategy_ids_in_readme(self) -> None:
        m = _manifest()
        readme_text = README.read_text(encoding="utf-8")
        for sid in m["admitted_strategy_ids"]:
            assert sid in readme_text, (
                f"Corpus-admitted strategy '{sid}' not found in README. "
                "README may be stale — update to match manifest."
            )


# ---------------------------------------------------------------------------
# 4. Canonical workflow labels — CLI help must use the labels from manifest
# ---------------------------------------------------------------------------


class TestCanonicalWorkflowLabels:
    """CLI help epilog must contain each canonical workflow label from manifest."""

    def test_workflow_labels_in_cli_help(self) -> None:
        m = _manifest()
        help_text = _cli_help()
        labels = m["canonical_workflow_labels"]
        # We check the key distinguishing phrases rather than exact formatting
        # "Expert/manual" must appear somewhere in help (covers seed_driven label)
        assert "Expert/manual" in help_text or "expert/manual" in help_text, (
            f"CLI help does not contain 'expert/manual' (from workflow labels: {labels}). "
            "Update cli.py epilog."
        )

    def test_recommended_commands_in_cli_help(self) -> None:
        m = _manifest()
        help_text = _cli_help()
        # Both recommended workflow commands must appear in CLI help epilog
        assert "generate-corpus" in help_text, (
            "generate-corpus not in CLI help — single-target recommended path missing"
        )
        assert "generate-portfolio" in help_text, (
            "generate-portfolio not in CLI help — portfolio recommended path missing"
        )


# ---------------------------------------------------------------------------
# 5. CLI subcommand presence — all documented subcommands must be in --help
# ---------------------------------------------------------------------------


class TestCliCommandPresence:
    """All CLI subcommands documented in the manifest/README must appear in --help."""

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

    def test_all_subcommands_in_help(self) -> None:
        help_text = _cli_help()
        missing = [cmd for cmd in self.REQUIRED_SUBCOMMANDS if cmd not in help_text]
        assert not missing, (
            f"Subcommands missing from `insert-me --help`: {missing}. "
            "A command was removed or renamed without updating the test."
        )


# ---------------------------------------------------------------------------
# 6. Not-yet-available items — README must contain each item from manifest
# ---------------------------------------------------------------------------


class TestNotYetAvailableSync:
    """Each 'not yet available' item in the manifest must be reflected in README."""

    # We check for the CWE/feature keyword rather than the full sentence,
    # since wording may differ slightly between manifest and README.
    _KEYWORD_MAP = {
        "CWE-787 Out-of-bounds Write":    "CWE-787",
        "AST-based or compiler-backed":   "AST-based",
        "Phase 7B real LLM adjudicator":  "LLMAdjudicator",
        "Parallel execution":             "Parallel execution",
        "Portfolio reproducibility check":"Portfolio reproducibility",
        "Production codebase support":    "Production codebase",
    }

    def test_not_yet_available_items_in_readme(self) -> None:
        m = _manifest()
        readme_text = README.read_text(encoding="utf-8")
        missing = []
        for item in m["not_yet_available"]:
            # find the first matching keyword for this item
            keyword = next(
                (kw for prefix, kw in self._KEYWORD_MAP.items() if prefix in item),
                None,
            )
            if keyword and keyword not in readme_text:
                missing.append(f"{keyword!r} (from: {item[:60]}...)")
        assert not missing, (
            "README is missing 'not yet available' items from manifest:\n"
            + "\n".join(f"  - {x}" for x in missing)
        )


# ---------------------------------------------------------------------------
# 7. Example artifact existence — required files and dirs must be on disk
# ---------------------------------------------------------------------------


class TestExampleArtifactExistence:
    """Bundled example files referenced in docs must exist on disk."""

    REQUIRED_PATHS = [
        REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json",
        REPO_ROOT / "examples" / "seeds" / "cwe416_use_after_free.json",
        REPO_ROOT / "examples" / "seeds" / "cwe190_integer_overflow.json",
        REPO_ROOT / "examples" / "seeds" / "sandbox" / "cwe416_sb_001.json",
        REPO_ROOT / "examples" / "targets" / "sandbox_targets.json",
        REPO_ROOT / "examples" / "sandbox_eval" / "src",
        REPO_ROOT / "examples" / "demo" / "src",
        REPO_ROOT / "config" / "strategy_catalog.json",
        REPO_ROOT / "config" / "project_status.json",
        REPO_ROOT / "config" / "workload_classes.json",
        REPO_ROOT / "docs" / "support_envelope.md",
        REPO_ROOT / "schemas" / "seed.schema.json",
        REPO_ROOT / "schemas" / "targets.schema.json",
        REPO_ROOT / "schemas" / "portfolio_plan.schema.json",
        REPO_ROOT / "schemas" / "corpus_plan.schema.json",
        REPO_ROOT / "scripts" / "check_public_status.py",
        REPO_ROOT / "scripts" / "check_portfolio_stability.py",
        REPO_ROOT / "scripts" / "characterize_workloads.py",
        REPO_ROOT / "scripts" / "profile_pipeline_stage.py",
    ]

    @pytest.mark.parametrize(
        "path", REQUIRED_PATHS, ids=lambda p: str(p.relative_to(REPO_ROOT))
    )
    def test_required_path_exists(self, path: Path) -> None:
        assert path.exists(), (
            f"Required file/dir not found: {path.relative_to(REPO_ROOT)}. "
            "Was it deleted or renamed? Update docs and this test."
        )

    def test_sandbox_targets_paths_resolve(self) -> None:
        """All target paths in sandbox_targets.json must resolve to real dirs."""
        targets_file = REPO_ROOT / "examples" / "targets" / "sandbox_targets.json"
        data = json.loads(targets_file.read_text(encoding="utf-8"))
        for entry in data["targets"]:
            resolved = (targets_file.parent / entry["path"]).resolve()
            assert resolved.exists(), (
                f"Target path in sandbox_targets.json does not exist: "
                f"{entry['path']!r} (resolved: {resolved})"
            )


# ---------------------------------------------------------------------------
# 8. Phase 16 artifact integrity — workload characterization files are wired in
# ---------------------------------------------------------------------------


class TestPhase16ArtifactIntegrity:
    """Phase 16 characterization artifacts must be present and cross-referenced."""

    def test_workload_classes_manifest_valid_json(self) -> None:
        path = REPO_ROOT / "config" / "workload_classes.json"
        assert path.exists(), "config/workload_classes.json not found"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "classes" in data, "workload_classes.json missing 'classes' key"
        assert "known_targets" in data, "workload_classes.json missing 'known_targets' key"

    def test_project_status_references_workload_classes(self) -> None:
        m = json.loads(
            (REPO_ROOT / "config" / "project_status.json").read_text(encoding="utf-8")
        )
        assert "workload_classes_manifest" in m, (
            "project_status.json missing 'workload_classes_manifest' field -- "
            "add a pointer to config/workload_classes.json"
        )

    def test_project_status_references_support_envelope(self) -> None:
        m = json.loads(
            (REPO_ROOT / "config" / "project_status.json").read_text(encoding="utf-8")
        )
        assert "support_envelope_doc" in m, (
            "project_status.json missing 'support_envelope_doc' field -- "
            "add a pointer to docs/support_envelope.md"
        )

    def test_support_envelope_referenced_in_local_target_pilot(self) -> None:
        text = (REPO_ROOT / "docs" / "local_target_pilot.md").read_text(encoding="utf-8")
        assert "support_envelope" in text, (
            "docs/local_target_pilot.md does not reference support_envelope.md. "
            "Add a cross-reference so users can find detailed target profiles."
        )

    def test_support_envelope_referenced_in_readme(self) -> None:
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "support_envelope" in text, (
            "README.md does not reference docs/support_envelope.md. "
            "Add a cross-reference in the target sizing section."
        )
