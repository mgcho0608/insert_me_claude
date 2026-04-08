#!/usr/bin/env python3
"""
check_public_status.py — manifest-driven public truth validation script.

Loads ``config/project_status.json`` and validates that every public-facing
document (README, ARCHITECTURE, ROADMAP, docs/ headers, CLI help) agrees with
the stable claims in the manifest.

Exit code:
  0  — all checks pass
  1  — one or more checks fail

Usage::

    python scripts/check_public_status.py            # validate
    python scripts/check_public_status.py --summary  # also print a status block

The same checks run as part of ``pytest tests/test_doc_drift.py``.
This script is intended for quick interactive use or CI without pytest.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent
MANIFEST_PATH = REPO_ROOT / "config" / "project_status.json"

README       = REPO_ROOT / "README.md"
ARCHITECTURE = REPO_ROOT / "ARCHITECTURE.md"
ROADMAP      = REPO_ROOT / "ROADMAP.md"
DOCS = {
    "repro_runbook":       REPO_ROOT / "docs" / "repro_runbook.md",
    "local_target_pilot":  REPO_ROOT / "docs" / "local_target_pilot.md",
    "corpus_quality_gate": REPO_ROOT / "docs" / "corpus_quality_gate.md",
    "strategy_catalog":    REPO_ROOT / "docs" / "strategy_catalog.md",
}
STRATEGY_CATALOG = REPO_ROOT / "config" / "strategy_catalog.json"

# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""

@dataclass
class Report:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append(CheckResult(name, passed, detail))

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    def print(self) -> None:
        width = max(len(r.name) for r in self.results) + 2
        for r in self.results:
            icon = "PASS" if r.passed else "FAIL"
            detail = f"  => {r.detail}" if not r.passed and r.detail else ""
            print(f"  [{icon}]  {r.name:{width}}{detail}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

def _load_catalog() -> dict[str, Any]:
    return json.loads(STRATEGY_CATALOG.read_text(encoding="utf-8"))

def _cli_help() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return result.stdout + result.stderr

_PHASE_RE = re.compile(r"Phase\s+(\d+(?:\.\d+)?)", re.IGNORECASE)

def _first_phase(text: str) -> str | None:
    m = _PHASE_RE.search(text)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_manifest_vs_catalog(m: dict, catalog: dict, report: Report) -> None:
    catalog_admitted = [
        s for s in catalog["strategies"]
        if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
    ]
    catalog_ids = {s["strategy_id"] for s in catalog_admitted}
    manifest_ids = set(m["admitted_strategy_ids"])

    report.add(
        "manifest.admitted_count == catalog",
        m["admitted_strategy_count"] == len(catalog_admitted),
        f"manifest={m['admitted_strategy_count']} catalog={len(catalog_admitted)}",
    )
    report.add(
        "manifest.admitted_ids == catalog",
        manifest_ids == catalog_ids,
        f"extra in manifest={sorted(manifest_ids - catalog_ids)} "
        f"missing from manifest={sorted(catalog_ids - manifest_ids)}",
    )
    report.add(
        "manifest.total_count == catalog",
        m["total_strategy_count"] == len(catalog["strategies"]),
        f"manifest={m['total_strategy_count']} catalog={len(catalog['strategies'])}",
    )


def check_phase_markers(m: dict, report: Report) -> None:
    phase = m["phase"]

    for label, path in [("README", README), ("ARCHITECTURE", ARCHITECTURE)]:
        text = path.read_text(encoding="utf-8")
        found = _first_phase(text)
        report.add(
            f"{label} phase == manifest",
            found == phase,
            f"found={found!r} expected={phase!r}",
        )

    roadmap_text = ROADMAP.read_text(encoding="utf-8")
    report.add(
        "ROADMAP has Phase entry",
        f"Phase {phase}" in roadmap_text,
        f"Phase {phase!r} not found in ROADMAP",
    )

    for doc_name, doc_path in DOCS.items():
        text = doc_path.read_text(encoding="utf-8")
        report.add(
            f"docs/{doc_path.name} phase == manifest",
            phase in text,
            f"phase {phase!r} not found in {doc_path.name}",
        )


def check_strategy_sync(m: dict, report: Report) -> None:
    readme = README.read_text(encoding="utf-8")
    count = m["admitted_strategy_count"]

    report.add(
        "README mentions admitted count",
        str(count) in readme,
        f"count {count} not found in README",
    )
    for sid in m["admitted_strategy_ids"]:
        report.add(
            f"README mentions {sid}",
            sid in readme,
            f"'{sid}' not found in README",
        )


def check_workflow_labels(m: dict, help_text: str, report: Report) -> None:
    report.add(
        "CLI help contains 'expert/manual'",
        "Expert/manual" in help_text or "expert/manual" in help_text,
        "expert/manual workflow label missing from --help",
    )
    report.add(
        "CLI help contains generate-corpus",
        "generate-corpus" in help_text,
        "generate-corpus not in --help",
    )
    report.add(
        "CLI help contains generate-portfolio",
        "generate-portfolio" in help_text,
        "generate-portfolio not in --help",
    )


def check_not_yet_available(m: dict, report: Report) -> None:
    readme = README.read_text(encoding="utf-8")
    keyword_map = {
        "CWE-787 Out-of-bounds Write":    "CWE-787",
        "AST-based or compiler-backed":   "AST-based",
        "Phase 7B real LLM adjudicator":  "LLMAdjudicator",
        "Parallel execution":             "Parallel execution",
        "Portfolio reproducibility check":"Portfolio reproducibility",
        "Production codebase support":    "Production codebase",
    }
    for item in m["not_yet_available"]:
        keyword = next(
            (kw for prefix, kw in keyword_map.items() if prefix in item), None
        )
        if keyword:
            report.add(
                f"README: not-yet-available '{keyword}'",
                keyword in readme,
                f"'{keyword}' not found in README 'not yet available' section",
            )


def check_required_files(report: Report) -> None:
    required = [
        REPO_ROOT / "config" / "project_status.json",
        REPO_ROOT / "config" / "strategy_catalog.json",
        REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json",
        REPO_ROOT / "examples" / "targets" / "sandbox_targets.json",
        REPO_ROOT / "scripts" / "check_public_status.py",
        REPO_ROOT / "schemas" / "seed.schema.json",
        REPO_ROOT / "schemas" / "portfolio_plan.schema.json",
    ]
    for p in required:
        report.add(
            f"file exists: {p.relative_to(REPO_ROOT)}",
            p.exists(),
            f"missing: {p}",
        )


# ---------------------------------------------------------------------------
# Summary block
# ---------------------------------------------------------------------------

def print_summary(m: dict, catalog: dict) -> None:
    catalog_admitted = [
        s for s in catalog["strategies"]
        if s["maturity"] == "IMPLEMENTED_AND_CORPUS_ADMITTED"
    ]
    print()
    print("=" * 60)
    print("  insert_me -- public product status")
    print("=" * 60)
    print(f"  Phase           : {m['phase']} -- {m['phase_label']}")
    print(f"  Maturity        : {m['maturity_label']}")
    print(f"  Strategies      : {m['admitted_strategy_count']} admitted / "
          f"{m['planned_strategy_count']} planned / "
          f"{m['candidate_strategy_count']} candidate / "
          f"{m['total_strategy_count']} total")
    print(f"  Admitted IDs    : {', '.join(m['admitted_strategy_ids'])}")
    print()
    print("  Canonical workflows:")
    for key, label in m["canonical_workflow_labels"].items():
        print(f"    {key:15}  {label}")
    print()
    print("  Not yet available:")
    for item in m["not_yet_available"]:
        print(f"    - {item[:70]}")
    print()
    print("  Stability policy:")
    for metric, policy in m["stability_policy"].items():
        print(f"    {metric:30}  {policy}")
    print()
    if "test_counts" in m:
        tc = m["test_counts"]
        print(f"  Tests (manifest) : {tc['total_passing']} passing, "
              f"{tc['total_skipped']} skipped  [{tc['note']}]")
    if "corpus_counts" in m:
        cc = m["corpus_counts"]
        print(f"  Corpus seeds     : {cc['total_accepted_seeds']} accepted  [{cc['note']}]")
    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate public docs against config/project_status.json manifest."
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Also print a formatted status block from the manifest."
    )
    args = parser.parse_args()

    m = _load_manifest()
    catalog = _load_catalog()
    help_text = _cli_help()
    report = Report()

    check_manifest_vs_catalog(m, catalog, report)
    check_phase_markers(m, report)
    check_strategy_sync(m, report)
    check_workflow_labels(m, help_text, report)
    check_not_yet_available(m, report)
    check_required_files(report)

    passes = sum(1 for r in report.results if r.passed)
    total  = len(report.results)

    print(f"\ninsert_me public status check  (manifest phase: {m['phase']})")
    print("-" * 60)
    report.print()
    print("-" * 60)
    print(f"\n  {passes}/{total} checks passed")

    if args.summary:
        print_summary(m, catalog)

    return 0 if report.all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
