#!/usr/bin/env python3
"""
check_reproducibility.py — Verify deterministic reproducibility of insert_me corpus generation.

Runs each seed file N times (default: 2) into separate temporary directories and
compares the deterministic fields across runs. Any divergence is reported as a failure.

The following fields are compared (timestamps and monotonic IDs are excluded):

    patch_plan.json
        targets[*].file, targets[*].line, targets[*].mutation_strategy,
        targets[*].candidate_score, source_hash

    ground_truth.json
        cwe_id, spec_id, seed, validation_passed,
        mutations[*].file, mutations[*].line, mutations[*].mutation_type,
        mutations[*].original_fragment, mutations[*].mutated_fragment

    audit_result.json
        classification, confidence

    validation_result.json
        verdict, checks[*].name, checks[*].passed

Usage
-----
    python scripts/check_reproducibility.py [OPTIONS]

Options
-------
    --seeds-dir PATH       Directory containing seed JSON files.
                           Default: examples/seeds/sandbox
    --source-root PATH     Root of the sandbox C/C++ source tree.
                           Default: examples/sandbox_eval/src
    --runs INT             Number of times to run each seed (default: 2)
    --output-base PATH     Base directory for run outputs (default: output/repro_check)
    --keep-outputs         Do not delete run directories after comparison (for debugging)
    --verbose              Print field-by-field comparison detail
    --no-color             Disable ANSI colour output

Exit codes
----------
    0   All seeds reproduce identically
    1   One or more seeds show divergence between runs
    2   Invocation or configuration error
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_USE_COLOR = True


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t: str) -> str:  return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str) -> str:    return _c("31", t)
def bold(t: str) -> str:   return _c("1",  t)
def dim(t: str) -> str:    return _c("2",  t)


# ---------------------------------------------------------------------------
# Field extractors
# ---------------------------------------------------------------------------

def _extract_patch_plan(d: dict) -> dict:
    return {
        "source_hash": d.get("source_hash"),
        "targets": [
            {
                "file":               t.get("file"),
                "line":               t.get("line"),
                "mutation_strategy":  t.get("mutation_strategy"),
                "candidate_score":    t.get("candidate_score"),
            }
            for t in d.get("targets", [])
        ],
    }


def _extract_ground_truth(d: dict) -> dict:
    return {
        "cwe_id":           d.get("cwe_id"),
        "spec_id":          d.get("spec_id"),
        "seed":             d.get("seed"),
        "validation_passed": d.get("validation_passed"),
        "mutations": [
            {
                "file":               m.get("file"),
                "line":               m.get("line"),
                "mutation_type":      m.get("mutation_type"),
                "original_fragment":  m.get("original_fragment"),
                "mutated_fragment":   m.get("mutated_fragment"),
            }
            for m in d.get("mutations", [])
        ],
    }


def _extract_audit_result(d: dict) -> dict:
    return {
        "classification": d.get("classification"),
        "confidence":     d.get("confidence"),
    }


def _extract_validation_result(d: dict) -> dict:
    # Supports both "overall"/"verdict" and "status"/"passed" field names.
    # Normalise to lowercase for stable comparison across pipeline versions.
    raw_overall = d.get("overall", d.get("verdict", ""))
    return {
        "overall": str(raw_overall).lower() if raw_overall is not None else None,
        "checks": [
            {
                "name":   c.get("name"),
                "status": str(c.get("status", "pass" if c.get("passed", True) else "fail")).lower(),
            }
            for c in d.get("checks", [])
        ],
    }


_EXTRACTORS = {
    "patch_plan.json":        _extract_patch_plan,
    "ground_truth.json":      _extract_ground_truth,
    "audit_result.json":      _extract_audit_result,
    "validation_result.json": _extract_validation_result,
}


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

def _compare(a: object, b: object, path: str, diffs: list[str]) -> None:
    """Recursively compare two objects; append diff descriptions to diffs."""
    if type(a) != type(b):
        diffs.append(f"  {path}: type mismatch {type(a).__name__} vs {type(b).__name__}")
        return
    if isinstance(a, dict):
        keys = set(a.keys()) | set(b.keys())
        for k in sorted(keys):
            _compare(a.get(k), b.get(k), f"{path}.{k}", diffs)
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append(f"  {path}: list length {len(a)} vs {len(b)}")
            return
        for i, (ai, bi) in enumerate(zip(a, b)):
            _compare(ai, bi, f"{path}[{i}]", diffs)
    else:
        if a != b:
            diffs.append(f"  {path}: {a!r} != {b!r}")


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def _run_seed(seed_file: Path, source_root: Path, output_dir: Path) -> Path | None:
    result = subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(seed_file),
            "--source",    str(source_root),
            "--output",    str(output_dir),
        ],
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if "bundle written to:" in line:
            return Path(line.split("bundle written to:")[-1].strip())
    return None


def _extract_snapshot(bundle_dir: Path) -> dict[str, dict]:
    """Extract deterministic fields from all artifact files in bundle_dir."""
    snapshot: dict[str, dict] = {}
    for artifact_name, extractor in _EXTRACTORS.items():
        path = bundle_dir / artifact_name
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                snapshot[artifact_name] = extractor(data)
            except Exception as exc:
                snapshot[artifact_name] = {"_load_error": str(exc)}
        else:
            snapshot[artifact_name] = {"_missing": True}
    return snapshot


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    global _USE_COLOR

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--seeds-dir", type=Path,
        default=Path("examples/seeds/sandbox"),
        metavar="PATH",
    )
    parser.add_argument(
        "--source-root", type=Path,
        default=Path("examples/sandbox_eval/src"),
        metavar="PATH",
    )
    parser.add_argument(
        "--runs", type=int, default=2,
        metavar="INT",
        help="Number of times to run each seed (default: 2)",
    )
    parser.add_argument(
        "--output-base", type=Path,
        default=Path("output/repro_check"),
        metavar="PATH",
        help="Base directory for run outputs (default: output/repro_check)",
    )
    parser.add_argument(
        "--keep-outputs", action="store_true",
        help="Do not delete run directories after comparison",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print field-by-field comparison detail",
    )
    parser.add_argument(
        "--no-color", action="store_true",
    )
    args = parser.parse_args(argv)

    if args.no_color:
        _USE_COLOR = False

    if not args.seeds_dir.is_dir():
        print(f"ERROR: seeds-dir not found: {args.seeds_dir}", file=sys.stderr)
        return 2
    if not args.source_root.is_dir():
        print(f"ERROR: source-root not found: {args.source_root}", file=sys.stderr)
        return 2
    if args.runs < 2:
        print("ERROR: --runs must be at least 2", file=sys.stderr)
        return 2

    seed_files = sorted(args.seeds_dir.glob("*.json"))
    if not seed_files:
        print(f"ERROR: No .json files in {args.seeds_dir}", file=sys.stderr)
        return 2

    print(bold(f"\ninsert_me reproducibility check"))
    print(f"  seeds-dir   : {args.seeds_dir}")
    print(f"  source-root : {args.source_root}")
    print(f"  runs/seed   : {args.runs}")
    print(f"  seeds found : {len(seed_files)}")
    print()

    pass_count  = 0
    fail_count  = 0
    error_count = 0
    run_dirs: list[Path] = []

    for seed_file in seed_files:
        snapshots: list[dict[str, dict]] = []
        run_bundle_dirs: list[Path | None] = []

        for run_idx in range(args.runs):
            out_dir = args.output_base / f"run_{run_idx}" / seed_file.stem
            out_dir.mkdir(parents=True, exist_ok=True)
            run_dirs.append(out_dir)

            bundle_dir = _run_seed(seed_file, args.source_root, out_dir)
            run_bundle_dirs.append(bundle_dir)
            if bundle_dir:
                snapshots.append(_extract_snapshot(bundle_dir))
            else:
                snapshots.append({"_run_failed": True})

        # Compare all runs against run 0
        diffs: list[str] = []
        ref = snapshots[0]

        for run_idx in range(1, args.runs):
            cmp = snapshots[run_idx]
            for artifact in _EXTRACTORS:
                ref_art = ref.get(artifact, {})
                cmp_art = cmp.get(artifact, {})
                artifact_diffs: list[str] = []
                _compare(ref_art, cmp_art, artifact, artifact_diffs)
                if artifact_diffs:
                    diffs.extend(
                        [f"  run 0 vs run {run_idx} — {artifact}"]
                        + artifact_diffs
                    )

        status_label = (
            green("PASS") if not diffs
            else red("FAIL")
        )
        if "_run_failed" in ref:
            status_label = red("ERROR")
            error_count += 1
        elif diffs:
            fail_count += 1
        else:
            pass_count += 1

        print(f"  {status_label}  {seed_file.stem}")
        if diffs and (args.verbose or fail_count <= 3):
            for d in diffs[:20]:
                print(dim(f"         {d}"))
            if len(diffs) > 20:
                print(dim(f"         ... ({len(diffs) - 20} more diffs)"))

    print()
    print(bold("Reproducibility summary:"))
    print(f"  {green('PASS')}  : {pass_count} / {len(seed_files)}")
    if fail_count:
        print(f"  {red('FAIL')}  : {fail_count} / {len(seed_files)}")
    if error_count:
        print(f"  {red('ERROR')} : {error_count} / {len(seed_files)}")
    print()

    if not args.keep_outputs:
        # Clean up run directories
        base = args.output_base
        if base.exists():
            shutil.rmtree(base, ignore_errors=True)
            print(dim(f"  (run directories removed: {base})"))
    print()

    if fail_count > 0 or error_count > 0:
        print(red("RESULT: REPRODUCIBILITY FAILURE"))
        return 1

    print(green("RESULT: All seeds reproduce identically."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
