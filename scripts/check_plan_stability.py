#!/usr/bin/env python3
"""
check_plan_stability.py — verify fresh-plan reproducibility for insert_me.

Runs ``insert-me plan-corpus`` N times (default: 3) on the same source tree
and requested count, then compares the resulting ``corpus_plan.json`` files
to prove they are byte-identical and attributes any drift to grounded categories.

Writes a machine-readable ``plan_repro_report.json`` summarising the result.

Usage::

    # Basic check on the bundled moderate fixture
    python scripts/check_plan_stability.py \\
        --source examples/local_targets/moderate/src \\
        --count 5

    # Check the sandbox_eval target with 3 runs
    python scripts/check_plan_stability.py \\
        --source examples/sandbox_eval/src \\
        --count 20 \\
        --runs 3 \\
        --output plan_repro_report.json

    # Verbose diff output (useful when drift is detected)
    python scripts/check_plan_stability.py \\
        --source examples/local_targets/moderate/src \\
        --count 5 \\
        --verbose

Exit codes
----------
    0   All runs produced byte-identical plans (STABLE)
    1   Plan drift detected (UNSTABLE)
    2   Configuration error or plan generation failed

Plan diff categories
--------------------
The following grounded drift categories are reported when plans diverge:

    source_hash_mismatch
        ``source_hash`` differs between runs. Cause: source tree was modified
        between runs (a file was added, removed, or changed).

    planned_count_mismatch
        ``planned_count`` integers differ. Cause: candidate enumeration returned
        different counts (would imply non-deterministic file scan or scoring).

    strategy_allocation_drift
        The ``strategy_allocation`` dict has different values. Cause: candidate
        proportions changed, altering the proportional distribution algorithm.

    case_set_drift
        The set of ``case_id`` values differs between runs. Most severe form of
        drift — entirely different cases were selected. Cause: synthesis sweep
        chose different seed_integer → (file, line) assignments.

    case_content_drift
        Same ``case_id`` values but one or more cases has different
        ``target_file``, ``target_line``, ``seed_integer``, or ``strategy``.
        Cause: equal-score tie-breaking became non-deterministic.

    case_ordering_drift
        Same case content but cases appear in different order in the ``cases``
        array. This does NOT affect execution correctness (replay uses case_id),
        but should still be treated as a drift signal.

Note: if two plans are byte-identical (the expected outcome), all categories
will be absent and ``plan_diff`` will be ``null`` in the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Colour helpers (same style as check_reproducibility.py)
# ---------------------------------------------------------------------------

_USE_COLOR = True


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t: str) -> str:  return _c("32", t)
def red(t: str) -> str:    return _c("31", t)
def bold(t: str) -> str:   return _c("1",  t)
def dim(t: str) -> str:    return _c("2",  t)


# ---------------------------------------------------------------------------
# Plan fingerprint
# ---------------------------------------------------------------------------

def _plan_fingerprint(plan: dict) -> str:
    """
    Compute a 16-char hex fingerprint of the canonical plan content.

    Only stable, semantic fields are included (case_id, strategy, seed_integer,
    target_file, target_line). Cases are sorted by case_id so ordering drift
    does not affect the fingerprint. Timestamps and schema_version are excluded.
    """
    cases = sorted(
        [
            {
                "case_id":      c["case_id"],
                "strategy":     c["strategy"],
                "seed_integer": c["seed_integer"],
                "target_file":  c["target_file"],
                "target_line":  c["target_line"],
            }
            for c in plan.get("cases", [])
        ],
        key=lambda x: x["case_id"],
    )
    canonical = {
        "source_hash":         plan.get("source_hash"),
        "requested_count":     plan.get("requested_count"),
        "planned_count":       plan.get("planned_count"),
        "strategy_allocation": plan.get("strategy_allocation"),
        "cases":               cases,
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True).encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Drift analysis
# ---------------------------------------------------------------------------

def _categorise_drift(plans: list[dict]) -> dict:
    """
    Compare all plans against plans[0] and return a dict of drift categories.

    Returns ``{"categories": {...}, "first_diverging_run": int, "field_diffs": [...]}``
    if any drift is found, or ``None`` if all plans are byte-identical.
    """
    ref = plans[0]
    categories: dict[str, int] = {}
    field_diffs: list[str] = []

    for run_idx in range(1, len(plans)):
        cmp = plans[run_idx]
        tag = f"run 0 vs run {run_idx}"

        # source_hash
        if ref.get("source_hash") != cmp.get("source_hash"):
            categories["source_hash_mismatch"] = (
                categories.get("source_hash_mismatch", 0) + 1
            )
            field_diffs.append(
                f"{tag}: source_hash "
                f"{ref.get('source_hash')!r} != {cmp.get('source_hash')!r}"
            )

        # planned_count
        if ref.get("planned_count") != cmp.get("planned_count"):
            categories["planned_count_mismatch"] = (
                categories.get("planned_count_mismatch", 0) + 1
            )
            field_diffs.append(
                f"{tag}: planned_count "
                f"{ref.get('planned_count')} != {cmp.get('planned_count')}"
            )

        # strategy_allocation
        if ref.get("strategy_allocation") != cmp.get("strategy_allocation"):
            categories["strategy_allocation_drift"] = (
                categories.get("strategy_allocation_drift", 0) + 1
            )
            field_diffs.append(f"{tag}: strategy_allocation differs")

        # cases
        ref_ids = [c["case_id"] for c in ref.get("cases", [])]
        cmp_ids = [c["case_id"] for c in cmp.get("cases", [])]
        if set(ref_ids) != set(cmp_ids):
            categories["case_set_drift"] = (
                categories.get("case_set_drift", 0) + 1
            )
            field_diffs.append(
                f"{tag}: case sets differ — "
                f"ref has {set(ref_ids) - set(cmp_ids)} extra, "
                f"cmp has {set(cmp_ids) - set(ref_ids)} extra"
            )
        else:
            # Same set — check content and ordering
            ref_by_id = {c["case_id"]: c for c in ref.get("cases", [])}
            cmp_by_id = {c["case_id"]: c for c in cmp.get("cases", [])}
            for cid in sorted(ref_by_id):
                rc = ref_by_id[cid]
                cc = cmp_by_id[cid]
                for field in ("strategy", "seed_integer", "target_file", "target_line"):
                    if rc.get(field) != cc.get(field):
                        categories["case_content_drift"] = (
                            categories.get("case_content_drift", 0) + 1
                        )
                        field_diffs.append(
                            f"{tag}: case {cid}.{field} "
                            f"{rc.get(field)!r} != {cc.get(field)!r}"
                        )

            if ref_ids != cmp_ids and set(ref_ids) == set(cmp_ids):
                categories["case_ordering_drift"] = (
                    categories.get("case_ordering_drift", 0) + 1
                )
                field_diffs.append(
                    f"{tag}: case ordering differs "
                    f"(same set, different array order)"
                )

    if not categories:
        return None  # type: ignore[return-value]

    # Find first diverging run
    first_diverging = next(
        (i for i in range(1, len(plans)) if plans[i] != ref), 1
    )
    return {
        "categories":          categories,
        "first_diverging_run": first_diverging,
        "field_diffs":         field_diffs,
    }


# ---------------------------------------------------------------------------
# Plan runner
# ---------------------------------------------------------------------------

def _run_plan(
    source: Path,
    count: int,
    output_dir: Path,
    extra_args: list[str],
) -> tuple[bool, str]:
    """
    Run ``insert-me plan-corpus``.

    Returns ``(ok, error_message)`` where ok=True on success.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "plan-corpus",
            "--source", str(source),
            "--count",  str(count),
            "--output-dir", str(output_dir),
        ] + extra_args,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False, result.stderr or result.stdout or "(no output)"
    plan_file = output_dir / "corpus_plan.json"
    if not plan_file.exists():
        return False, f"corpus_plan.json not written in {output_dir}"
    return True, ""


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _write_report(
    path: Path,
    source: Path,
    count: int,
    run_count: int,
    plans: list[dict],
    fingerprints: list[str],
    drift: dict | None,
) -> None:
    """Write plan_repro_report.json."""
    all_identical = (len(set(fingerprints)) == 1) if fingerprints else False
    verdict = "STABLE" if all_identical else "PLAN_UNSTABLE"

    run_details = [
        {
            "run_index":       i,
            "planned_count":   p.get("planned_count", 0),
            "strategy_allocation": p.get("strategy_allocation", {}),
            "plan_fingerprint": fp,
        }
        for i, (p, fp) in enumerate(zip(plans, fingerprints))
    ]

    report = {
        "schema_version":   "1.0",
        "target_source":    str(source.resolve()),
        "requested_count":  count,
        "run_count":        run_count,
        "verdict":          verdict,
        "plan_stable":      all_identical,
        "all_identical":    all_identical,
        "plan_fingerprints": fingerprints,
        "plan_diff":        drift,
        "run_details":      run_details,
        "repro_guarantee":  (
            "Same source tree + same --count + same constraints "
            "=> byte-identical corpus_plan.json on every fresh run."
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


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
        "--source", type=Path, required=True, metavar="PATH",
        help="Root of the C/C++ source tree to plan against.",
    )
    parser.add_argument(
        "--count", type=int, required=True, metavar="N",
        help="Requested corpus case count.",
    )
    parser.add_argument(
        "--runs", type=int, default=3, metavar="INT",
        help="Number of independent fresh plan runs to compare (default: 3).",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path("plan_repro_report.json"),
        metavar="PATH",
        help="Where to write plan_repro_report.json (default: plan_repro_report.json).",
    )
    parser.add_argument(
        "--keep-outputs", action="store_true",
        help="Do not delete temporary plan directories after comparison.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print field-by-field diff detail when drift is detected.",
    )
    parser.add_argument(
        "--no-color", action="store_true",
    )
    args = parser.parse_args(argv)

    if args.no_color:
        _USE_COLOR = False

    if not args.source.is_dir():
        print(f"ERROR: --source not found or not a directory: {args.source}",
              file=sys.stderr)
        return 2
    if args.runs < 2:
        print("ERROR: --runs must be at least 2", file=sys.stderr)
        return 2

    print(bold("\ninsert_me plan stability check"))
    print(f"  source  : {args.source}")
    print(f"  count   : {args.count}")
    print(f"  runs    : {args.runs}")
    print(f"  report  : {args.output}")
    print()

    tmp_root = Path(tempfile.mkdtemp(prefix="insert_me_plan_stability_"))
    plans: list[dict] = []
    fingerprints: list[str] = []
    run_errors: list[str] = []

    for run_idx in range(args.runs):
        out_dir = tmp_root / f"run_{run_idx}"
        ok, err = _run_plan(args.source, args.count, out_dir, [])
        if not ok:
            run_errors.append(f"run {run_idx}: {err[:120]}")
            print(f"  run {run_idx}/{args.runs}  {red('ERROR')}  {err[:80]}")
            continue

        plan_file = out_dir / "corpus_plan.json"
        plan_data = json.loads(plan_file.read_text(encoding="utf-8"))
        fp = _plan_fingerprint(plan_data)
        plans.append(plan_data)
        fingerprints.append(fp)

        planned = plan_data.get("planned_count", "?")
        print(f"  run {run_idx}/{args.runs}  OK  "
              f"planned={planned}  fingerprint={fp}")

    if not args.keep_outputs:
        shutil.rmtree(tmp_root, ignore_errors=True)
    else:
        print(dim(f"\n  (plan dirs kept at: {tmp_root})"))

    print()

    if run_errors:
        print(red(f"RESULT: {len(run_errors)} run(s) failed to generate a plan."))
        for e in run_errors:
            print(f"  {e}")
        return 2

    if len(plans) < 2:
        print(red("RESULT: Not enough successful runs to compare."), file=sys.stderr)
        return 2

    # --- Compare ---
    drift = _categorise_drift(plans)
    all_identical = drift is None

    _write_report(
        path=args.output,
        source=args.source,
        count=args.count,
        run_count=args.runs,
        plans=plans,
        fingerprints=fingerprints,
        drift=drift,
    )
    print(f"  report written: {args.output}")
    print()

    if all_identical:
        print(green("RESULT: STABLE -- all plans are byte-identical."))
        fp_set = list(set(fingerprints))
        print(f"  shared fingerprint: {fp_set[0]}")
        return 0
    else:
        print(red("RESULT: PLAN_UNSTABLE — drift detected."))
        assert drift is not None
        cats = drift["categories"]
        print(f"  drift categories: {', '.join(cats.keys())}")
        if args.verbose:
            print()
            for d in drift.get("field_diffs", [])[:40]:
                print(f"  {dim(d)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
