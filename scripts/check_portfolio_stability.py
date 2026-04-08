#!/usr/bin/env python3
"""
check_portfolio_stability.py -- verify portfolio reproducibility for insert_me.

Runs three independent checks:

1. Fresh-plan stability
   Same targets-file + same --count => same portfolio_plan.json (byte-identical).
   Runs ``insert-me generate-portfolio --dry-run`` N times and compares plans.

2. Replay stability
   Generate once (fresh plan + execution), then replay with ``--from-plan``.
   Compares portfolio_acceptance_summary.json accepted/rejected counts.

3. Sequential vs parallel parity
   Run ``generate-portfolio --jobs 1`` and ``generate-portfolio --jobs N``.
   Compares accepted_count, rejected_count, and acceptance_fingerprint.

Writes ``portfolio_repro_report.json`` with per-check results.

Usage::

    # Basic check on the bundled sandbox targets
    python scripts/check_portfolio_stability.py \\
        --targets-file examples/targets/sandbox_targets.json \\
        --count 5

    # Skip parity check (useful in single-core CI)
    python scripts/check_portfolio_stability.py \\
        --targets-file examples/targets/sandbox_targets.json \\
        --count 5 --skip-parity

    # Verbose output
    python scripts/check_portfolio_stability.py \\
        --targets-file examples/targets/sandbox_targets.json \\
        --count 5 --verbose

Exit codes
----------
    0   All checks passed (STABLE)
    1   One or more checks failed
    2   Configuration error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

_USE_COLOR = True


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t: str) -> str:  return _c("32", t)
def red(t: str) -> str:    return _c("31", t)
def bold(t: str) -> str:   return _c("1",  t)
def dim(t: str) -> str:    return _c("2",  t)
def yellow(t: str) -> str: return _c("33", t)


# ---------------------------------------------------------------------------
# Portfolio plan fingerprint
# ---------------------------------------------------------------------------

def _portfolio_fingerprint(plan: dict) -> str:
    """Stable 16-char hex fingerprint of portfolio_plan.json content."""
    entries = sorted(
        [
            {
                "case_id":      e.get("case_id"),
                "target_name":  e.get("target_name"),
                "strategy":     e.get("strategy"),
                "seed_integer": e.get("seed_integer"),
                "target_file":  e.get("target_file"),
                "target_line":  e.get("target_line"),
            }
            for e in plan.get("entries", [])
        ],
        key=lambda x: (x["target_name"] or "", x["case_id"] or ""),
    )
    canonical = {
        "targets_hash":     plan.get("targets_hash"),
        "requested_count":  plan.get("requested_count"),
        "planned_count":    plan.get("planned_count"),
        "entries":          entries,
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True).encode()
    ).hexdigest()[:16]


def _acceptance_fingerprint(summary: dict) -> str:
    """Stable fingerprint of portfolio acceptance counts."""
    canonical = {
        "accepted_count":  summary.get("accepted_count", 0),
        "rejected_count":  summary.get("rejected_count", 0),
        "error_count":     summary.get("error_count", 0),
        "planned_count":   summary.get("planned_count", 0),
        "by_target":       dict(sorted((summary.get("by_target") or {}).items())),
        "by_strategy":     dict(sorted((summary.get("by_strategy") or {}).items())),
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True).encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# CLI runners
# ---------------------------------------------------------------------------

def _run_generate_portfolio(
    targets_file: Path,
    count: int,
    output_root: Path,
    extra_args: list[str],
    dry_run: bool = False,
) -> tuple[bool, str]:
    """
    Run ``insert-me generate-portfolio``.

    Returns (ok, error_message).
    """
    output_root.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "insert_me.cli", "generate-portfolio",
        "--targets-file", str(targets_file),
        "--count", str(count),
        "--output-root", str(output_root),
    ]
    if dry_run:
        cmd.append("--dry-run")
    cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "(no output)")[:200]
    plan_file = output_root / "_plan" / "portfolio_plan.json"
    if not plan_file.exists():
        return False, f"portfolio_plan.json not written at {plan_file}"
    return True, ""


def _run_portfolio_replay(
    from_plan: Path,
    output_root: Path,
    extra_args: list[str],
) -> tuple[bool, str]:
    """
    Run ``insert-me generate-portfolio --from-plan``.

    Returns (ok, error_message).
    """
    output_root.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "insert_me.cli", "generate-portfolio",
        "--from-plan", str(from_plan),
        "--output-root", str(output_root),
    ]
    cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "(no output)")[:200]
    summary = output_root / "portfolio_acceptance_summary.json"
    if not summary.exists():
        return False, f"portfolio_acceptance_summary.json not written at {summary}"
    return True, ""


# ---------------------------------------------------------------------------
# Check 1: Fresh-plan stability
# ---------------------------------------------------------------------------

def check_fresh_plan_stability(
    targets_file: Path,
    count: int,
    runs: int,
    verbose: bool,
) -> dict:
    """
    Run generate-portfolio --dry-run N times, compare portfolio_plan.json.

    Returns a result dict with keys: passed, verdict, fingerprints, detail.
    """
    print(bold("\n[Check 1] Fresh-plan stability"))
    print(f"  Running {runs} independent fresh plans (--dry-run) ...")

    plans: list[dict] = []
    fingerprints: list[str] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="insert_me_port_plan_") as tmp:
        tmp_path = Path(tmp)
        for i in range(runs):
            out = tmp_path / f"run_{i}"
            ok, err = _run_generate_portfolio(targets_file, count, out, [], dry_run=True)
            if not ok:
                errors.append(f"run {i}: {err}")
                print(f"    run {i}  {red('ERROR')}  {err[:80]}")
                continue
            plan_file = out / "_plan" / "portfolio_plan.json"
            plan_data = json.loads(plan_file.read_text(encoding="utf-8"))
            fp = _portfolio_fingerprint(plan_data)
            plans.append(plan_data)
            fingerprints.append(fp)
            planned = plan_data.get("planned_count", "?")
            print(f"    run {i}  OK  planned={planned}  fingerprint={fp}")

    if errors:
        print(f"  {red('SKIP')} -- {len(errors)} run(s) failed")
        return {"passed": False, "verdict": "ERROR", "errors": errors, "fingerprints": fingerprints}

    all_same = len(set(fingerprints)) == 1
    if all_same:
        print(f"  {green('PASS')} -- all {runs} plans have identical fingerprint: {fingerprints[0]}")
        return {"passed": True, "verdict": "STABLE", "fingerprints": fingerprints, "errors": []}
    else:
        print(f"  {red('FAIL')} -- plan fingerprints differ: {fingerprints}")
        return {"passed": False, "verdict": "PLAN_UNSTABLE", "fingerprints": fingerprints, "errors": []}


# ---------------------------------------------------------------------------
# Check 2: Replay stability
# ---------------------------------------------------------------------------

def check_replay_stability(
    targets_file: Path,
    count: int,
    verbose: bool,
) -> dict:
    """
    Generate once (fresh), then replay from the saved plan.
    Compare portfolio_acceptance_summary.json accepted/rejected/error counts.

    Returns result dict.
    """
    print(bold("\n[Check 2] Replay stability"))
    print("  Running fresh generate, then replay from saved plan ...")

    with tempfile.TemporaryDirectory(prefix="insert_me_port_replay_") as tmp:
        tmp_path = Path(tmp)
        fresh_out = tmp_path / "fresh"
        replay_out = tmp_path / "replay"

        # Fresh run
        ok, err = _run_generate_portfolio(targets_file, count, fresh_out, [])
        if not ok:
            print(f"  {red('SKIP')} -- fresh run failed: {err[:100]}")
            return {"passed": False, "verdict": "ERROR", "error": err}

        summary_fresh = json.loads(
            (fresh_out / "portfolio_acceptance_summary.json").read_text(encoding="utf-8")
        )
        fp_fresh = _acceptance_fingerprint(summary_fresh)
        print(f"    fresh   accepted={summary_fresh.get('accepted_count')}  "
              f"rejected={summary_fresh.get('rejected_count')}  "
              f"fingerprint={fp_fresh}")

        # Replay
        plan_file = fresh_out / "_plan" / "portfolio_plan.json"
        ok, err = _run_portfolio_replay(plan_file, replay_out, [])
        if not ok:
            print(f"  {red('SKIP')} -- replay failed: {err[:100]}")
            return {"passed": False, "verdict": "ERROR", "error": err}

        summary_replay = json.loads(
            (replay_out / "portfolio_acceptance_summary.json").read_text(encoding="utf-8")
        )
        fp_replay = _acceptance_fingerprint(summary_replay)
        print(f"    replay  accepted={summary_replay.get('accepted_count')}  "
              f"rejected={summary_replay.get('rejected_count')}  "
              f"fingerprint={fp_replay}")

    if fp_fresh == fp_replay:
        print(f"  {green('PASS')} -- fresh and replay produce identical acceptance fingerprint")
        return {
            "passed": True, "verdict": "STABLE",
            "fresh_fingerprint": fp_fresh, "replay_fingerprint": fp_replay,
            "fresh_accepted": summary_fresh.get("accepted_count"),
            "replay_accepted": summary_replay.get("accepted_count"),
        }
    else:
        print(f"  {red('FAIL')} -- acceptance fingerprints differ: {fp_fresh!r} vs {fp_replay!r}")
        if verbose:
            print(f"    fresh  by_target : {summary_fresh.get('by_target')}")
            print(f"    replay by_target : {summary_replay.get('by_target')}")
        return {
            "passed": False, "verdict": "REPLAY_UNSTABLE",
            "fresh_fingerprint": fp_fresh, "replay_fingerprint": fp_replay,
        }


# ---------------------------------------------------------------------------
# Check 3: Sequential vs parallel parity
# ---------------------------------------------------------------------------

def check_seq_par_parity(
    targets_file: Path,
    count: int,
    par_jobs: int,
    verbose: bool,
) -> dict:
    """
    Run generate-portfolio with --jobs 1 and --jobs N.
    Compare acceptance fingerprints.

    Returns result dict.
    """
    print(bold(f"\n[Check 3] Sequential vs parallel parity  (--jobs 1 vs --jobs {par_jobs})"))

    with tempfile.TemporaryDirectory(prefix="insert_me_port_parity_") as tmp:
        tmp_path = Path(tmp)
        seq_out = tmp_path / "seq"
        par_out = tmp_path / "par"

        print("  Running sequential (--jobs 1) ...")
        ok, err = _run_generate_portfolio(targets_file, count, seq_out, ["--jobs", "1"])
        if not ok:
            print(f"  {red('SKIP')} -- sequential run failed: {err[:100]}")
            return {"passed": False, "verdict": "ERROR", "error": err}

        seq_summary = json.loads(
            (seq_out / "portfolio_acceptance_summary.json").read_text(encoding="utf-8")
        )
        fp_seq = _acceptance_fingerprint(seq_summary)
        print(f"    seq  accepted={seq_summary.get('accepted_count')}  "
              f"rejected={seq_summary.get('rejected_count')}  "
              f"fingerprint={fp_seq}")

        print(f"  Running parallel (--jobs {par_jobs}) ...")
        ok, err = _run_generate_portfolio(
            targets_file, count, par_out, ["--jobs", str(par_jobs)]
        )
        if not ok:
            print(f"  {red('SKIP')} -- parallel run failed: {err[:100]}")
            return {"passed": False, "verdict": "ERROR", "error": err}

        par_summary = json.loads(
            (par_out / "portfolio_acceptance_summary.json").read_text(encoding="utf-8")
        )
        fp_par = _acceptance_fingerprint(par_summary)
        print(f"    par  accepted={par_summary.get('accepted_count')}  "
              f"rejected={par_summary.get('rejected_count')}  "
              f"fingerprint={fp_par}")

    if fp_seq == fp_par:
        print(f"  {green('PASS')} -- sequential and parallel produce identical acceptance fingerprint")
        return {
            "passed": True, "verdict": "PARITY_OK",
            "seq_fingerprint": fp_seq, "par_fingerprint": fp_par,
            "seq_accepted": seq_summary.get("accepted_count"),
            "par_accepted": par_summary.get("accepted_count"),
            "jobs_used": par_jobs,
        }
    else:
        print(f"  {red('FAIL')} -- fingerprints differ: seq={fp_seq!r} par={fp_par!r}")
        if verbose:
            print(f"    seq by_target : {seq_summary.get('by_target')}")
            print(f"    par by_target : {par_summary.get('by_target')}")
        return {
            "passed": False, "verdict": "PARITY_FAIL",
            "seq_fingerprint": fp_seq, "par_fingerprint": fp_par,
        }


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _write_report(
    path: Path,
    targets_file: Path,
    count: int,
    check1: dict,
    check2: dict,
    check3: dict | None,
) -> None:
    """Write portfolio_repro_report.json."""
    all_passed = check1["passed"] and check2["passed"] and (
        check3 is None or check3["passed"]
    )
    verdict = "STABLE" if all_passed else "UNSTABLE"

    report = {
        "schema_version": "1.0",
        "phase": "17",
        "targets_file": str(targets_file.resolve()),
        "requested_count": count,
        "verdict": verdict,
        "all_checks_passed": all_passed,
        "checks": {
            "fresh_plan_stability": check1,
            "replay_stability": check2,
            "seq_par_parity": check3 if check3 is not None else {"skipped": True},
        },
        "repro_guarantees": {
            "fresh_plan": (
                "Same targets-file + same --count + same constraints "
                "=> byte-identical portfolio_plan.json on every fresh run."
            ),
            "replay": (
                "Same portfolio_plan.json => same accepted/rejected outcomes "
                "=> same acceptance fingerprint."
            ),
            "seq_par_parity": (
                "Sequential (--jobs 1) and parallel (--jobs N) execution "
                "produce identical acceptance_fingerprint for the same plan."
            ),
        },
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
        "--targets-file", type=Path, required=True, metavar="PATH",
        help="Path to targets JSON file.",
    )
    parser.add_argument(
        "--count", type=int, required=True, metavar="N",
        help="Global requested corpus case count.",
    )
    parser.add_argument(
        "--runs", type=int, default=3, metavar="INT",
        help="Number of fresh-plan runs for stability check (default: 3).",
    )
    parser.add_argument(
        "--par-jobs", type=int, default=min(os.cpu_count() or 2, 4), metavar="N",
        help="Worker count for parallel parity check (default: min(cpu_count, 4)).",
    )
    parser.add_argument(
        "--skip-parity", action="store_true",
        help="Skip sequential vs parallel parity check.",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path("portfolio_repro_report.json"),
        metavar="PATH",
        help="Output report path (default: portfolio_repro_report.json).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print field-level diff detail on failure.",
    )
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.no_color:
        _USE_COLOR = False

    if not args.targets_file.exists():
        print(f"ERROR: --targets-file not found: {args.targets_file}", file=sys.stderr)
        return 2
    if args.runs < 2:
        print("ERROR: --runs must be >= 2", file=sys.stderr)
        return 2

    print(bold("\ninsert_me portfolio stability check"))
    print(f"  targets-file : {args.targets_file}")
    print(f"  count        : {args.count}")
    print(f"  runs         : {args.runs}")
    print(f"  report       : {args.output}")

    check1 = check_fresh_plan_stability(
        args.targets_file, args.count, args.runs, args.verbose
    )
    check2 = check_replay_stability(
        args.targets_file, args.count, args.verbose
    )
    check3: dict | None = None
    if not args.skip_parity:
        check3 = check_seq_par_parity(
            args.targets_file, args.count, args.par_jobs, args.verbose
        )

    _write_report(args.output, args.targets_file, args.count, check1, check2, check3)

    all_passed = check1["passed"] and check2["passed"] and (
        check3 is None or check3["passed"]
    )

    print()
    print("=" * 55)
    print(f"  Verdict: {green('STABLE') if all_passed else red('UNSTABLE')}")
    print(f"  Check 1 (fresh-plan) : {green('PASS') if check1['passed'] else red('FAIL')}")
    print(f"  Check 2 (replay)     : {green('PASS') if check2['passed'] else red('FAIL')}")
    if check3 is not None:
        print(f"  Check 3 (seq/par)    : {green('PASS') if check3['passed'] else red('FAIL')}")
    else:
        print(f"  Check 3 (seq/par)    : {dim('SKIPPED')}")
    print(f"\n  Report: {args.output}")
    print("=" * 55)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
