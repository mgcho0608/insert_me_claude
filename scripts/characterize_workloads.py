#!/usr/bin/env python3
"""
characterize_workloads.py -- workload characterization for insert_me.

Runs inspect-target, plan-corpus, and (optionally) generate-corpus on each
known bundled fixture and produces machine-readable characterization artifacts.

Output artifacts (written to --output-dir):
  support_matrix.json       -- per-target suitability + capacity data
  target_classification.json -- workload class assignment for each target
  workload_report.json      -- combined inspection + generation results

Usage::

    python scripts/characterize_workloads.py [--output-dir output/characterization]
    python scripts/characterize_workloads.py --skip-generate    # inspection only (fast)
    python scripts/characterize_workloads.py --generate-count 5 # small counts

Exit code:
  0  -- all artifacts written
  1  -- error
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent

KNOWN_TARGETS = {
    "minimal":     REPO_ROOT / "examples" / "local_targets" / "minimal" / "src",
    "demo":        REPO_ROOT / "examples" / "demo" / "src",
    "moderate":    REPO_ROOT / "examples" / "local_targets" / "moderate" / "src",
    "target_b":    REPO_ROOT / "examples" / "sandbox_targets" / "target_b" / "src",
    "sandbox_eval":REPO_ROOT / "examples" / "sandbox_eval" / "src",
}

# Representative seed files for generate-corpus timing
TIMING_SEEDS = {
    "minimal":     REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json",
    "demo":        REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json",
    "moderate":    REPO_ROOT / "examples" / "seeds" / "sandbox" / "cwe416_sb_001.json",
    "target_b":    REPO_ROOT / "examples" / "seeds" / "sandbox" / "cwe416_sb_001.json",
    "sandbox_eval":REPO_ROOT / "examples" / "seeds" / "sandbox" / "cwe416_sb_001.json",
}


def _run_cli(*args: str, cwd: Path = REPO_ROOT) -> tuple[int, str, str]:
    """Run insert-me CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", *args],
        capture_output=True, text=True, cwd=cwd,
    )
    return result.returncode, result.stdout, result.stderr


def _count_files_and_loc(source: Path) -> tuple[int, int]:
    exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    files = [f for f in source.rglob("*") if f.suffix in exts]
    loc = sum(
        len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        for f in files
    )
    return len(files), loc


def _load_workload_classes() -> dict[str, Any]:
    return json.loads(
        (REPO_ROOT / "config" / "workload_classes.json").read_text(encoding="utf-8")
    )


def _classify(files: int, loc: int, wc: dict[str, Any]) -> str:
    for cls_name, cls in wc["classes"].items():
        loc_ok = loc <= cls.get("loc_max", 10**9) and loc >= cls.get("loc_min", 0)
        file_ok = files <= cls.get("files_max", 10**9) and files >= cls.get("files_min", 0)
        if loc_ok and file_ok:
            return cls_name
    return "large_phase16"


def _inspect_target(name: str, source: Path) -> dict[str, Any]:
    """Run inspect-target and return structured result."""
    from insert_me.planning import TargetInspector
    insp = TargetInspector(source)
    result = insp.run()
    d = result.to_dict()
    return {
        "file_count": d["file_count"],
        "max_supportable": d["max_supportable_count"],
        "suitability_summary": d["suitability_summary"],
        "strategies": {
            sid: {
                "suitability": sv["suitability"],
                "total_candidates": sv["total_candidates"],
                "files_with_candidates": sv["files_with_candidates"],
                "max_file_fraction": sv["max_file_fraction"],
            }
            for sid, sv in d["strategies"].items()
            if sv["corpus_admitted"]
        },
    }


def _plan_corpus(source: Path, count: int) -> tuple[int, float]:
    """Run plan-corpus and return (planned_count, elapsed_ms)."""
    with tempfile.TemporaryDirectory() as tmp:
        t0 = time.perf_counter()
        rc, out, err = _run_cli(
            "plan-corpus", "--source", str(source),
            "--count", str(count), "--output-dir", tmp,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        plan_path = Path(tmp) / "corpus_plan.json"
        if plan_path.exists():
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            planned = plan.get("planned_count", 0)
        else:
            planned = 0
        return planned, round(elapsed_ms, 1)


def _generate_corpus(
    source: Path, count: int, dry_run: bool = False
) -> tuple[int, int, float]:
    """Run generate-corpus and return (planned, accepted, elapsed_ms)."""
    with tempfile.TemporaryDirectory() as tmp:
        out_root = Path(tmp) / "gen"
        args = [
            "generate-corpus", "--source", str(source),
            "--count", str(count), "--output-root", str(out_root),
        ]
        if dry_run:
            args.append("--dry-run")
        t0 = time.perf_counter()
        rc, out, err = _run_cli(*args)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        summ_path = out_root / "acceptance_summary.json"
        if summ_path.exists():
            s = json.loads(summ_path.read_text(encoding="utf-8"))
            planned = s.get("planned_count", 0)
            accepted = s.get("accepted_count", 0)
        else:
            planned = accepted = 0
        return planned, accepted, round(elapsed_ms, 1)


def characterize_all(
    skip_generate: bool = False,
    generate_count: int = 5,
) -> dict[str, Any]:
    """Run full characterization and return combined results dict."""
    wc = _load_workload_classes()
    results: dict[str, Any] = {}

    for name, source in KNOWN_TARGETS.items():
        if not source.exists():
            print(f"  [SKIP] {name}: path not found ({source})", file=sys.stderr)
            continue

        print(f"  [{name}]  inspecting...")
        n_files, loc = _count_files_and_loc(source)
        workload_class = _classify(n_files, loc, wc)
        cls_info = wc["classes"][workload_class]

        t0 = time.perf_counter()
        inspect_data = _inspect_target(name, source)
        inspect_ms = round((time.perf_counter() - t0) * 1000, 1)

        # Determine a sensible count for this target
        count = min(generate_count, cls_info["recommended_max_count"])

        print(f"  [{name}]  planning (count={count})...")
        planned_count, plan_ms = _plan_corpus(source, count)

        gen_result: dict[str, Any] = {}
        if not skip_generate:
            print(f"  [{name}]  generating (count={count})...")
            planned_gen, accepted, gen_ms = _generate_corpus(source, count)
            per_case_ms = round(gen_ms / max(accepted, 1), 1)
            gen_result = {
                "requested_count": count,
                "planned_count": planned_gen,
                "accepted_count": accepted,
                "shortfall": planned_gen - accepted,
                "total_time_ms": gen_ms,
                "per_case_time_ms": per_case_ms,
            }

        results[name] = {
            "source": str(source.relative_to(REPO_ROOT)),
            "workload_class": workload_class,
            "files": n_files,
            "loc_approx": loc,
            "support_level": cls_info["support_level"],
            "recommended_max_count": cls_info["recommended_max_count"],
            "inspect": {
                "elapsed_ms": inspect_ms,
                **inspect_data,
            },
            "plan_corpus": {
                "requested_count": count,
                "planned_count": planned_count,
                "plan_time_ms": plan_ms,
            },
        }
        if gen_result:
            results[name]["generate_corpus"] = gen_result

    return results


def _build_support_matrix(
    results: dict[str, Any], wc: dict[str, Any]
) -> dict[str, Any]:
    matrix_targets = {}
    for name, r in results.items():
        suitability = r["inspect"].get("suitability_summary", {})
        viable = suitability.get("viable", [])
        matrix_targets[name] = {
            "workload_class": r["workload_class"],
            "support_level": r["support_level"],
            "files": r["files"],
            "loc_approx": r["loc_approx"],
            "max_supportable": r["inspect"].get("max_supportable", "?"),
            "recommended_max_count": r["recommended_max_count"],
            "viable_strategy_count": len(viable),
            "viable_strategies": viable,
            "inspect_tier": (
                "corpus_generation" if "corpus_generation" in str(suitability)
                else ("pilot_small_batch" if suitability.get("viable") or suitability.get("limited")
                      else "pilot_single_only")
            ),
        }
        if "generate_corpus" in r:
            gc = r["generate_corpus"]
            matrix_targets[name]["generation_result"] = {
                "requested": gc["requested_count"],
                "accepted": gc["accepted_count"],
                "shortfall": gc["shortfall"],
                "per_case_ms": gc["per_case_time_ms"],
            }
    return {
        "schema_version": "1.0",
        "phase": "16",
        "workload_class_thresholds": {
            cls: {
                "loc_range": [c.get("loc_min", 0), c.get("loc_max", None)],
                "files_range": [c.get("files_min", 0), c.get("files_max", None)],
                "support_level": c["support_level"],
                "recommended_max_count": c["recommended_max_count"],
            }
            for cls, c in wc["classes"].items()
        },
        "targets": matrix_targets,
    }


def _build_target_classification(results: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "phase": "16",
        "classifications": {
            name: {
                "workload_class": r["workload_class"],
                "support_level": r["support_level"],
                "recommended_max_count": r["recommended_max_count"],
                "files": r["files"],
                "loc_approx": r["loc_approx"],
            }
            for name, r in results.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Characterize insert_me workloads on bundled fixtures."
    )
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("output") / "characterization",
        help="Directory for output artifacts (default: output/characterization/).",
    )
    parser.add_argument(
        "--skip-generate", action="store_true",
        help="Skip generate-corpus runs (inspect + plan only; fast mode).",
    )
    parser.add_argument(
        "--generate-count", type=int, default=5,
        help="Cases to request per target during generate-corpus (default: 5).",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    wc = _load_workload_classes()

    print(f"\ninsert_me workload characterization")
    print(f"  output dir  : {args.output_dir}")
    print(f"  skip-generate: {args.skip_generate}")
    print(f"  generate-count: {args.generate_count}")
    print()

    results = characterize_all(
        skip_generate=args.skip_generate,
        generate_count=args.generate_count,
    )

    # workload_report.json
    report = {
        "schema_version": "1.0",
        "phase": "16",
        "skip_generate": args.skip_generate,
        "generate_count": args.generate_count,
        "targets": results,
    }
    (args.output_dir / "workload_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    # support_matrix.json
    matrix = _build_support_matrix(results, wc)
    (args.output_dir / "support_matrix.json").write_text(
        json.dumps(matrix, indent=2), encoding="utf-8"
    )

    # target_classification.json
    classification = _build_target_classification(results)
    (args.output_dir / "target_classification.json").write_text(
        json.dumps(classification, indent=2), encoding="utf-8"
    )

    print()
    print("Artifacts written:")
    for fname in ("workload_report.json", "support_matrix.json", "target_classification.json"):
        p = args.output_dir / fname
        print(f"  {p}  ({p.stat().st_size} bytes)")

    print()
    print("Target summary:")
    print(f"  {'Name':15s}  {'Class':18s}  {'Files':5s}  {'LOC':5s}  {'Support':30s}")
    for name, r in results.items():
        print(f"  {name:15s}  {r['workload_class']:18s}  {r['files']:5d}  "
              f"{r['loc_approx']:5d}  {r['support_level']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
