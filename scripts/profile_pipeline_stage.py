#!/usr/bin/env python3
"""
profile_pipeline_stage.py -- per-stage pipeline timing for insert_me.

Runs one seed through each pipeline stage (Seeder, Patcher, Validator, Auditor)
using the Python API directly, measuring wall-clock time per stage.

Usage::

    python scripts/profile_pipeline_stage.py \\
        --seed-file examples/seeds/sandbox/cwe416_sb_001.json \\
        --source    examples/sandbox_eval/src \\
        [--runs N]  [--output stage_timing_report.json]

Exit code:
  0  -- timing report written successfully
  1  -- error

Output artifact: ``stage_timing_report.json`` with fields:
  - phase, seed_file, source, runs
  - stages: seeder, patcher, validator, auditor
    each with: mean_ms, min_ms, max_ms, all_ms
  - pipeline_total_mean_ms
  - dominant_stage
  - bottleneck_pct
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent


def _load_workload_classes() -> dict[str, Any]:
    p = REPO_ROOT / "config" / "workload_classes.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _classify_target(source: Path, wc: dict[str, Any]) -> str:
    """Return workload class label for a given source directory."""
    # Count files and LOC
    c_files = list(source.rglob("*.c")) + list(source.rglob("*.cpp")) + \
              list(source.rglob("*.h")) + list(source.rglob("*.hpp"))
    n_files = len(c_files)
    loc = sum(len(f.read_text(encoding="utf-8", errors="replace").splitlines()) for f in c_files)

    for cls_name, cls in wc["classes"].items():
        loc_ok = loc <= cls.get("loc_max", 10**9) and loc >= cls.get("loc_min", 0)
        files_ok = n_files <= cls.get("files_max", 10**9) and n_files >= cls.get("files_min", 0)
        if loc_ok and files_ok:
            return cls_name
    return "large_phase16"


def run_stage_profiling(
    seed_file: Path,
    source: Path,
    runs: int = 5,
) -> dict[str, Any]:
    """Run the pipeline stages individually and return timing data."""
    from insert_me.artifacts import BundlePaths
    from insert_me.pipeline.auditor import Auditor
    from insert_me.pipeline.patcher import Patcher
    from insert_me.pipeline.seeder import Seeder
    from insert_me.pipeline.validator import Validator

    seed_data = json.loads(seed_file.read_text(encoding="utf-8"))
    seed_int = seed_data["seed"]

    stage_times: dict[str, list[float]] = {
        "seeder": [],
        "patcher": [],
        "validator": [],
        "auditor": [],
    }

    for _ in range(runs):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = BundlePaths.from_run_id(Path(tmp), "prof_run")
            bundle.create_dirs()

            # Seeder
            t0 = time.perf_counter()
            seeder = Seeder(seed=seed_int, spec=seed_data, source_root=source)
            target_list = seeder.run()
            stage_times["seeder"].append((time.perf_counter() - t0) * 1000)

            # Patcher
            t0 = time.perf_counter()
            patcher = Patcher(
                targets=target_list,
                bad_root=bundle.bad_dir,
                good_root=bundle.good_dir,
            )
            patch_result = patcher.run()
            stage_times["patcher"].append((time.perf_counter() - t0) * 1000)

            # Validator
            t0 = time.perf_counter()
            validator = Validator(patch_result=patch_result, source_root=source)
            verdict = validator.run()
            stage_times["validator"].append((time.perf_counter() - t0) * 1000)

            # Auditor
            t0 = time.perf_counter()
            auditor = Auditor(
                patch_result,
                verdict,
                bundle,
                run_id="prof_run",
                seed=seed_int,
                seed_data=seed_data,
                pipeline_version="profile",
                spec_path=seed_file,
                spec_hash="profiling",
                source_root=source,
                source_hash=target_list.source_hash,
            )
            auditor.run()
            stage_times["auditor"].append((time.perf_counter() - t0) * 1000)

    stages_out: dict[str, dict[str, float]] = {}
    totals: list[float] = []

    for stage, times in stage_times.items():
        stages_out[stage] = {
            "mean_ms": round(sum(times) / len(times), 2),
            "min_ms": round(min(times), 2),
            "max_ms": round(max(times), 2),
            "all_ms": [round(t, 2) for t in times],
        }

    for i in range(runs):
        totals.append(sum(stage_times[s][i] for s in stage_times))

    total_mean = sum(totals) / len(totals)
    dominant = max(stages_out, key=lambda s: stages_out[s]["mean_ms"])
    dom_pct = round(100 * stages_out[dominant]["mean_ms"] / total_mean, 1)

    wc = _load_workload_classes()
    workload_class = _classify_target(source, wc)

    return {
        "schema_version": "1.0",
        "phase": "16",
        "seed_file": str(seed_file),
        "source": str(source),
        "source_workload_class": workload_class,
        "runs": runs,
        "stages": stages_out,
        "pipeline_total_mean_ms": round(total_mean, 2),
        "dominant_stage": dominant,
        "dominant_stage_pct": dom_pct,
        "bottleneck_note": (
            f"'{dominant}' consumed {dom_pct}% of pipeline time "
            f"({stages_out[dominant]['mean_ms']:.1f}ms / {total_mean:.1f}ms)"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Per-stage pipeline timing for insert_me."
    )
    parser.add_argument(
        "--seed-file", required=True, type=Path,
        help="Path to seed JSON file.",
    )
    parser.add_argument(
        "--source", required=True, type=Path,
        help="Path to C/C++ source directory.",
    )
    parser.add_argument(
        "--runs", type=int, default=5,
        help="Number of timing runs (default: 5).",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("stage_timing_report.json"),
        help="Output JSON file path (default: stage_timing_report.json).",
    )
    args = parser.parse_args()

    if not args.seed_file.exists():
        print(f"ERROR: seed file not found: {args.seed_file}", file=sys.stderr)
        return 1
    if not args.source.exists():
        print(f"ERROR: source directory not found: {args.source}", file=sys.stderr)
        return 1

    print(f"Profiling pipeline stages: {args.source.name}  ({args.runs} runs)")
    report = run_stage_profiling(args.seed_file, args.source, runs=args.runs)

    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Stage timing report written: {args.output}")
    print()
    print(f"  Pipeline total (mean): {report['pipeline_total_mean_ms']:.1f}ms")
    for stage, data in report["stages"].items():
        pct = round(100 * data["mean_ms"] / report["pipeline_total_mean_ms"], 0)
        print(f"    {stage:12s}  {data['mean_ms']:6.1f}ms  ({pct:.0f}%)")
    print(f"  Bottleneck: {report['bottleneck_note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
