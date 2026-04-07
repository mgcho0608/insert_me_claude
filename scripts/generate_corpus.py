#!/usr/bin/env python3
"""
generate_corpus.py — Batch corpus generation and quality-gate review for insert_me.

Runs all seed files in a seeds directory through the insert_me pipeline, applies the
formal quality gate rubric (docs/corpus_quality_gate.md), detects duplicates, and
writes a corpus manifest JSON.

Usage
-----
    python scripts/generate_corpus.py [OPTIONS]

Options
-------
    --seeds-dir PATH       Directory containing seed JSON files.
                           Default: examples/seeds/sandbox
    --source-root PATH     Root of the sandbox C/C++ source tree.
                           Default: examples/sandbox_eval/src
    --output-dir PATH      Base directory for generated bundles.
                           Default: output/corpus
    --manifest PATH        Path to write corpus manifest JSON.
                           Default: examples/corpus_manifest.json
    --batch-sizes SIZES    Comma-separated cumulative batch sizes (e.g. 2,5,10,20,30).
                           Seeds are processed in order; each size is a cumulative
                           checkpoint. Default: run all seeds in one batch.
    --dry-run              Print the generation plan without running the pipeline.
    --verbose              Print field-level detail for each case.
    --no-color             Disable ANSI colour output.

Exit codes
----------
    0   All cases ACCEPT or ACCEPT_WITH_NOTES
    1   One or more cases REVISE or REJECT
    2   Invocation or configuration error
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import textwrap
from collections import defaultdict
from datetime import date
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
def cyan(t: str) -> str:   return _c("36", t)
def bold(t: str) -> str:   return _c("1",  t)
def dim(t: str) -> str:    return _c("2",  t)


# ---------------------------------------------------------------------------
# Quality gate logic
# ---------------------------------------------------------------------------

_KNOWN_STRATEGIES = frozenset({
    "alloc_size_undercount",
    "insert_premature_free",
    "insert_double_free",
    "remove_free_call",
    "remove_null_guard",
})

# Functions that appear in ≥ 3 already-accepted cases will trigger a note.
_FUNCTION_NOTE_THRESHOLD = 3


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Cannot read {path}: {exc}") from exc


def _classify(
    seed_file: Path,
    bundle_dir: Path,
    accepted_targets: dict[str, int],      # "file:line" -> count so far
    accepted_functions: dict[str, int],    # "file:fn" -> count so far
    verbose: bool,
) -> dict:
    """
    Apply the corpus quality gate to one generated bundle.

    Returns a classification dict:
        {
            "classification":  "ACCEPT" | "ACCEPT_WITH_NOTES" | "REVISE" | "REJECT",
            "notes":           [str],   # reasons for ACCEPT_WITH_NOTES
            "reject_reasons":  [str],   # reasons for REJECT
            "revise_reasons":  [str],   # reasons for REVISE
            "case_meta":       dict,    # extracted metadata for the manifest
        }
    """
    notes: list[str] = []
    reject: list[str] = []
    revise: list[str] = []

    # Load seed for metadata
    seed_data = _load_json(seed_file)

    # --- Load artifacts ---
    plan_path   = bundle_dir / "patch_plan.json"
    gt_path     = bundle_dir / "ground_truth.json"
    audit_path  = bundle_dir / "audit_result.json"
    vr_path     = bundle_dir / "validation_result.json"

    for p in (plan_path, gt_path, audit_path, vr_path):
        if not p.exists():
            reject.append(f"Missing artifact: {p.name}")

    if reject:
        return _result("REJECT", notes, reject, revise, {})

    plan  = _load_json(plan_path)
    gt    = _load_json(gt_path)
    audit = _load_json(audit_path)
    vr    = _load_json(vr_path)

    # --- Extract target info ---
    targets = plan.get("targets", [])
    if not targets:
        reject.append("patch_plan.json has no targets (seed produced no candidates)")
        return _result("REJECT", notes, reject, revise, {})

    t0          = targets[0]
    target_file = t0.get("file", "")
    target_line = t0.get("line", 0)
    target_score = t0.get("candidate_score", 0.0)
    target_fn   = t0.get("context", {}).get("function_name", "")
    target_key  = f"{target_file}:{target_line}"
    fn_key      = f"{target_file}:{target_fn}"

    # --- Extract mutation info ---
    mutations = gt.get("mutations", [])
    mutation  = mutations[0] if mutations else {}
    orig      = mutation.get("original_fragment", "")
    mutated   = mutation.get("mutated_fragment", "")
    mut_type  = mutation.get("mutation_type", "")
    gt_file   = mutation.get("file", "")
    gt_line   = mutation.get("line", 0)
    cwe_id    = gt.get("cwe_id", seed_data.get("cwe_id", ""))

    # -----------------------------------------------------------------------
    # C1 — Single Primary Flaw (automated partial: audit classification)
    # -----------------------------------------------------------------------
    classification = audit.get("classification", "")
    if classification == "INVALID":
        reject.append(f"C1/C2: audit_result.classification == INVALID")
    elif classification == "NOOP":
        reject.append("C2: audit_result.classification == NOOP (no mutation applied)")
    elif classification == "AMBIGUOUS":
        revise.append("C1: audit_result.classification == AMBIGUOUS")

    # -----------------------------------------------------------------------
    # C2 — Bad/Good Pair Discipline
    # -----------------------------------------------------------------------
    # validation_result uses field "overall" (not "verdict") and check status
    # is recorded in "status" (not "passed").
    vr_overall = vr.get("overall", vr.get("verdict", ""))
    if str(vr_overall).lower() != "pass":
        revise.append(f"C2: validation_result.overall == {vr_overall!r} (expected 'pass')")
    else:
        # Check all 5 individual checks (status may be 'pass'/'fail' or 'PASS'/'FAIL')
        failed_checks = [
            c["name"] for c in vr.get("checks", [])
            if str(c.get("status", c.get("passed", "pass"))).lower() != "pass"
            and c.get("passed", True) is not True
        ]
        if failed_checks:
            revise.append(f"C2: validation checks failed: {failed_checks}")

    # -----------------------------------------------------------------------
    # C3 — Minimal Semantic Delta
    # -----------------------------------------------------------------------
    if not orig or not mutated:
        reject.append("C3/C5: original_fragment or mutated_fragment is empty")
    elif orig == mutated:
        reject.append("C3: original_fragment == mutated_fragment (no mutation)")
    if mut_type and mut_type not in _KNOWN_STRATEGIES:
        revise.append(f"C3: unknown mutation_type {mut_type!r}")

    # -----------------------------------------------------------------------
    # C4 — Explicit Vulnerable Intent
    # -----------------------------------------------------------------------
    seed_cwe   = seed_data.get("cwe_id", "")
    seed_strat = seed_data.get("mutation_strategy", "")
    if not cwe_id:
        reject.append("C4: cwe_id missing from ground_truth.json")
    elif seed_cwe and cwe_id != seed_cwe:
        reject.append(f"C4: cwe_id mismatch: ground_truth={cwe_id!r} seed={seed_cwe!r}")
    if seed_strat and mut_type and mut_type != seed_strat:
        revise.append(
            f"C4: mutation_type mismatch: ground_truth={mut_type!r} seed={seed_strat!r}"
        )

    # -----------------------------------------------------------------------
    # C5 — Oracle Completeness
    # -----------------------------------------------------------------------
    missing_oracle = []
    if not gt.get("cwe_id"):        missing_oracle.append("cwe_id")
    if not gt.get("spec_id"):       missing_oracle.append("spec_id")
    if not gt_file:                 missing_oracle.append("mutations[0].file")
    if not gt_line:                 missing_oracle.append("mutations[0].line")
    if not mut_type:                missing_oracle.append("mutations[0].mutation_type")
    if "validation_passed" not in gt: missing_oracle.append("validation_passed")
    if missing_oracle:
        revise.append(f"C5: missing oracle fields: {missing_oracle}")

    # -----------------------------------------------------------------------
    # C7 — Evaluator Usefulness (duplicate detection)
    # -----------------------------------------------------------------------
    if target_key in accepted_targets:
        reject.append(
            f"C7: duplicate target {target_key} already accepted "
            f"({accepted_targets[target_key]} prior case(s))"
        )

    # -----------------------------------------------------------------------
    # ACCEPT_WITH_NOTES thresholds
    # -----------------------------------------------------------------------
    if not reject and not revise:
        if target_score < 0.70:
            notes.append(
                f"C7: candidate_score={target_score:.2f} < 0.70 (lower-confidence selection)"
            )
        fn_count = accepted_functions.get(fn_key, 0)
        if fn_count >= _FUNCTION_NOTE_THRESHOLD:
            notes.append(
                f"C7: {fn_count} other accepted case(s) already target function "
                f"{target_fn!r} in {target_file} (reduced per-function signal diversity)"
            )
        # C6 and C7 human review pending (always note — human must verify)
        # We mark it only if no other notes would cover it.
        # Suppress if already noted for score or function density.
        if not notes:
            pass  # No automated concerns; human review still recommended per rubric.

    # -----------------------------------------------------------------------
    # Determine final classification
    # -----------------------------------------------------------------------
    if reject:
        cls = "REJECT"
    elif revise:
        cls = "REVISE"
    elif notes:
        cls = "ACCEPT_WITH_NOTES"
    else:
        cls = "ACCEPT"

    case_meta = {
        "case_id": seed_data.get("seed_id", seed_file.stem),
        "seed_file": str(seed_file),
        "seed": seed_data.get("seed"),
        "cwe_id": cwe_id,
        "strategy": mut_type or seed_strat,
        "target_file": target_file,
        "target_line": target_line,
        "target_function": target_fn,
        "candidate_score": target_score,
        "classification": cls,
        "notes": notes,
        "reject_reasons": reject,
        "revise_reasons": revise,
        "run_id": gt.get("run_id", ""),
        "source_hash": plan.get("source_hash", ""),
        "audit_classification": classification,
    }

    return _result(cls, notes, reject, revise, case_meta)


def _result(
    cls: str,
    notes: list[str],
    reject: list[str],
    revise: list[str],
    case_meta: dict,
) -> dict:
    return {
        "classification": cls,
        "notes": notes,
        "reject_reasons": reject,
        "revise_reasons": revise,
        "case_meta": case_meta,
    }


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def _run_seed(seed_file: Path, source_root: Path, output_dir: Path) -> Path | None:
    """Run insert-me for one seed. Returns the bundle directory path, or None on failure."""
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _print_case(
    idx: int,
    seed_file: Path,
    cls_result: dict,
    verbose: bool,
) -> None:
    cls   = cls_result["classification"]
    meta  = cls_result["case_meta"]
    notes = cls_result["notes"]
    rj    = cls_result["reject_reasons"]
    rv    = cls_result["revise_reasons"]

    cls_label = {
        "ACCEPT":             green(bold("ACCEPT           ")),
        "ACCEPT_WITH_NOTES":  yellow(bold("ACCEPT_WITH_NOTES")),
        "REVISE":             yellow(bold("REVISE           ")),
        "REJECT":             red(bold("REJECT           ")),
    }.get(cls, cls)

    target = f"{meta.get('target_file','?')}:{meta.get('target_line','?')}"
    fn     = meta.get("target_function", "?")
    score  = meta.get("candidate_score", 0.0)
    cwe    = meta.get("cwe_id", "?")

    print(
        f"  {idx:>3}  {cls_label}  "
        f"{seed_file.stem:<22}  {cwe:<8}  "
        f"{target:<20}  fn={fn}  score={score:.2f}"
    )

    if verbose or cls in ("REVISE", "REJECT"):
        for n in notes:
            print(f"       {yellow('NOTE')}  {n}")
        for r in rj:
            print(f"       {red('REJECT')} {r}")
        for r in rv:
            print(f"       {yellow('REVISE')} {r}")
        if cls == "ACCEPT_WITH_NOTES" and notes:
            pass  # already printed above


def _print_batch_summary(batch_idx: int, batch_results: list[dict]) -> None:
    counts = defaultdict(int)
    for r in batch_results:
        counts[r["classification"]] += 1
    total = len(batch_results)
    print()
    print(bold(f"  Batch {batch_idx} summary ({total} cases):"))
    print(f"    {green('ACCEPT')}:             {counts['ACCEPT']}")
    print(f"    {yellow('ACCEPT_WITH_NOTES')}: {counts['ACCEPT_WITH_NOTES']}")
    print(f"    {yellow('REVISE')}:            {counts['REVISE']}")
    print(f"    {red('REJECT')}:             {counts['REJECT']}")
    print()


def _write_manifest(
    manifest_path: Path,
    all_results: list[dict],
    seeds_dir: Path,
    source_root: Path,
) -> None:
    by_cls: dict[str, int] = defaultdict(int)
    by_cwe: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    by_strat: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    cases = []

    for r in all_results:
        cls  = r["classification"]
        meta = r["case_meta"]
        by_cls[cls] += 1
        cwe   = meta.get("cwe_id", "?")
        strat = meta.get("strategy", "?")
        by_cwe[cwe][cls.lower().replace(" ", "_")] += 1
        by_cwe[cwe]["count"] = by_cwe[cwe].get("count", 0) + 1
        by_strat[strat][cls.lower().replace(" ", "_")] += 1
        by_strat[strat]["count"] = by_strat[strat].get("count", 0) + 1
        cases.append({k: v for k, v in meta.items() if k not in ("reject_reasons", "revise_reasons")})

    manifest = {
        "schema_version": "1.0",
        "corpus_id": "sandbox-v1",
        "generated_at": str(date.today()),
        "seeds_dir": str(seeds_dir),
        "source_target": str(source_root),
        "total_cases": len(all_results),
        "accepted": by_cls.get("ACCEPT", 0),
        "accepted_with_notes": by_cls.get("ACCEPT_WITH_NOTES", 0),
        "revised": by_cls.get("REVISE", 0),
        "rejected": by_cls.get("REJECT", 0),
        "by_cwe": {k: dict(v) for k, v in sorted(by_cwe.items())},
        "by_strategy": {k: dict(v) for k, v in sorted(by_strat.items())},
        "cases": cases,
    }

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  Manifest written -> {manifest_path}")


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
        help="Directory containing seed JSON files (default: examples/seeds/sandbox)",
    )
    parser.add_argument(
        "--source-root", type=Path,
        default=Path("examples/sandbox_eval/src"),
        metavar="PATH",
        help="Root of sandbox C/C++ source tree (default: examples/sandbox_eval/src)",
    )
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("output/corpus"),
        metavar="PATH",
        help="Base directory for generated bundles (default: output/corpus)",
    )
    parser.add_argument(
        "--manifest", type=Path,
        default=Path("examples/corpus_manifest.json"),
        metavar="PATH",
        help="Path to write corpus manifest JSON (default: examples/corpus_manifest.json)",
    )
    parser.add_argument(
        "--batch-sizes", type=str,
        default=None,
        metavar="SIZES",
        help=(
            "Comma-separated cumulative batch sizes, e.g. 2,5,10,20,30. "
            "Each number is the total seeds processed up to that checkpoint. "
            "Default: process all seeds in one batch."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the generation plan without running the pipeline",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print field-level detail for each case",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output",
    )
    args = parser.parse_args(argv)

    if args.no_color:
        _USE_COLOR = False

    # --- Validate inputs ---
    if not args.seeds_dir.is_dir():
        print(f"ERROR: seeds-dir not found: {args.seeds_dir}", file=sys.stderr)
        return 2
    if not args.source_root.is_dir():
        print(f"ERROR: source-root not found: {args.source_root}", file=sys.stderr)
        return 2

    # --- Discover seeds ---
    seed_files = sorted(args.seeds_dir.glob("*.json"))
    if not seed_files:
        print(f"ERROR: No .json files found in {args.seeds_dir}", file=sys.stderr)
        return 2

    # --- Parse batch sizes ---
    if args.batch_sizes:
        try:
            checkpoints = [int(x.strip()) for x in args.batch_sizes.split(",")]
        except ValueError:
            print("ERROR: --batch-sizes must be comma-separated integers", file=sys.stderr)
            return 2
        # Build batch slices (exclusive upper bounds)
        prev = 0
        batches: list[list[Path]] = []
        for cp in checkpoints:
            batches.append(seed_files[prev:cp])
            prev = cp
        if prev < len(seed_files):
            batches.append(seed_files[prev:])
    else:
        batches = [seed_files]

    # --- Print plan ---
    print(bold(f"\ninsert_me corpus generator"))
    print(f"  seeds-dir   : {args.seeds_dir}")
    print(f"  source-root : {args.source_root}")
    print(f"  output-dir  : {args.output_dir}")
    print(f"  manifest    : {args.manifest}")
    print(f"  total seeds : {len(seed_files)}")
    print(f"  batches     : {len(batches)} ({[len(b) for b in batches]})")
    print()

    if args.dry_run:
        print(dim("Dry-run mode: no pipeline runs will be executed."))
        print()
        for i, batch in enumerate(batches, 1):
            print(bold(f"Batch {i} ({len(batch)} seeds):"))
            for sf in batch:
                sd = json.loads(sf.read_text(encoding="utf-8"))
                print(f"  {sf.stem:<22}  seed={sd.get('seed'):<4}  cwe={sd.get('cwe_id')}")
            print()
        return 0

    # --- Run batches ---
    all_results:   list[dict] = []
    accepted_targets:   dict[str, int] = {}
    accepted_functions: dict[str, int] = defaultdict(int)
    global_idx = 0
    any_fail = False

    for batch_idx, batch in enumerate(batches, 1):
        print(bold(f"Batch {batch_idx} - {len(batch)} seed(s):"))
        print(
            f"  {'#':>3}  {'Classification':<19}  {'Seed':<22}  {'CWE':<8}  "
            f"{'Target':<20}  Function"
        )
        print("  " + "-" * 90)

        batch_results: list[dict] = []

        for seed_file in batch:
            global_idx += 1

            # Run pipeline
            bundle_dir = _run_seed(seed_file, args.source_root, args.output_dir)
            if bundle_dir is None:
                cls_result = _result(
                    "REJECT",
                    [],
                    [f"Pipeline produced no bundle for {seed_file.name}"],
                    [],
                    {"seed_file": str(seed_file), "classification": "REJECT"},
                )
            else:
                try:
                    cls_result = _classify(
                        seed_file, bundle_dir,
                        accepted_targets, accepted_functions,
                        args.verbose,
                    )
                except RuntimeError as exc:
                    cls_result = _result("REJECT", [], [str(exc)], [], {
                        "seed_file": str(seed_file), "classification": "REJECT",
                    })

            _print_case(global_idx, seed_file, cls_result, args.verbose)

            cls  = cls_result["classification"]
            meta = cls_result.get("case_meta", {})

            # Update tracking state for accepted cases
            if cls in ("ACCEPT", "ACCEPT_WITH_NOTES"):
                tk = f"{meta.get('target_file','?')}:{meta.get('target_line','?')}"
                fk = f"{meta.get('target_file','?')}:{meta.get('target_function','?')}"
                accepted_targets[tk] = accepted_targets.get(tk, 0) + 1
                accepted_functions[fk] = accepted_functions.get(fk, 0) + 1

            if cls in ("REVISE", "REJECT"):
                any_fail = True

            batch_results.append(cls_result)
            all_results.append(cls_result)

        _print_batch_summary(batch_idx, batch_results)

    # --- Final summary ---
    counts: dict[str, int] = defaultdict(int)
    for r in all_results:
        counts[r["classification"]] += 1

    print(bold("Final corpus summary:"))
    print(f"  Total generated : {len(all_results)}")
    print(f"  {green('ACCEPT')}           : {counts['ACCEPT']}")
    print(f"  {yellow('ACCEPT_WITH_NOTES')}: {counts['ACCEPT_WITH_NOTES']}")
    print(f"  {yellow('REVISE')}           : {counts['REVISE']}")
    print(f"  {red('REJECT')}           : {counts['REJECT']}")
    accepted_total = counts["ACCEPT"] + counts["ACCEPT_WITH_NOTES"]
    if len(all_results) > 0:
        accept_rate = accepted_total / len(all_results) * 100
        print(f"  Accept rate     : {accept_rate:.1f}%  (target: >= 80%)")

    # Unique target stats
    print(f"  Unique targets  : {len(accepted_targets)}")
    files_hit = {k.split(":")[0] for k in accepted_targets}
    fns_hit   = {k.split(":")[1] for k in accepted_functions if accepted_functions[k] > 0}
    print(f"  Unique files    : {len(files_hit)}")
    print(f"  Unique functions: {len(fns_hit)}")
    print()

    # Health targets
    targets_met = True
    if accepted_total > 0:
        if accept_rate < 80:
            print(yellow("  WARNING: Accept rate below 80% target"))
            targets_met = False
        if counts["REJECT"] > 0.05 * len(all_results):
            print(yellow("  WARNING: Reject rate above 5% target"))
            targets_met = False
        if len(files_hit) < 4:
            print(yellow("  WARNING: Fewer than 4 unique source files (target: >= 4)"))
            targets_met = False

    if targets_met and accepted_total > 0:
        print(green("  All corpus health targets met."))
    print()

    # Write manifest
    _write_manifest(args.manifest, all_results, args.seeds_dir, args.source_root)
    print()

    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
