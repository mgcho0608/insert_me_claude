"""
CLI entrypoint for insert_me.

Commands
--------
run             Run the vulnerability insertion pipeline for a given seed file + source tree.
batch           Run the pipeline for every seed file in a directory.
inspect-target  Preflight suitability check for a C/C++ source tree (no mutation applied).
validate-bundle Validate the schema conformance of an existing output bundle.
audit           Pretty-print the audit record from an output bundle.
evaluate        Evaluate a detector report against an insert_me output bundle.

Canonical interface (primary)
------------------------------
    insert-me run --seed-file PATH --source PATH [--output PATH] [--config PATH] [--no-llm] [--dry-run]

Batch interface
---------------
    insert-me batch --seed-dir PATH --source PATH [--output PATH] [--config PATH] [--no-llm] [--dry-run]

Preflight suitability check
----------------------------
    insert-me inspect-target --source PATH [--output PATH]

Legacy interface (backward-compatible fallback)
-----------------------------------------------
    insert-me run --seed INT --spec PATH --source PATH [--output PATH] [--config PATH] [--no-llm]

    The legacy interface keeps the old --seed INT --spec PATH arguments working.
    The seed JSON file (--seed-file) is preferred: it captures seed integer,
    CWE class, mutation strategy, and target constraints in one versioned artifact.

Other commands
--------------
    insert-me validate-bundle output/<run-id>/
    insert-me audit output/<run-id>/audit.json
    insert-me evaluate --bundle output/<run-id>/ --tool-report report.json --tool cppcheck
"""

import argparse
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="insert-me",
        description="Deterministic seeded vulnerability generation for C/C++.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Canonical usage:\n"
            "  insert-me run --seed-file examples/seeds/cwe122_heap_overflow.json\n"
            "                --source /path/to/project\n\n"
            "Legacy usage (backward-compatible):\n"
            "  insert-me run --seed 42 --spec specs/cwe-122.toml\n"
            "                --source /path/to/project\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # -----------------------------------------------------------------------
    # run
    # -----------------------------------------------------------------------
    run_p = subparsers.add_parser(
        "run",
        help="Run the vulnerability insertion pipeline.",
        description=(
            "Run the vulnerability insertion pipeline against a C/C++ source tree\n"
            "and produce a complete, schema-validated output bundle.\n\n"
            "Default (real) mode applies one mutation and runs full validation.\n"
            "Use --dry-run to emit all artifacts without modifying source files.\n\n"
            "Primary input (canonical):\n"
            "  --seed-file PATH   Path to a seed JSON file (see seed.schema.json).\n"
            "                     The seed file contains the seed integer, CWE class,\n"
            "                     mutation strategy, and target constraints.\n\n"
            "Legacy input (backward-compatible):\n"
            "  --seed INT         Deterministic integer seed.\n"
            "  --spec PATH        Path to a vulnerability spec file.\n"
            "  (provide either --seed-file OR --seed + --spec, not both)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Primary canonical input
    run_p.add_argument(
        "--seed-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to seed JSON file (canonical primary input). "
            "See seed.schema.json and examples/seeds/. "
            "Mutually exclusive with --seed + --spec."
        ),
    )

    # Legacy inputs
    run_p.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="INT",
        help="[Legacy] Deterministic integer seed. Use --seed-file instead.",
    )
    run_p.add_argument(
        "--spec",
        type=Path,
        default=None,
        metavar="PATH",
        help="[Legacy] Path to vulnerability spec file. Use --seed-file instead.",
    )

    # Common arguments
    run_p.add_argument(
        "--source",
        type=Path,
        default=None,
        metavar="PATH",
        help="Root of the C/C++ source tree to mutate. May be a non-existent path in --dry-run mode.",
    )
    run_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Output root directory (default: ./output).",
    )
    run_p.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to config TOML (default: built-in defaults).",
    )
    run_p.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM adapter; use NoOpAdapter for all enrichment steps.",
    )
    run_p.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Emit all output artifacts without modifying source files. "
            "When not set (default), the Patcher is invoked and bad/good "
            "source trees are written when a compatible target is found."
        ),
    )
    run_p.set_defaults(func=_cmd_run)

    # -----------------------------------------------------------------------
    # batch
    # -----------------------------------------------------------------------
    batch_p = subparsers.add_parser(
        "batch",
        help="Run the pipeline for every seed file in a directory.",
        description=(
            "Run the vulnerability insertion pipeline for every .json seed file\n"
            "found in --seed-dir and collect results into a summary table.\n\n"
            "Each seed is processed sequentially. The command exits 0 if every\n"
            "seed produces a VALID bundle, non-zero if any seed fails.\n\n"
            "For quality-gate review and corpus manifests, use\n"
            "scripts/generate_corpus.py (a superset of this command).\n\n"
            "Example:\n"
            "  insert-me batch \\\n"
            "    --seed-dir examples/seeds/sandbox \\\n"
            "    --source   examples/sandbox_eval/src"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    batch_p.add_argument(
        "--seed-dir",
        type=Path,
        required=True,
        metavar="PATH",
        help="Directory containing seed JSON files (.json). All files are processed in sorted order.",
    )
    batch_p.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root of the C/C++ source tree to mutate.",
    )
    batch_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Output root directory (default: ./output).",
    )
    batch_p.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to config TOML (default: built-in defaults).",
    )
    batch_p.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM adapter; use NoOpAdapter for all enrichment steps.",
    )
    batch_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Emit all artifacts without modifying source files (passed through to each run).",
    )
    batch_p.set_defaults(func=_cmd_batch)

    # -----------------------------------------------------------------------
    # inspect-target
    # -----------------------------------------------------------------------
    inspect_p = subparsers.add_parser(
        "inspect-target",
        help="Preflight suitability check: scan a C/C++ source tree before running seeds.",
        description=(
            "Inspect a C/C++ source tree and report deterministic suitability signals\n"
            "for use with insert_me. No mutations are applied; this is a read-only scan.\n\n"
            "Reports:\n"
            "  - Number and list of C/C++ source files found\n"
            "  - Candidate site counts by strategy (corpus-admitted + experimental)\n"
            "  - File concentration risk\n"
            "  - Suitability tier: pilot-single / pilot-small-batch / corpus-generation\n"
            "  - Blockers and warnings\n\n"
            "Optionally writes a machine-readable target_suitability.json.\n\n"
            "Example:\n"
            "  insert-me inspect-target --source /path/to/local/toy_project\n"
            "  insert-me inspect-target --source /path/to/project --output inspect_out/"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inspect_p.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root of the C/C++ source tree to inspect.",
    )
    inspect_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "If provided, write target_suitability.json to this directory. "
            "Directory is created if it does not exist."
        ),
    )
    inspect_p.set_defaults(func=_cmd_inspect_target)

    # -----------------------------------------------------------------------
    # validate-bundle
    # -----------------------------------------------------------------------
    vb_p = subparsers.add_parser(
        "validate-bundle",
        help="Validate schema conformance of an output bundle directory.",
        description=(
            "Validates all recognised JSON artifacts in a bundle directory\n"
            "against their versioned schemas. Exits 0 if all present artifacts\n"
            "are valid, non-zero otherwise.\n\n"
            "Example:\n"
            "  insert-me validate-bundle output/a3f9c1e8b2d47065/"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vb_p.add_argument(
        "bundle",
        type=Path,
        metavar="BUNDLE_DIR",
        help="Path to the output bundle directory (the run-id subdirectory).",
    )
    vb_p.set_defaults(func=_cmd_validate_bundle)

    # -----------------------------------------------------------------------
    # audit
    # -----------------------------------------------------------------------
    audit_p = subparsers.add_parser(
        "audit",
        help="Pretty-print an audit.json record.",
    )
    audit_p.add_argument(
        "audit_file",
        type=Path,
        metavar="AUDIT_JSON",
        help="Path to audit.json file.",
    )
    audit_p.set_defaults(func=_cmd_audit)

    # -----------------------------------------------------------------------
    # evaluate
    # -----------------------------------------------------------------------
    eval_p = subparsers.add_parser(
        "evaluate",
        help="Evaluate a detector report against an insert_me output bundle.",
        description=(
            "Compare a normalized detector report (detector_report.schema.json)\n"
            "against the ground truth mutations in an existing insert_me output bundle.\n\n"
            "Produces match_result.json and coverage_result.json in the output directory.\n\n"
            "Match levels (in order of precedence):\n"
            "  exact    — same file basename, same CWE ID, line within ±2\n"
            "  family   — same CWE family group\n"
            "  semantic — keyword heuristic on finding message (adjudication_pending=True)\n"
            "  no_match — none of the above\n\n"
            "Example:\n"
            "  insert-me evaluate \\\n"
            "    --bundle output/abc123/ \\\n"
            "    --tool-report examples/evaluation/exact_match_report.json \\\n"
            "    --tool cppcheck-demo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    eval_p.add_argument(
        "--bundle",
        type=Path,
        required=True,
        metavar="PATH",
        help="Path to the existing insert_me output bundle directory (the run-id subdirectory).",
    )
    eval_p.add_argument(
        "--tool-report",
        type=Path,
        required=True,
        metavar="PATH",
        help="Path to the normalized detector report JSON file (detector_report.schema.json).",
    )
    eval_p.add_argument(
        "--tool",
        type=str,
        required=True,
        metavar="NAME",
        help="Tool name string, e.g. 'cppcheck', 'coverity'. Used in output artifact metadata.",
    )
    eval_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Directory where evaluation artifacts are written. Default: same as --bundle.",
    )
    eval_p.add_argument(
        "--adjudicator",
        type=str,
        default="heuristic",
        choices=["disabled", "heuristic"],
        metavar="MODE",
        help=(
            "Adjudication mode for semantic matches: "
            "'heuristic' (default) runs deterministic offline scoring; "
            "'disabled' leaves semantic matches unresolved."
        ),
    )
    eval_p.set_defaults(func=_cmd_evaluate)

    return parser


def _get_version() -> str:
    from insert_me import __version__
    return __version__


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def _cmd_run(args: argparse.Namespace) -> int:
    from insert_me.config import load_config, apply_cli_overrides
    from insert_me.pipeline import run_pipeline

    # ------------------------------------------------------------------
    # Validate mutual exclusivity of input modes
    # ------------------------------------------------------------------
    has_seed_file = args.seed_file is not None
    has_legacy = (args.seed is not None) or (args.spec is not None)

    if has_seed_file and has_legacy:
        print(
            "[insert-me] error: --seed-file is mutually exclusive with --seed and --spec.",
            file=sys.stderr,
        )
        return 2

    if not has_seed_file and not has_legacy:
        print(
            "[insert-me] error: provide --seed-file PATH (canonical) "
            "or --seed INT --spec PATH (legacy).",
            file=sys.stderr,
        )
        return 2

    if has_legacy:
        # Legacy mode requires both --seed and --spec
        if args.seed is None or args.spec is None:
            print(
                "[insert-me] error: legacy mode requires both --seed INT and --spec PATH.",
                file=sys.stderr,
            )
            return 2
        print(
            "[insert-me] warning: --seed + --spec is the legacy interface. "
            "Prefer --seed-file PATH for new runs.",
            file=sys.stderr,
        )

    # ------------------------------------------------------------------
    # Load and assemble config
    # ------------------------------------------------------------------
    config = load_config(args.config)
    config = apply_cli_overrides(
        config,
        seed_file=args.seed_file,
        seed=args.seed,
        spec_path=args.spec,
        source_path=args.source or Path("."),
        output_root=args.output,
        no_llm=args.no_llm,
    )

    # ------------------------------------------------------------------
    # Run pipeline
    # ------------------------------------------------------------------
    dry_run = args.dry_run  # False by default; --dry-run skips Patcher

    print(f"[insert-me] starting {'dry-run ' if dry_run else ''}pipeline")
    if config.pipeline.seed_file:
        print(f"  seed-file : {config.pipeline.seed_file}")
    else:
        print(f"  seed      : {config.pipeline.seed}")
        print(f"  spec      : {config.pipeline.spec_path}")
    print(f"  source    : {config.pipeline.source_path}")
    print(f"  output    : {config.pipeline.output_root}")

    try:
        bundle = run_pipeline(config, dry_run=dry_run)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[insert-me] error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[insert-me] unexpected error: {exc}", file=sys.stderr)
        raise

    print(f"[insert-me] bundle written to: {bundle.root}")
    print(f"  patch_plan.json       : {bundle.patch_plan}")
    print(f"  validation_result.json: {bundle.validation_result}")
    print(f"  audit_result.json     : {bundle.audit_result}")
    print(f"  ground_truth.json     : {bundle.ground_truth}")
    print(f"  audit.json            : {bundle.audit}")
    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    from insert_me.config import load_config, apply_cli_overrides
    from insert_me.pipeline import run_pipeline

    seed_dir: Path = args.seed_dir
    if not seed_dir.is_dir():
        print(f"[insert-me] error: --seed-dir not found: {seed_dir}", file=sys.stderr)
        return 2

    seed_files = sorted(seed_dir.glob("*.json"))
    if not seed_files:
        print(f"[insert-me] error: no .json files found in {seed_dir}", file=sys.stderr)
        return 2

    dry_run: bool = args.dry_run
    total = len(seed_files)

    print(f"[insert-me] batch {'dry-run ' if dry_run else ''}-- {total} seed(s) in {seed_dir}")
    print(f"  source : {args.source}")
    print(f"  output : {args.output or Path('output')}")
    print()
    print(f"  {'#':>3}  {'Result':<8}  {'Classification':<14}  {'Seed file'}")
    print("  " + "-" * 70)

    results: list[dict] = []
    any_fail = False

    for idx, seed_file in enumerate(seed_files, 1):
        config = load_config(args.config)
        config = apply_cli_overrides(
            config,
            seed_file=seed_file,
            source_path=args.source,
            output_root=args.output,
            no_llm=args.no_llm,
        )

        try:
            bundle = run_pipeline(config, dry_run=dry_run)
            # Read the audit classification from the emitted artifact
            import json as _json
            audit_result_path = bundle.audit_result
            classification = "UNKNOWN"
            if audit_result_path.exists():
                classification = _json.loads(
                    audit_result_path.read_text(encoding="utf-8")
                ).get("classification", "UNKNOWN")
            # In dry-run mode the Patcher is skipped so classification is NOOP — treat as OK.
            ok = classification == "VALID" or (dry_run and classification == "NOOP")
            status = "OK" if ok else "FAIL"
            if not ok:
                any_fail = True
        except Exception as exc:
            status = "ERROR"
            classification = str(exc)[:60]
            any_fail = True

        print(f"  {idx:>3}  {status:<8}  {classification:<14}  {seed_file.name}")
        results.append({"seed": seed_file.name, "status": status, "classification": classification})

    # Summary
    ok_count   = sum(1 for r in results if r["status"] == "OK")
    fail_count = sum(1 for r in results if r["status"] in ("FAIL", "ERROR"))
    print()
    print(f"[insert-me] batch complete: {ok_count}/{total} OK, {fail_count}/{total} failed")
    return 1 if any_fail else 0


def _cmd_validate_bundle(args: argparse.Namespace) -> int:
    from insert_me.schema import validate_bundle

    bundle_dir: Path = args.bundle
    print(f"[insert-me] validating bundle: {bundle_dir}")

    errors = validate_bundle(bundle_dir)
    if not errors:
        print("[insert-me] all artifacts valid.")
        return 0

    print(f"[insert-me] {len(errors)} validation error(s):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


def _cmd_audit(args: argparse.Namespace) -> int:
    import json

    audit_file: Path = args.audit_file
    if not audit_file.exists():
        print(f"[insert-me] error: file not found: {audit_file}", file=sys.stderr)
        return 1

    try:
        with open(audit_file, encoding="utf-8") as fh:
            data = json.load(fh)
        print(json.dumps(data, indent=2))
        return 0
    except json.JSONDecodeError as exc:
        print(f"[insert-me] error: invalid JSON in {audit_file}: {exc}", file=sys.stderr)
        return 1


def _cmd_evaluate(args: argparse.Namespace) -> int:
    import datetime
    import json

    from insert_me.evaluation import (
        Evaluator, emit_match_result, emit_coverage_result,
        DisabledAdjudicator, HeuristicAdjudicator,
    )
    from insert_me.evaluation.adjudication import emit_adjudication_result
    from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT

    bundle_dir: Path = args.bundle
    tool_report_path: Path = args.tool_report
    tool_name: str = args.tool
    output_dir: Path = args.output if args.output is not None else bundle_dir
    adjudicator_mode: str = getattr(args, "adjudicator", "heuristic")

    # --- Validate inputs ---
    if not bundle_dir.exists() or not bundle_dir.is_dir():
        print(
            f"[insert-me] error: bundle directory not found: {bundle_dir}",
            file=sys.stderr,
        )
        return 1

    if not tool_report_path.exists():
        print(
            f"[insert-me] error: tool report not found: {tool_report_path}",
            file=sys.stderr,
        )
        return 1

    ground_truth_path = bundle_dir / "ground_truth.json"
    if not ground_truth_path.exists():
        print(
            f"[insert-me] error: ground_truth.json not found in bundle: {bundle_dir}",
            file=sys.stderr,
        )
        return 1

    # --- Load and schema-validate the tool report ---
    try:
        with open(tool_report_path, encoding="utf-8") as fh:
            tool_report: dict = json.load(fh)
    except json.JSONDecodeError as exc:
        print(
            f"[insert-me] error: invalid JSON in tool report: {exc}",
            file=sys.stderr,
        )
        return 1

    try:
        validate_artifact(tool_report, SCHEMA_DETECTOR_REPORT)
    except Exception as exc:
        print(
            f"[insert-me] error: tool report does not conform to detector_report schema: {exc}",
            file=sys.stderr,
        )
        return 1

    # --- Build adjudicator ---
    if adjudicator_mode == "disabled":
        adjudicator = DisabledAdjudicator()
    else:
        adjudicator = HeuristicAdjudicator()

    # --- Run evaluation ---
    evaluator = Evaluator(bundle_dir, tool_report, tool_name, adjudicator=adjudicator)
    try:
        result = evaluator.run()
    except FileNotFoundError as exc:
        print(f"[insert-me] error: {exc}", file=sys.stderr)
        return 1

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    match_dict = emit_match_result(result, output_dir, now_utc)
    coverage_dict = emit_coverage_result(result, output_dir, now_utc)

    # --- Emit adjudication result (only when verdicts exist) ---
    emit_adjudication_result(
        result.match_records, result.run_id, tool_name,
        result.adjudicator_name, output_dir,
    )

    # --- Print summary ---
    total = coverage_dict["total_mutations"]
    matched = coverage_dict["matched"]
    unmatched = coverage_dict["unmatched"]
    coverage_rate = coverage_dict["coverage_rate"]
    false_positives = coverage_dict["false_positives"]

    print(f"[insert-me] evaluation complete")
    print(f"  tool            : {tool_name}")
    print(f"  bundle          : {bundle_dir}")
    print(f"  total_mutations : {total}")
    print(f"  matched         : {matched}")
    print(f"  unmatched       : {unmatched}")
    print(f"  coverage_rate   : {coverage_rate:.2%}")
    print(f"  false_positives : {false_positives}")
    print(f"  adjudicator     : {result.adjudicator_name}")
    if "adjudication_summary" in coverage_dict:
        s = coverage_dict["adjudication_summary"]
        print(f"  adj match       : {s['match']}")
        print(f"  adj unresolved  : {s['unresolved']}")
        print(f"  adj no_match    : {s['no_match']}")
    print(f"  match_result    : {output_dir / 'match_result.json'}")
    print(f"  coverage_result : {output_dir / 'coverage_result.json'}")
    adj_path = output_dir / "adjudication_result.json"
    if adj_path.exists():
        print(f"  adj_result      : {adj_path}")
    return 0


# ---------------------------------------------------------------------------
# inspect-target helpers
# ---------------------------------------------------------------------------

#: Corpus-admitted strategies and one experimental, mapped to their pattern types.
_INSPECT_STRATEGIES: tuple[tuple[str, str, str, bool], ...] = (
    # (strategy_name, cwe, pattern_type, experimental)
    ("alloc_size_undercount", "CWE-122", "malloc_call",   False),
    ("insert_premature_free", "CWE-416", "pointer_deref", False),
    ("insert_double_free",    "CWE-415", "free_call",     False),
    ("remove_free_call",      "CWE-401", "free_call",     False),
    ("remove_null_guard",     "CWE-476", "null_guard",    True),
)

_INSPECT_PATTERN_TYPES: tuple[str, ...] = (
    "malloc_call", "pointer_deref", "free_call", "null_guard"
)


def _inspect_source_tree(source_root: Path) -> dict:
    """
    Scan *source_root* and return a suitability report dict.

    Uses the same SOURCE_EXTENSIONS, DEFAULT_EXCLUDE_PATTERNS, and
    PATTERN_REGEXES as the Seeder.  No file writes; read-only.
    """
    import fnmatch

    from insert_me.pipeline.seeder import (
        SOURCE_EXTENSIONS,
        DEFAULT_EXCLUDE_PATTERNS,
        PATTERN_REGEXES,
    )

    all_paths = sorted(
        p for p in source_root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SOURCE_EXTENSIONS
        and not any(fnmatch.fnmatch(p.name, pat) for pat in DEFAULT_EXCLUDE_PATTERNS)
    )
    rel_files = [str(p.relative_to(source_root)) for p in all_paths]

    counts: dict[str, dict[str, int]] = {pt: {} for pt in _INSPECT_PATTERN_TYPES}
    compiled = {pt: PATTERN_REGEXES[pt] for pt in _INSPECT_PATTERN_TYPES}

    for fpath in all_paths:
        rel = str(fpath.relative_to(source_root))
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        in_block = False
        for line in lines:
            stripped = line.strip()
            if "/*" in stripped:
                in_block = True
            if "*/" in stripped:
                in_block = False
                continue
            if in_block or stripped.startswith("//"):
                continue
            for pt, rx in compiled.items():
                if rx.search(line):
                    counts[pt][rel] = counts[pt].get(rel, 0) + 1

    strategies: dict[str, dict] = {}
    for strategy_name, cwe, pattern_type, experimental in _INSPECT_STRATEGIES:
        by_file = counts[pattern_type]
        total = sum(by_file.values())
        entry: dict = {
            "cwe": cwe,
            "pattern_type": pattern_type,
            "total": total,
            "by_file": dict(by_file),
        }
        if experimental:
            entry["note"] = "experimental -- not corpus-admitted"
        strategies[strategy_name] = entry

    concentration: dict[str, dict] = {}
    for pt in _INSPECT_PATTERN_TYPES:
        by_file = counts[pt]
        total = sum(by_file.values())
        if total > 0:
            max_file = max(by_file, key=lambda k: by_file[k])
            fraction = round(by_file[max_file] / total, 3)
            concentration[pt] = {"file": max_file, "fraction": fraction, "total": total}
        else:
            concentration[pt] = {"file": None, "fraction": 0.0, "total": 0}

    _corpus_admitted = [s for s, _, _, exp in _INSPECT_STRATEGIES if not exp]

    def _files_with_hits(sname: str) -> int:
        return sum(1 for v in strategies[sname]["by_file"].values() if v > 0)

    blockers: list[str] = []
    warnings: list[str] = []

    file_count = len(all_paths)
    if file_count == 0:
        blockers.append(
            "No C/C++ source files found. Ensure --source points at a directory "
            "containing .c, .cpp, .cc, .cxx, .h, .hpp, or .hh files."
        )

    admitted_nonzero = [s for s in _corpus_admitted if strategies[s]["total"] > 0]
    pilot_single = bool(admitted_nonzero)
    if not pilot_single and file_count > 0:
        blockers.append(
            "No candidate sites found for any corpus-admitted strategy. "
            "Check that the source files contain malloc/free/pointer-dereference patterns."
        )

    batch_ready = [
        s for s in _corpus_admitted
        if strategies[s]["total"] >= 5 and _files_with_hits(s) >= 2
    ]
    pilot_batch = bool(batch_ready)
    if pilot_single and not pilot_batch:
        warnings.append(
            "Too few candidates for a small batch (need >= 5 candidates across >= 2 files "
            "for at least one admitted strategy). Suitable for single-case pilot only."
        )

    corpus_ready_strategies = [
        s for s in _corpus_admitted
        if strategies[s]["total"] >= 10 and _files_with_hits(s) >= 3
    ]
    corpus_ready = len(corpus_ready_strategies) >= 2

    if file_count > 0 and file_count < 3 and pilot_batch and not corpus_ready:
        warnings.append(
            f"Only {file_count} source file(s) found. "
            "Corpus generation typically needs >= 3 files for adequate diversity."
        )

    for pt in ("malloc_call", "pointer_deref", "free_call"):
        c = concentration[pt]
        if c["total"] >= 5 and c["fraction"] > 0.80:
            warnings.append(
                f"High concentration risk for {pt}: {c['fraction']:.0%} of candidates "
                f"in one file ({c['file']}). Corpus quality gate may flag over-concentration."
            )
        elif c["total"] >= 5 and c["fraction"] > 0.60:
            warnings.append(
                f"Moderate concentration for {pt}: {c['fraction']:.0%} of candidates "
                f"in one file ({c['file']})."
            )

    if not corpus_ready and pilot_batch:
        warnings.append(
            "Corpus generation needs >= 2 strategies each with >= 10 candidates "
            "across >= 3 files. Consider adding more source files or choosing a richer target."
        )

    return {
        "schema_version": "1.0",
        "source_root": str(source_root.resolve()),
        "file_count": file_count,
        "files": rel_files,
        "candidates_by_strategy": strategies,
        "concentration_risk": concentration,
        "suitability": {
            "pilot_single_case": pilot_single,
            "pilot_small_batch": pilot_batch,
            "corpus_generation": corpus_ready,
            "blockers": blockers,
            "warnings": warnings,
        },
    }


def _format_inspection_report(report: dict) -> str:
    """Format a suitability report dict as a human-readable string."""
    out: list[str] = []
    suitability = report["suitability"]

    out.append(f"[insert-me] target inspection: {report['source_root']}")
    out.append("")
    out.append(f"Source files found: {report['file_count']}")
    for f in report["files"]:
        out.append(f"  {f}")

    out.append("")
    out.append("Candidate sites by strategy:")
    for strategy_name, info in report["candidates_by_strategy"].items():
        total = info["total"]
        n_files = sum(1 for v in info["by_file"].values() if v > 0)
        exp_tag = "  [experimental]" if "note" in info else ""
        label = f"{strategy_name} ({info['cwe']}, {info['pattern_type']}){exp_tag}"
        out.append(f"  {label:<55}: {total:>4}  candidates across {n_files} file(s)")

    out.append("")
    out.append("Concentration risk (fraction of candidates in most-loaded file):")
    for pt, c in report["concentration_risk"].items():
        if c["total"] > 0:
            risk = "HIGH" if c["fraction"] > 0.80 else ("MODERATE" if c["fraction"] > 0.60 else "OK")
            out.append(f"  {pt:<18}: {c['fraction']:>5.0%} in {c['file']}  [{risk}]")
        else:
            out.append(f"  {pt:<18}: no candidates")

    out.append("")
    out.append("Suitability assessment:")
    def yn(v: bool) -> str:
        return "YES" if v else "NO "
    out.append(f"  pilot_single_case  : {yn(suitability['pilot_single_case'])}  "
               "(any admitted strategy has >= 1 candidate)")
    out.append(f"  pilot_small_batch  : {yn(suitability['pilot_small_batch'])}  "
               "(>= 1 strategy with >= 5 candidates across >= 2 files)")
    out.append(f"  corpus_generation  : {yn(suitability['corpus_generation'])}  "
               "(>= 2 strategies with >= 10 candidates across >= 3 files)")

    if suitability["blockers"]:
        out.append("")
        out.append("BLOCKERS:")
        for b in suitability["blockers"]:
            out.append(f"  [!] {b}")

    if suitability["warnings"]:
        out.append("")
        out.append("Warnings:")
        for w in suitability["warnings"]:
            out.append(f"  [~] {w}")

    if not suitability["blockers"] and not suitability["warnings"]:
        out.append("")
        out.append("No blockers or warnings.")

    return "\n".join(out)


def _cmd_inspect_target(args: argparse.Namespace) -> int:
    import json

    source: Path = args.source
    output_dir: Path | None = args.output

    if not source.exists():
        print(f"[insert-me] error: --source not found: {source}", file=sys.stderr)
        return 1
    if not source.is_dir():
        print(f"[insert-me] error: --source must be a directory: {source}", file=sys.stderr)
        return 1

    report = _inspect_source_tree(source)
    print(_format_inspection_report(report))

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / "target_suitability.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[insert-me] suitability report written to: {out_path}")

    return 1 if report["suitability"]["blockers"] else 0


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
