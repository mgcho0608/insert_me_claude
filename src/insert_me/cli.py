"""
CLI entrypoint for insert_me.

Commands
--------
run               Run the vulnerability insertion pipeline for a given seed file + source tree.
batch             Run the pipeline for every seed file in a directory.
inspect-target    Preflight suitability check for a C/C++ source tree (no mutation applied).
plan-corpus       Target-aware corpus planning: synthesise seeds for a requested count.
generate-corpus   Plan + execute the full corpus pipeline toward a requested count.
plan-portfolio    Multi-target corpus planning across a list of targets.
generate-portfolio Plan + execute a multi-target corpus across a list of targets.
validate-bundle   Validate the schema conformance of an existing output bundle.
audit             Pretty-print the audit record from an output bundle.
evaluate          Evaluate a detector report against an insert_me output bundle.

Expert/manual seed-driven interface (single-case)
--------------------------------------------------
    insert-me run --seed-file PATH --source PATH [--output PATH] [--config PATH] [--no-llm] [--dry-run]

Expert/manual batch interface
------------------------------
    insert-me batch --seed-dir PATH --source PATH [--output PATH] [--config PATH] [--no-llm] [--dry-run]

Preflight suitability check
----------------------------
    insert-me inspect-target --source PATH [--output PATH]

Count-driven corpus planning
-----------------------------
    insert-me plan-corpus --source PATH --count N [--output-dir DIR] [options]
    insert-me generate-corpus --source PATH --count N [--output-root DIR] [options]

Multi-target portfolio planning
--------------------------------
    insert-me plan-portfolio --targets-file TARGETS.json --count N [--output-dir DIR] [options]
    insert-me generate-portfolio --targets-file TARGETS.json --count N [--output-root DIR] [options]
    insert-me generate-portfolio --from-plan portfolio_plan.json [--output-root DIR] [options]

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
import os
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="insert-me",
        description="Deterministic seeded vulnerability generation for C/C++.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Recommended (single-target corpus):\n"
            "  insert-me inspect-target --source /path/to/c-project\n"
            "  insert-me generate-corpus --source /path/to/c-project --count 20\n\n"
            "Recommended (multi-target portfolio):\n"
            "  insert-me generate-portfolio --targets-file targets.json --count 40\n\n"
            "Expert/manual (single seed):\n"
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

    # Seed file input (expert/manual seed-driven path)
    run_p.add_argument(
        "--seed-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to seed JSON file. Expert/manual seed-driven path. "
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
            "Optionally writes three machine-readable JSON artifacts to --output:\n"
            "  target_suitability.json    -- overall suitability report\n"
            "  target_inspection.json     -- full per-file candidate inventory\n"
            "  target_strategy_matrix.json -- strategy x file candidate matrix\n\n"
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
    # plan-corpus
    # -----------------------------------------------------------------------
    def _add_planning_args(p: argparse.ArgumentParser) -> None:
        """Shared planning constraint arguments."""
        p.add_argument(
            "--max-per-file",
            type=int,
            default=5,
            metavar="N",
            help="Max cases per source file (default: 5).",
        )
        p.add_argument(
            "--max-per-function",
            type=int,
            default=2,
            metavar="N",
            help="Max cases per function (default: 2).",
        )
        p.add_argument(
            "--max-per-family",
            type=int,
            default=None,
            metavar="N",
            help="Max cases per strategy/CWE family (default: no limit).",
        )
        p.add_argument(
            "--allow-strategies",
            type=str,
            default=None,
            metavar="LIST",
            help="Comma-separated list of strategy names to allow (default: all admitted).",
        )
        p.add_argument(
            "--disallow-strategies",
            type=str,
            default=None,
            metavar="LIST",
            help="Comma-separated list of strategy names to disallow.",
        )
        p.add_argument(
            "--min-candidate-score",
            type=float,
            default=0.0,
            metavar="SCORE",
            help="Minimum candidate suitability score (0.0-1.0, default: 0.0).",
        )
        p.add_argument(
            "--strict-quality",
            action="store_true",
            help="Skip LIMITED strategies; only use VIABLE ones.",
        )

    plan_p = subparsers.add_parser(
        "plan-corpus",
        help="Target-aware corpus planning: inspect target and synthesise seed files.",
        description=(
            "Inspect a local C/C++ source tree, determine which strategies are\n"
            "viable, and synthesise a deterministic corpus plan toward --count cases.\n\n"
            "Outputs (written to --output-dir):\n"
            "  corpus_plan.json    -- allocation plan with per-case details\n"
            "  seeds/*.json        -- one synthesised seed file per planned case\n\n"
            "The plan is deterministic: same source tree + same count + same options\n"
            "=> same plan and same seed files.\n\n"
            "After planning, run the generation pipeline with:\n"
            "  insert-me batch --seed-dir <output-dir>/seeds/ --source PATH\n"
            "or apply the full quality gate with scripts/generate_corpus.py.\n\n"
            "Example:\n"
            "  insert-me plan-corpus --source /path/to/project --count 20\n"
            "  insert-me plan-corpus --source /path/to/project --count 30 \\\n"
            "    --output-dir plan_out/ --max-per-file 4 --strict-quality"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    plan_p.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root of the C/C++ source tree to plan for.",
    )
    plan_p.add_argument(
        "--count",
        type=int,
        required=True,
        metavar="N",
        help="Target number of corpus cases to plan. Actual planned count may be less if the target lacks sufficient diverse candidates.",
    )
    plan_p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Directory to write corpus_plan.json and seeds/. Defaults to ./plan_output/.",
    )
    _add_planning_args(plan_p)
    plan_p.set_defaults(func=_cmd_plan_corpus)

    # -----------------------------------------------------------------------
    # generate-corpus
    # -----------------------------------------------------------------------
    gen_p = subparsers.add_parser(
        "generate-corpus",
        help="Plan + execute full corpus pipeline toward a requested count.",
        description=(
            "Full count-driven corpus generation pipeline:\n"
            "  1. Inspect target (insert-me inspect-target)\n"
            "  2. Synthesise seed plan (insert-me plan-corpus)\n"
            "  3. Run pipeline for every planned seed (insert-me batch)\n"
            "  4. Report acceptance summary (requested / planned / accepted / rejected)\n\n"
            "The system honestly reports if fewer than --count high-quality cases\n"
            "are achievable given the target's candidate diversity.\n\n"
            "Example:\n"
            "  insert-me generate-corpus --source /path/to/project --count 20\n"
            "  insert-me generate-corpus --source /path/to/project --count 30 \\\n"
            "    --output-root corpus_out/ --max-per-file 4"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    gen_p.add_argument(
        "--source",
        type=Path,
        default=None,
        metavar="PATH",
        help="Root of the C/C++ source tree. Required unless --from-plan is given.",
    )
    gen_p.add_argument(
        "--count",
        type=int,
        default=None,
        metavar="N",
        help="Target number of corpus cases. Required unless --from-plan is given.",
    )
    gen_p.add_argument(
        "--from-plan",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Replay an existing corpus plan. PATH may be corpus_plan.json or "
            "the directory containing it. Skips re-planning; re-executes the "
            "same cases in the same order."
        ),
    )
    gen_p.add_argument(
        "--output-root",
        type=Path,
        default=None,
        metavar="PATH",
        help="Root directory for plan and generated bundles (default: ./corpus_out/).",
    )
    gen_p.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM adapter.",
    )
    gen_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only; do not execute the pipeline.",
    )
    gen_p.add_argument(
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Number of worker processes for parallel case execution "
            "(default: use all available CPU cores). "
            "Use --jobs 1 for sequential mode (debug / parity checking)."
        ),
    )
    _add_planning_args(gen_p)
    gen_p.set_defaults(func=_cmd_generate_corpus)

    # -----------------------------------------------------------------------
    # plan-portfolio
    # -----------------------------------------------------------------------
    def _add_portfolio_args(p: argparse.ArgumentParser) -> None:
        """Shared portfolio constraint arguments."""
        p.add_argument(
            "--max-per-target",
            type=int,
            default=20,
            metavar="N",
            help="Hard limit on cases from any single target (default: 20).",
        )
        p.add_argument(
            "--max-per-target-fraction",
            type=float,
            default=0.6,
            metavar="F",
            help="Warn if any target accounts for >F fraction of total cases (default: 0.6).",
        )
        p.add_argument(
            "--max-per-strategy",
            type=int,
            default=20,
            metavar="N",
            help="Hard limit on cases of any single strategy across all targets (default: 20).",
        )
        p.add_argument(
            "--max-per-file",
            type=int,
            default=5,
            metavar="N",
            help="Max cases per source file within each target (default: 5).",
        )
        p.add_argument(
            "--max-per-function",
            type=int,
            default=2,
            metavar="N",
            help="Max cases per function within each target (default: 2).",
        )
        p.add_argument(
            "--strict-quality",
            action="store_true",
            help="Skip LIMITED strategies; only use VIABLE ones.",
        )

    pplan_p = subparsers.add_parser(
        "plan-portfolio",
        help="Multi-target corpus planning: allocate cases across a list of targets.",
        description=(
            "Inspect each target listed in --targets-file, compute effective capacity,\n"
            "allocate the requested global count proportionally, and synthesise seed\n"
            "files for each target.\n\n"
            "Outputs (written to --output-dir):\n"
            "  portfolio_plan.json          -- global allocation plan\n"
            "  targets/<name>/_plan/        -- per-target corpus_plan.json + seeds/\n\n"
            "The plan is deterministic: same targets-file + same count + same options\n"
            "=> same portfolio_plan.json and per-target seed files.\n\n"
            "Example:\n"
            "  insert-me plan-portfolio \\\n"
            "    --targets-file examples/targets/sandbox_targets.json --count 30\n"
            "  insert-me plan-portfolio \\\n"
            "    --targets-file targets.json --count 50 \\\n"
            "    --output-dir portfolio_plan/ --max-per-target 15"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pplan_p.add_argument(
        "--targets-file",
        type=Path,
        required=True,
        metavar="PATH",
        help="Path to targets JSON file (see examples/targets/sandbox_targets.json).",
    )
    pplan_p.add_argument(
        "--count",
        type=int,
        required=True,
        metavar="N",
        help="Global target number of corpus cases.",
    )
    pplan_p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Directory to write portfolio_plan.json and per-target plans (default: ./portfolio_plan/).",
    )
    _add_portfolio_args(pplan_p)
    pplan_p.set_defaults(func=_cmd_plan_portfolio)

    # -----------------------------------------------------------------------
    # generate-portfolio
    # -----------------------------------------------------------------------
    pgen_p = subparsers.add_parser(
        "generate-portfolio",
        help="Plan + execute a multi-target corpus pipeline.",
        description=(
            "Full count-driven multi-target corpus generation:\n"
            "  1. Inspect each target and allocate globally (plan-portfolio)\n"
            "  2. Execute the pipeline for every planned case (batch per target)\n"
            "  3. Write per-target diagnostics + global portfolio artifacts\n\n"
            "Accepts --from-plan to replay an existing portfolio_plan.json without\n"
            "re-planning (re-executes the same cases in the same order).\n\n"
            "Outputs (written to --output-root):\n"
            "  portfolio_plan.json             -- global allocation plan\n"
            "  portfolio_index.json            -- corpus manifest + fingerprints\n"
            "  portfolio_acceptance_summary.json\n"
            "  portfolio_shortfall_report.json\n"
            "  targets/<name>/                 -- per-target corpus artifacts\n\n"
            "Example:\n"
            "  insert-me generate-portfolio \\\n"
            "    --targets-file examples/targets/sandbox_targets.json --count 30\n"
            "  insert-me generate-portfolio --from-plan portfolio_out/portfolio_plan.json\n"
            "    --output-root portfolio_replay/"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pgen_p.add_argument(
        "--targets-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to targets JSON file. Required unless --from-plan is given.",
    )
    pgen_p.add_argument(
        "--count",
        type=int,
        default=None,
        metavar="N",
        help="Global target number of corpus cases. Required unless --from-plan is given.",
    )
    pgen_p.add_argument(
        "--from-plan",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Replay an existing portfolio plan. PATH may be portfolio_plan.json "
            "or the directory containing it. Skips re-planning; re-executes the "
            "same cases in the same order."
        ),
    )
    pgen_p.add_argument(
        "--output-root",
        type=Path,
        default=None,
        metavar="PATH",
        help="Root directory for plan and generated bundles (default: ./portfolio_out/).",
    )
    pgen_p.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM adapter.",
    )
    pgen_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only; do not execute the pipeline.",
    )
    pgen_p.add_argument(
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Number of worker processes for parallel case execution "
            "(default: use all available CPU cores). "
            "Use --jobs 1 for sequential mode (debug / parity checking)."
        ),
    )
    _add_portfolio_args(pgen_p)
    pgen_p.set_defaults(func=_cmd_generate_portfolio)

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

    # Build per-file inventory: {rel_file: {strategy: count, ...}}
    per_file_inventory: dict[str, dict[str, int]] = {}
    for fpath in all_paths:
        rel = str(fpath.relative_to(source_root))
        per_file_inventory[rel] = {}
        for strategy_name, _cwe, pattern_type, _exp in _INSPECT_STRATEGIES:
            per_file_inventory[rel][strategy_name] = counts[pattern_type].get(rel, 0)

    # Per-function analysis via planning layer (best-effort)
    function_candidates: dict[str, list[dict]] = {}
    try:
        from insert_me.planning import TargetInspector
        _ti_result = TargetInspector(source_root).run()
        for strategy_name, s_stats in _ti_result.strategies.items():
            entries = []
            for func_key, count in s_stats.by_function.items():
                if count > 0:
                    entries.append({"function": func_key, "count": count})
            if entries:
                entries.sort(key=lambda x: x["count"], reverse=True)
                function_candidates[strategy_name] = entries
    except Exception:
        pass  # function analysis is best-effort

    return {
        "schema_version": "1.0",
        "source_root": str(source_root.resolve()),
        "file_count": file_count,
        "files": rel_files,
        "candidates_by_strategy": strategies,
        "per_file_inventory": per_file_inventory,
        "function_candidates": function_candidates,
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


def _build_target_strategy_matrix(report: dict) -> dict:
    """
    Build a target_strategy_matrix.json artifact from an inspection report.

    The matrix rows are strategy names; columns are relative file paths.
    Each cell is the candidate count (0 if none).
    """
    strategies = list(report["candidates_by_strategy"].keys())
    files = report["files"]

    rows: dict[str, dict] = {}
    for strat in strategies:
        info = report["candidates_by_strategy"][strat]
        row: dict[str, int] = {}
        for f in files:
            row[f] = info["by_file"].get(f, 0)
        rows[strat] = {
            "cwe": info["cwe"],
            "pattern_type": info["pattern_type"],
            "total": info["total"],
            "suitable_for_planning": not ("note" in info),
            "by_file": row,
        }

    return {
        "schema_version": "1.0",
        "source_root": report["source_root"],
        "file_count": report["file_count"],
        "strategy_count": len(strategies),
        "strategies": rows,
    }


def _build_target_inspection(report: dict) -> dict:
    """
    Build a target_inspection.json artifact from an inspection report.

    Contains the full per-file candidate inventory and function-level signals.
    """
    return {
        "schema_version": "1.0",
        "source_root": report["source_root"],
        "file_count": report["file_count"],
        "files": report["files"],
        "per_file_inventory": report.get("per_file_inventory", {}),
        "function_candidates": report.get("function_candidates", {}),
        "concentration_risk": report["concentration_risk"],
    }


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

        # target_suitability.json — overall suitability report
        suitability_artifact = {
            "schema_version": "1.0",
            "source_root": report["source_root"],
            "file_count": report["file_count"],
            "files": report["files"],
            "candidates_by_strategy": report["candidates_by_strategy"],
            "concentration_risk": report["concentration_risk"],
            "suitability": report["suitability"],
        }
        suitability_path = output_dir / "target_suitability.json"
        suitability_path.write_text(json.dumps(suitability_artifact, indent=2), encoding="utf-8")

        # target_inspection.json — full per-file inventory + function signals
        inspection_artifact = _build_target_inspection(report)
        inspection_path = output_dir / "target_inspection.json"
        inspection_path.write_text(json.dumps(inspection_artifact, indent=2), encoding="utf-8")

        # target_strategy_matrix.json — strategy x file candidate matrix
        matrix_artifact = _build_target_strategy_matrix(report)
        matrix_path = output_dir / "target_strategy_matrix.json"
        matrix_path.write_text(json.dumps(matrix_artifact, indent=2), encoding="utf-8")

        print(f"\n[insert-me] artifacts written to: {output_dir}/")
        print(f"  target_suitability.json     -- overall suitability")
        print(f"  target_inspection.json      -- per-file inventory + function signals")
        print(f"  target_strategy_matrix.json -- strategy x file candidate matrix")

    return 1 if report["suitability"]["blockers"] else 0


def _cmd_plan_corpus(args: argparse.Namespace) -> int:
    from insert_me.planning import CorpusPlanner, PlanConstraints

    source: Path = args.source
    if not source.exists():
        print(f"[insert-me] error: --source not found: {source}", file=sys.stderr)
        return 1
    if not source.is_dir():
        print(f"[insert-me] error: --source must be a directory: {source}", file=sys.stderr)
        return 1

    output_dir: Path = args.output_dir or (Path.cwd() / "corpus_plan")

    def _parse_strategy_list(val: str | None) -> list[str] | None:
        if val is None:
            return None
        return [s.strip() for s in val.split(",") if s.strip()]

    constraints = PlanConstraints(
        max_per_file=args.max_per_file,
        max_per_function=args.max_per_function,
        max_per_family=args.max_per_family,
        allow_strategies=_parse_strategy_list(args.allow_strategies),
        disallow_strategies=_parse_strategy_list(args.disallow_strategies),
        min_candidate_score=args.min_candidate_score,
        strict_quality=args.strict_quality,
    )

    print(f"[insert-me] planning {args.count} cases for {source} ...")
    planner = CorpusPlanner(
        source_root=source,
        requested_count=args.count,
        constraints=constraints,
    )
    plan = planner.plan()

    # Print summary
    print(f"\n  requested : {plan.requested_count}")
    print(f"  planned   : {plan.planned_count}")
    print(f"  projected : {plan.projected_accepted_count} (after quality gate)")
    print()
    if plan.strategy_allocation:
        print("  allocation by strategy:")
        for strat, cnt in sorted(plan.strategy_allocation.items()):
            suit = plan.suitability.get(strat, "")
            print(f"    {strat:<30} {cnt:>4}  [{suit}]")
    print()

    if plan.blockers:
        print("  BLOCKERS:")
        for b in plan.blockers:
            print(f"    - {b}")
        print()

    if plan.warnings:
        print("  warnings:")
        for w in plan.warnings:
            print(f"    - {w}")
        print()

    if plan.planned_count > 0:
        plan.write(output_dir)
        print(f"[insert-me] corpus plan written to: {output_dir / 'corpus_plan.json'}")
        print(f"            seeds written to:       {output_dir / 'seeds'}/")
    else:
        print("[insert-me] no cases planned — nothing written.", file=sys.stderr)

    return 1 if plan.blockers else 0


def _cmd_generate_corpus(args: argparse.Namespace) -> int:
    """Plan + execute (or replay): synthesise a corpus plan then run the batch pipeline."""
    import json as _json
    from insert_me.planning import CorpusPlanner, PlanConstraints
    from insert_me.planning.corpus_planner import CorpusPlan

    dry_run: bool = args.dry_run
    from_plan: Path | None = getattr(args, "from_plan", None)

    # ------------------------------------------------------------------
    # Mode A: Replay from existing plan
    # ------------------------------------------------------------------
    if from_plan is not None:
        return _cmd_generate_corpus_replay(args, from_plan, dry_run)

    # ------------------------------------------------------------------
    # Mode B: Fresh plan + execute
    # ------------------------------------------------------------------
    source: Path | None = args.source
    count: int | None = args.count
    if source is None:
        print("[insert-me] error: --source is required unless --from-plan is given.", file=sys.stderr)
        return 1
    if count is None:
        print("[insert-me] error: --count is required unless --from-plan is given.", file=sys.stderr)
        return 1
    if not source.exists():
        print(f"[insert-me] error: --source not found: {source}", file=sys.stderr)
        return 1
    if not source.is_dir():
        print(f"[insert-me] error: --source must be a directory: {source}", file=sys.stderr)
        return 1

    output_root: Path = args.output_root or (Path.cwd() / "corpus_out")
    plan_dir = output_root / "_plan"

    def _parse_strategy_list_gen(val: str | None) -> list[str] | None:
        if val is None:
            return None
        return [s.strip() for s in val.split(",") if s.strip()]

    constraints = PlanConstraints(
        max_per_file=args.max_per_file,
        max_per_function=args.max_per_function,
        max_per_family=args.max_per_family,
        allow_strategies=_parse_strategy_list_gen(args.allow_strategies),
        disallow_strategies=_parse_strategy_list_gen(args.disallow_strategies),
        min_candidate_score=args.min_candidate_score,
        strict_quality=args.strict_quality,
    )

    # --- Phase 1: Plan ---
    print(f"[insert-me] [1/2] planning {count} cases for {source} ...")
    planner = CorpusPlanner(
        source_root=source,
        requested_count=count,
        constraints=constraints,
    )
    plan = planner.plan()

    print(f"  planned {plan.planned_count}/{plan.requested_count} cases "
          f"(projected accepted: {plan.projected_accepted_count})")

    if plan.blockers:
        for b in plan.blockers:
            print(f"  BLOCKER: {b}", file=sys.stderr)
        return 1

    if plan.planned_count == 0:
        print("[insert-me] no cases planned — nothing to execute.", file=sys.stderr)
        return 1

    plan.write(plan_dir)
    print(f"  plan written to: {plan_dir}")

    plan_file = plan_dir / "corpus_plan.json"
    run_mode = "generate"

    if dry_run:
        print("[insert-me] --dry-run: skipping batch execution.")
        shortfall_cats_dry = _compute_plan_shortfall(plan)
        _write_acceptance_summary(
            output_root, plan, attempted=0, case_outcomes={},
            shortfall_categories=shortfall_cats_dry,
        )
        _write_shortfall_report(
            output_root, plan, attempted=0, case_outcomes={},
            plan_shortfall_cats=shortfall_cats_dry,
        )
        _write_corpus_index(output_root, plan, 0, {}, "dry-run", plan_file)
        return 0

    # --- Phase 2: Execute ---
    case_outcomes = _execute_plan_cases(args, plan, plan_dir, source, output_root)
    return _finish_generate_corpus(output_root, plan, case_outcomes, run_mode, plan_file)


def _cmd_generate_corpus_replay(
    args: argparse.Namespace,
    from_plan: Path,
    dry_run: bool,
) -> int:
    """Replay an existing corpus plan: skip re-planning, re-execute cases."""
    import json as _json
    from insert_me.planning.corpus_planner import CorpusPlan

    # Resolve the plan file
    if from_plan.is_dir():
        plan_file = from_plan / "corpus_plan.json"
    else:
        plan_file = from_plan
    if not plan_file.exists():
        print(f"[insert-me] error: corpus_plan.json not found: {plan_file}", file=sys.stderr)
        return 1

    plan_data = _json.loads(plan_file.read_text(encoding="utf-8"))
    plan = CorpusPlan.from_dict(plan_data)
    plan_dir = plan_file.parent

    # Source: explicit --source overrides plan's source_root (for portability)
    source: Path
    if args.source is not None:
        source = args.source
    else:
        source = Path(plan.source_root)
    if not source.exists() or not source.is_dir():
        print(f"[insert-me] error: source not found or not a directory: {source}", file=sys.stderr)
        print("  Tip: use --source to specify an alternate source root.", file=sys.stderr)
        return 1

    output_root: Path = args.output_root or (Path.cwd() / "corpus_out_replay")

    print(f"[insert-me] [replay] loading plan from: {plan_file}")
    print(f"  {plan.planned_count} cases, requested {plan.requested_count}, source: {source}")

    if dry_run:
        print("[insert-me] --dry-run: plan loaded, skipping execution.")
        shortfall_cats_dry = _compute_plan_shortfall(plan)
        _write_acceptance_summary(
            output_root, plan, attempted=0, case_outcomes={},
            shortfall_categories=shortfall_cats_dry,
        )
        _write_shortfall_report(
            output_root, plan, attempted=0, case_outcomes={},
            plan_shortfall_cats=shortfall_cats_dry,
        )
        _write_corpus_index(output_root, plan, 0, {}, "dry-run-replay", plan_file)
        return 0

    print(f"\n[insert-me] [replay] executing {plan.planned_count} cases ...")
    case_outcomes = _execute_plan_cases(args, plan, plan_dir, source, output_root)
    return _finish_generate_corpus(output_root, plan, case_outcomes, "replay", plan_file)


def _execute_single_case_worker(task: dict) -> tuple[str, dict]:
    """
    Top-level worker function for per-case parallel execution.

    Must be defined at module level (not as a closure or nested function)
    so that it is picklable by the multiprocessing spawn start method used
    on Windows and macOS.

    Accepts a plain dict of picklable primitives; returns (case_id, outcome).
    """
    import json as _json
    from pathlib import Path as _Path
    from insert_me.config import load_config, apply_cli_overrides
    from insert_me.pipeline import run_pipeline

    case_id     = task["case_id"]
    seed_path   = _Path(task["seed_path"])
    source      = _Path(task["source"])
    output_root = _Path(task["output_root"])
    strategy    = task["strategy"]
    target_file = task["target_file"]
    config_path = _Path(task["config_path"]) if task.get("config_path") else None
    no_llm      = bool(task.get("no_llm", False))

    outcome: dict = {
        "strategy":       strategy,
        "target_file":    target_file,
        "classification": "ERROR",
        "error":          None,
    }

    if not seed_path.exists():
        outcome["error"] = f"seed file missing: {seed_path}"
        return case_id, outcome

    try:
        run_cfg = load_config(config_path)
        run_cfg = apply_cli_overrides(
            run_cfg,
            seed_file=seed_path,
            source_path=source,
            output_root=output_root / "cases",
            no_llm=no_llm,
        )
        bundle = run_pipeline(run_cfg, dry_run=False)

        classification = "UNKNOWN"
        if bundle.audit_result.exists():
            ar = _json.loads(bundle.audit_result.read_text(encoding="utf-8"))
            classification = ar.get("classification", "UNKNOWN")
        outcome["classification"] = classification

    except Exception as exc:
        outcome["error"] = str(exc)

    return case_id, outcome


def _execute_plan_cases(
    args: argparse.Namespace,
    plan,
    plan_dir: Path,
    source: Path,
    output_root: Path,
) -> dict:
    """Execute all cases in a plan, returning per-case outcome dict.

    When ``args.jobs == 1`` (or the flag is absent), execution is sequential —
    preserving prior behaviour and making it easy to debug individual cases.

    When ``args.jobs > 1`` (or ``None`` for auto), cases are dispatched to a
    ``ProcessPoolExecutor``.  Results are **collected and printed in canonical
    plan order** (by case_id) regardless of which worker finishes first, so
    artifact content is identical between sequential and parallel runs.

    Determinism guarantees
    ----------------------
    * Planning is always single-threaded; the case list is fixed before any
      worker is spawned.
    * Each case writes to its own ``cases/<run_id>/`` subdirectory derived
      deterministically from its seed + source hash — no path collisions.
    * ``case_outcomes`` is a dict keyed by ``case_id``; aggregation functions
      (``_write_acceptance_summary``, ``_write_corpus_index``) already sort
      their inputs, so counts and fingerprints are execution-order independent.
    """
    raw_jobs: int | None = getattr(args, "jobs", None)
    # None → auto-detect all available CPU cores
    jobs: int = raw_jobs if raw_jobs is not None else (os.cpu_count() or 1)
    n_tasks = len(plan.cases)
    # Cap workers at the number of tasks — no benefit spawning more processes
    effective_jobs = min(max(jobs, 1), max(n_tasks, 1))

    # Build task list in canonical plan order
    config_val = getattr(args, "config", None)
    tasks = [
        {
            "case_id":     case.case_id,
            "seed_path":   str(plan_dir / case.seed_file),
            "source":      str(source),
            "output_root": str(output_root),
            "strategy":    case.strategy,
            "target_file": case.target_file,
            "config_path": str(config_val) if config_val is not None else None,
            "no_llm":      bool(getattr(args, "no_llm", False)),
        }
        for case in plan.cases
    ]

    case_outcomes: dict[str, dict] = {}

    if effective_jobs <= 1:
        # Sequential mode — identical to previous behaviour, preserves print ordering
        for idx, task in enumerate(tasks, 1):
            case_id, outcome = _execute_single_case_worker(task)
            case_outcomes[case_id] = outcome
            classification = outcome["classification"]
            if outcome.get("error"):
                print(
                    f"  [{idx:>3}] ERROR   {case_id}: {outcome['error'][:60]}",
                    file=sys.stderr,
                )
            else:
                status = (
                    "OK  " if classification == "VALID" else
                    "NOOP" if classification == "NOOP" else "FAIL"
                )
                print(f"  [{idx:>3}] {status}  {case_id}  [{classification}]")
    else:
        # Parallel mode — dispatch all tasks, collect in canonical order
        from concurrent.futures import ProcessPoolExecutor, as_completed as _as_completed

        print(
            f"  [parallel] dispatching {n_tasks} case(s) "
            f"across {effective_jobs} worker(s) ..."
        )
        with ProcessPoolExecutor(max_workers=effective_jobs) as executor:
            future_map = {
                executor.submit(_execute_single_case_worker, task): task["case_id"]
                for task in tasks
            }
            completed = 0
            for future in _as_completed(future_map):
                case_id, outcome = future.result()
                case_outcomes[case_id] = outcome
                completed += 1
                milestone = max(1, n_tasks // 4)
                if completed % milestone == 0 or completed == n_tasks:
                    print(f"  [parallel] {completed}/{n_tasks} completed ...")

        # Print results in canonical case order (not completion order)
        for idx, task in enumerate(tasks, 1):
            cid = task["case_id"]
            outcome = case_outcomes[cid]
            classification = outcome["classification"]
            if outcome.get("error"):
                print(
                    f"  [{idx:>3}] ERROR   {cid}: {outcome['error'][:60]}",
                    file=sys.stderr,
                )
            else:
                status = (
                    "OK  " if classification == "VALID" else
                    "NOOP" if classification == "NOOP" else "FAIL"
                )
                print(f"  [{idx:>3}] {status}  {cid}  [{classification}]")

    return case_outcomes


def _finish_generate_corpus(
    output_root: Path,
    plan,
    case_outcomes: dict,
    run_mode: str,
    plan_file: Path,
) -> int:
    """Write all diagnostics artifacts and print summary. Returns exit code."""
    accepted = sum(1 for o in case_outcomes.values() if o.get("classification") == "VALID")
    rejected = sum(1 for o in case_outcomes.values()
                   if o.get("classification") not in ("VALID", "ERROR", "UNKNOWN")
                   and o.get("error") is None)
    errors   = sum(1 for o in case_outcomes.values() if o.get("error") is not None)
    total = len(case_outcomes)

    print(f"\n  requested  : {plan.requested_count}")
    print(f"  planned    : {plan.planned_count}")
    print(f"  executed   : {total}")
    print(f"  accepted   : {accepted}")
    print(f"  rejected   : {rejected}")
    if errors:
        print(f"  errors     : {errors}")
    print(f"\n[insert-me] corpus written to: {output_root}")

    shortfall_cats = _compute_plan_shortfall(plan)
    _write_acceptance_summary(output_root, plan, total, case_outcomes, shortfall_cats)
    _write_generation_diagnostics(output_root, plan, case_outcomes, shortfall_cats)
    _write_shortfall_report(output_root, plan, total, case_outcomes, shortfall_cats)
    _write_corpus_index(output_root, plan, total, case_outcomes, run_mode, plan_file)

    print(f"  acceptance_summary.json    : {output_root / 'acceptance_summary.json'}")
    print(f"  generation_diagnostics.json: {output_root / 'generation_diagnostics.json'}")
    print(f"  shortfall_report.json      : {output_root / 'shortfall_report.json'}")
    print(f"  corpus_index.json          : {output_root / 'corpus_index.json'}")

    return 0 if errors == 0 else 1


def _write_corpus_index(
    output_root: Path,
    plan,
    attempted: int,
    case_outcomes: dict,
    run_mode: str,
    plan_file: Path,
) -> None:
    """
    Write corpus_index.json — machine-readable corpus manifest.

    Captures target identity, plan identity, all counts, per-strategy/file
    breakdowns, artifact locations, and reproducibility metadata.
    """
    import json as _json
    import hashlib

    accepted = sum(
        1 for o in case_outcomes.values()
        if o.get("classification") == "VALID" and not o.get("error")
    )
    rejected = sum(
        1 for o in case_outcomes.values()
        if o.get("classification") not in ("VALID", "ERROR", "UNKNOWN")
        and not o.get("error")
    )
    errors = sum(1 for o in case_outcomes.values() if o.get("error") is not None)

    # Per-strategy breakdown
    per_strategy: dict[str, dict[str, int]] = {}
    for outcome in case_outcomes.values():
        s = outcome.get("strategy", "unknown")
        if s not in per_strategy:
            per_strategy[s] = {"attempted": 0, "accepted": 0, "rejected": 0, "error": 0}
        per_strategy[s]["attempted"] += 1
        cl = outcome.get("classification", "UNKNOWN")
        err = outcome.get("error")
        if err:
            per_strategy[s]["error"] += 1
        elif cl == "VALID":
            per_strategy[s]["accepted"] += 1
        else:
            per_strategy[s]["rejected"] += 1

    # Per-file breakdown
    per_file: dict[str, dict[str, int]] = {}
    for outcome in case_outcomes.values():
        f = outcome.get("target_file", "unknown")
        if f not in per_file:
            per_file[f] = {"attempted": 0, "accepted": 0, "rejected": 0, "error": 0}
        per_file[f]["attempted"] += 1
        cl = outcome.get("classification", "UNKNOWN")
        err = outcome.get("error")
        if err:
            per_file[f]["error"] += 1
        elif cl == "VALID":
            per_file[f]["accepted"] += 1
        else:
            per_file[f]["rejected"] += 1

    # Plan hash (sha256 of corpus_plan.json bytes for reproducibility auditing)
    plan_hash = "unknown"
    if plan_file.exists():
        plan_hash = hashlib.sha256(plan_file.read_bytes()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Fingerprints (Phase 13 — fresh-plan reproducibility)
    # ------------------------------------------------------------------
    import json as _json2

    # plan_fingerprint — sha256 of canonical plan cases (stable, semantic fields only)
    plan_cases_canonical = sorted(
        [
            {
                "case_id":      c.case_id,
                "strategy":     c.strategy,
                "seed_integer": c.seed_integer,
                "target_file":  c.target_file,
                "target_line":  c.target_line,
            }
            for c in plan.cases
        ],
        key=lambda x: x["case_id"],
    )
    plan_fingerprint = hashlib.sha256(
        _json2.dumps(
            {
                "source_hash":         plan.source_hash,
                "requested_count":     plan.requested_count,
                "planned_count":       plan.planned_count,
                "strategy_allocation": plan.strategy_allocation,
                "cases":               plan_cases_canonical,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()[:16]

    # synthesized_seed_fingerprint — sha256 of sorted (seed_integer, file, line) tuples
    seed_coords = sorted(
        (c.seed_integer, c.target_file, c.target_line) for c in plan.cases
    )
    synthesized_seed_fingerprint = hashlib.sha256(
        _json2.dumps(seed_coords).encode()
    ).hexdigest()[:16]

    # acceptance_fingerprint — sha256 of sorted accepted case_ids
    accepted_ids = sorted(
        k for k, v in case_outcomes.items()
        if v.get("classification") == "VALID" and not v.get("error")
    )
    acceptance_fingerprint = hashlib.sha256(
        _json2.dumps(accepted_ids).encode()
    ).hexdigest()[:16]

    replay_cmd = (
        f"insert-me generate-corpus --from-plan {plan_file} "
        f"--output-root {output_root}"
    )

    index = {
        "schema_version": "1.1",
        "run_mode": run_mode,
        "source_root": plan.source_root,
        "source_hash": plan.source_hash,
        "plan_path": str(plan_file),
        "plan_hash": plan_hash,
        "counts": {
            "requested": plan.requested_count,
            "planned": plan.planned_count,
            "attempted": attempted,
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors,
        },
        "fingerprints": {
            "plan_fingerprint":               plan_fingerprint,
            "synthesized_seed_fingerprint":   synthesized_seed_fingerprint,
            "acceptance_fingerprint":         acceptance_fingerprint,
            "adjudicator_mode":               "heuristic",
        },
        "per_strategy": per_strategy,
        "per_file": per_file,
        "artifacts": {
            "corpus_plan": str(plan_file),
            "acceptance_summary": str(output_root / "acceptance_summary.json"),
            "generation_diagnostics": str(output_root / "generation_diagnostics.json"),
            "shortfall_report": str(output_root / "shortfall_report.json"),
            "corpus_index": str(output_root / "corpus_index.json"),
            "cases_dir": str(output_root / "cases"),
        },
        "reproducibility": {
            "deterministic": True,
            "replay_command": replay_cmd,
            "note": (
                "Same source tree + same corpus_plan.json => same outputs. "
                "Use --from-plan to replay this run exactly. "
                "Use check_plan_stability.py to verify fresh-plan stability."
            ),
        },
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "corpus_index.json").write_text(
        _json.dumps(index, indent=2), encoding="utf-8"
    )


def _compute_plan_shortfall(plan) -> dict[str, int]:
    """
    Attribute shortfall between requested_count and planned_count to categories.

    Returns a dict of {category: count}.
    """
    from insert_me.planning.inspector import VIABLE, LIMITED, BLOCKED

    cats: dict[str, int] = {}
    shortfall = plan.requested_count - plan.planned_count
    if shortfall <= 0:
        return cats

    # Attribute shortfall to why strategies are BLOCKED or have limited capacity
    blocked_strategies = [
        s for s, suit in plan.suitability.items() if suit == BLOCKED
    ]
    limited_strategies = [
        s for s, suit in plan.suitability.items() if suit == LIMITED
    ]
    experimental = [
        s for s, suit in plan.suitability.items() if suit == "EXPERIMENTAL"
    ]

    if blocked_strategies:
        cats["strategy_blocked_no_candidates"] = len(blocked_strategies)
    if limited_strategies:
        cats["strategy_limited_few_candidates"] = len(limited_strategies)
    if experimental:
        cats["experimental_strategy_skipped"] = len(experimental)
    if plan.warnings:
        for w in plan.warnings:
            if "diverse" in w.lower() or "max-per-file" in w.lower():
                cats["concentration_limits"] = cats.get("concentration_limits", 0) + 1
            if "insufficient" in w.lower() or "cannot" in w.lower():
                cats["target_too_small"] = cats.get("target_too_small", 0) + 1
    if not cats and shortfall > 0:
        cats["sweep_exhausted"] = shortfall

    return cats


def _write_acceptance_summary(
    output_root: Path,
    plan,
    attempted: int,
    case_outcomes: dict,
    shortfall_categories: dict,
) -> None:
    """Write acceptance_summary.json with full per-strategy and per-file breakdown."""
    import json as _json

    # Per-strategy tally
    by_strategy: dict[str, dict[str, int]] = {}
    for case_id, outcome in case_outcomes.items():
        strat = outcome.get("strategy", "unknown")
        if strat not in by_strategy:
            by_strategy[strat] = {"accepted": 0, "rejected": 0, "error": 0}
        cl = outcome.get("classification", "ERROR")
        err = outcome.get("error")
        if err:
            by_strategy[strat]["error"] += 1
        elif cl == "VALID":
            by_strategy[strat]["accepted"] += 1
        else:
            by_strategy[strat]["rejected"] += 1

    # Per-file tally
    by_file: dict[str, dict[str, int]] = {}
    for case_id, outcome in case_outcomes.items():
        fname = outcome.get("target_file", "unknown")
        if fname not in by_file:
            by_file[fname] = {"accepted": 0, "rejected": 0, "error": 0}
        cl = outcome.get("classification", "ERROR")
        err = outcome.get("error")
        if err:
            by_file[fname]["error"] += 1
        elif cl == "VALID":
            by_file[fname]["accepted"] += 1
        else:
            by_file[fname]["rejected"] += 1

    accepted_count = sum(v["accepted"] for v in by_strategy.values())
    rejected = sum(v["rejected"] for v in by_strategy.values())
    errors   = sum(v["error"] for v in by_strategy.values())
    shortfall_amount = max(0, plan.requested_count - accepted_count)
    requested_count_met = accepted_count >= plan.requested_count

    summary = {
        "schema_version": "1.1",
        "source_root": str((output_root / "..").resolve()),
        "requested_count": plan.requested_count,
        "planned_count": plan.planned_count,
        "projected_accepted_count": plan.projected_accepted_count,
        "attempted_count": attempted,
        "accepted_count": accepted_count,
        "revised_count": 0,
        "rejected_count": rejected,
        "error_count": errors,
        "unresolved_count": 0,
        "requested_count_met": requested_count_met,
        "shortfall_amount": shortfall_amount,
        "honest": shortfall_amount > 0,
        "shortfall_categories": shortfall_categories,
        "shortfall_message": (
            next((w for w in plan.warnings if "Only" in w and "cases planned" in w), None)
        ),
        "strategy_allocation": plan.strategy_allocation,
        "by_strategy": by_strategy,
        "by_file": by_file,
        "plan_path": str(output_root / "_plan" / "corpus_plan.json"),
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "acceptance_summary.json").write_text(
        _json.dumps(summary, indent=2), encoding="utf-8"
    )


def _write_shortfall_report(
    output_root: Path,
    plan,
    attempted: int,
    case_outcomes: dict,
    plan_shortfall_cats: dict,
) -> None:
    """
    Write shortfall_report.json — unified plan + execution shortfall view.

    Provides a single operator-readable record explaining why the requested
    count was or was not achieved, with both plan-level and execution-level
    attribution.
    """
    import json as _json

    accepted = sum(
        1 for o in case_outcomes.values()
        if o.get("classification") == "VALID" and not o.get("error")
    )

    # Execution-level shortfall categories (from actual outcomes)
    exec_cats: dict[str, int] = {}
    for outcome in case_outcomes.values():
        cl = outcome.get("classification", "UNKNOWN")
        err = outcome.get("error")
        if err:
            exec_cats["pipeline_error"] = exec_cats.get("pipeline_error", 0) + 1
        elif cl == "NOOP":
            exec_cats["patcher_noop"] = exec_cats.get("patcher_noop", 0) + 1
        elif cl == "INVALID":
            exec_cats["audit_invalid"] = exec_cats.get("audit_invalid", 0) + 1
        elif cl == "AMBIGUOUS":
            exec_cats["audit_ambiguous"] = exec_cats.get("audit_ambiguous", 0) + 1
        elif cl not in ("VALID", "UNKNOWN"):
            exec_cats["unknown"] = exec_cats.get("unknown", 0) + 1

    plan_shortfall = max(0, plan.requested_count - plan.planned_count)
    exec_shortfall = max(0, plan.planned_count - accepted)
    total_shortfall = max(0, plan.requested_count - accepted)

    # Build human-readable explanation
    parts = []
    if plan_shortfall > 0:
        causes = ", ".join(plan_shortfall_cats.keys()) or "none identified"
        parts.append(
            f"Plan shortfall: {plan_shortfall} case(s) not planned "
            f"(causes: {causes})"
        )
    if exec_shortfall > 0:
        causes = ", ".join(exec_cats.keys()) or "none identified"
        parts.append(
            f"Execution shortfall: {exec_shortfall} case(s) planned but not accepted "
            f"(causes: {causes})"
        )
    if not parts:
        parts.append(
            f"Requested count ({plan.requested_count}) was achieved "
            f"with {accepted} accepted case(s)."
        )
    explanation = ". ".join(parts) + "."

    report = {
        "schema_version": "1.0",
        "requested_count": plan.requested_count,
        "planned_count": plan.planned_count,
        "attempted_count": attempted,
        "accepted_count": accepted,
        "requested_count_met": accepted >= plan.requested_count,
        "shortfall_amount": total_shortfall,
        "plan_shortfall": {
            "amount": plan_shortfall,
            "categories": plan_shortfall_cats,
        },
        "execution_shortfall": {
            "amount": exec_shortfall,
            "categories": exec_cats,
        },
        "shortfall_explanation": explanation,
        "plan_path": str(output_root / "_plan" / "corpus_plan.json"),
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "shortfall_report.json").write_text(
        _json.dumps(report, indent=2), encoding="utf-8"
    )


def _write_generation_diagnostics(
    output_root: Path,
    plan,
    case_outcomes: dict,
    shortfall_categories: dict,
) -> None:
    """
    Write generation_diagnostics.json explaining plan-vs-outcome drift.

    Attributes execution failures to grounded categories:
    - patcher_noop: Seeder found no compatible target (plan/target mismatch)
    - validator_fail: Validator checks failed (bad mutation quality)
    - audit_ambiguous: Audit classified as AMBIGUOUS
    - audit_invalid: Audit classified as INVALID
    - pipeline_error: Exception during pipeline execution
    """
    import json as _json

    # Attribute each non-accepted case to a category
    plan_shortfall = plan.requested_count - plan.planned_count
    exec_shortfall = plan.planned_count - sum(
        1 for o in case_outcomes.values()
        if o.get("classification") == "VALID" and not o.get("error")
    )

    categories: dict[str, list[str]] = {
        "patcher_noop": [],
        "validator_fail": [],
        "audit_ambiguous": [],
        "audit_invalid": [],
        "pipeline_error": [],
        "unknown": [],
    }

    for case_id, outcome in case_outcomes.items():
        cl = outcome.get("classification", "UNKNOWN")
        err = outcome.get("error")
        if err:
            categories["pipeline_error"].append(f"{case_id}: {str(err)[:80]}")
        elif cl == "VALID":
            pass  # accepted — no issue
        elif cl == "NOOP":
            categories["patcher_noop"].append(case_id)
        elif cl == "INVALID":
            categories["audit_invalid"].append(case_id)
        elif cl == "AMBIGUOUS":
            categories["audit_ambiguous"].append(case_id)
        else:
            categories["unknown"].append(f"{case_id}: classification={cl!r}")

    # Summarise strategy suitability for plan shortfall context
    strategy_suitability = {
        s: plan.suitability.get(s, "UNKNOWN")
        for s in plan.strategy_allocation
    }

    diag = {
        "schema_version": "1.0",
        "source_root": str((output_root / "..").resolve()),
        "requested_count": plan.requested_count,
        "planned_count": plan.planned_count,
        "attempted_count": len(case_outcomes),
        "accepted_count": sum(
            1 for o in case_outcomes.values()
            if o.get("classification") == "VALID" and not o.get("error")
        ),
        "plan_shortfall": plan_shortfall,
        "execution_shortfall": max(0, exec_shortfall),
        "plan_shortfall_categories": shortfall_categories,
        "execution_failure_categories": {
            k: {"count": len(v), "cases": v}
            for k, v in categories.items()
            if v
        },
        "strategy_suitability": strategy_suitability,
        "plan_warnings": plan.warnings,
        "plan_blockers": plan.blockers,
    }
    (output_root / "generation_diagnostics.json").write_text(
        _json.dumps(diag, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# plan-portfolio / generate-portfolio helpers
# ---------------------------------------------------------------------------

def _build_portfolio_constraints(args: argparse.Namespace):
    """Build PortfolioConstraints from CLI args."""
    from insert_me.planning.portfolio import PortfolioConstraints
    return PortfolioConstraints(
        max_per_target=args.max_per_target,
        max_per_target_fraction=args.max_per_target_fraction,
        max_per_strategy_global=args.max_per_strategy,
        max_per_file=args.max_per_file,
        max_per_function=args.max_per_function,
        strict_quality=args.strict_quality,
    )


def _cmd_plan_portfolio(args: argparse.Namespace) -> int:
    import json as _json
    from insert_me.planning.portfolio import (
        PortfolioPlanner, load_targets_file,
    )

    targets_file: Path = args.targets_file
    if not targets_file.exists():
        print(f"[insert-me] error: --targets-file not found: {targets_file}", file=sys.stderr)
        return 1

    try:
        targets = load_targets_file(targets_file)
    except (ValueError, KeyError) as exc:
        print(f"[insert-me] error: invalid targets file: {exc}", file=sys.stderr)
        return 1

    if not targets:
        print("[insert-me] error: targets file lists no targets.", file=sys.stderr)
        return 1

    output_dir: Path = args.output_dir or (Path.cwd() / "portfolio_plan")
    constraints = _build_portfolio_constraints(args)

    print(f"[insert-me] planning {args.count} cases across {len(targets)} target(s) ...")
    for t in targets:
        print(f"  target: {t.name}  ->  {t.path}")

    planner = PortfolioPlanner(
        targets=targets,
        requested_count=args.count,
        constraints=constraints,
    )
    portfolio_plan, per_target_plans = planner.plan()

    # Print summary
    print(f"\n  requested  : {portfolio_plan.requested_count}")
    print(f"  planned    : {portfolio_plan.planned_count}")
    print(f"  projected  : {portfolio_plan.projected_accepted_count} (after quality gate)")
    print()
    print("  allocation by target:")
    by_target: dict[str, int] = {}
    for e in portfolio_plan.entries:
        by_target[e.target_name] = by_target.get(e.target_name, 0) + 1
    for name, cnt in sorted(by_target.items()):
        print(f"    {name:<30} {cnt:>4}")
    print()
    print("  allocation by strategy:")
    for strat, cnt in sorted(portfolio_plan.global_strategy_allocation.items()):
        print(f"    {strat:<30} {cnt:>4}")
    print()

    if portfolio_plan.blockers:
        print("  BLOCKERS:")
        for b in portfolio_plan.blockers:
            print(f"    - {b}")
        print()

    if portfolio_plan.warnings:
        print("  warnings:")
        for w in portfolio_plan.warnings:
            print(f"    - {w}")
        print()

    shortfall = portfolio_plan.shortfall
    if shortfall.get("count", 0) > 0:
        print(f"  shortfall: {shortfall['count']} case(s) not planned")
        for cat, cnt in shortfall.get("categories", {}).items():
            print(f"    {cat}: {cnt}")
        print()

    if portfolio_plan.planned_count > 0:
        portfolio_plan.write(output_dir, per_target_plans)
        print(f"[insert-me] portfolio plan written to: {output_dir / 'portfolio_plan.json'}")
        print(f"            per-target plans:          {output_dir / 'targets'}/")
    else:
        print("[insert-me] no cases planned -- nothing written.", file=sys.stderr)

    return 1 if portfolio_plan.blockers else 0


def _cmd_generate_portfolio(args: argparse.Namespace) -> int:
    """Plan + execute (or replay): build a multi-target corpus portfolio."""
    import json as _json
    from insert_me.planning.portfolio import (
        PortfolioPlan, load_targets_file,
    )

    dry_run: bool = args.dry_run
    from_plan: Path | None = getattr(args, "from_plan", None)

    # ------------------------------------------------------------------
    # Mode A: Replay from existing portfolio plan
    # ------------------------------------------------------------------
    if from_plan is not None:
        return _cmd_generate_portfolio_replay(args, from_plan, dry_run)

    # ------------------------------------------------------------------
    # Mode B: Fresh plan + execute
    # ------------------------------------------------------------------
    targets_file: Path | None = args.targets_file
    count: int | None = args.count

    if targets_file is None:
        print("[insert-me] error: --targets-file is required unless --from-plan is given.", file=sys.stderr)
        return 1
    if count is None:
        print("[insert-me] error: --count is required unless --from-plan is given.", file=sys.stderr)
        return 1
    if not targets_file.exists():
        print(f"[insert-me] error: --targets-file not found: {targets_file}", file=sys.stderr)
        return 1

    try:
        targets = load_targets_file(targets_file)
    except (ValueError, KeyError) as exc:
        print(f"[insert-me] error: invalid targets file: {exc}", file=sys.stderr)
        return 1

    if not targets:
        print("[insert-me] error: targets file lists no targets.", file=sys.stderr)
        return 1

    output_root: Path = args.output_root or (Path.cwd() / "portfolio_out")
    plan_dir = output_root / "_plan"
    constraints = _build_portfolio_constraints(args)

    from insert_me.planning.portfolio import PortfolioPlanner

    print(f"[insert-me] [1/2] planning {count} cases across {len(targets)} target(s) ...")
    planner = PortfolioPlanner(
        targets=targets,
        requested_count=count,
        constraints=constraints,
    )
    portfolio_plan, per_target_plans = planner.plan()

    print(f"  planned {portfolio_plan.planned_count}/{portfolio_plan.requested_count} cases "
          f"(projected accepted: {portfolio_plan.projected_accepted_count})")

    if portfolio_plan.blockers:
        for b in portfolio_plan.blockers:
            print(f"  BLOCKER: {b}", file=sys.stderr)
        return 1

    if portfolio_plan.planned_count == 0:
        print("[insert-me] no cases planned -- nothing to execute.", file=sys.stderr)
        return 1

    portfolio_plan.write(plan_dir, per_target_plans)
    print(f"  plan written to: {plan_dir}")

    plan_file = plan_dir / "portfolio_plan.json"

    if dry_run:
        print("[insert-me] --dry-run: skipping execution.")
        _write_portfolio_acceptance_summary(output_root, portfolio_plan, {})
        _write_portfolio_shortfall_report(output_root, portfolio_plan, {})
        _write_portfolio_index(output_root, portfolio_plan, plan_file, {}, "dry-run")
        return 0

    # --- Phase 2: Execute ---
    print(f"\n[insert-me] [2/2] executing {portfolio_plan.planned_count} cases ...")
    all_outcomes = _execute_portfolio_cases(args, portfolio_plan, plan_dir, output_root)
    return _finish_generate_portfolio(output_root, portfolio_plan, all_outcomes, "generate", plan_file)


def _cmd_generate_portfolio_replay(
    args: argparse.Namespace,
    from_plan: Path,
    dry_run: bool,
) -> int:
    """Replay an existing portfolio plan: skip re-planning, re-execute cases."""
    import json as _json
    from insert_me.planning.portfolio import PortfolioPlan

    # Resolve the plan file
    if from_plan.is_dir():
        plan_file = from_plan / "portfolio_plan.json"
    else:
        plan_file = from_plan
    if not plan_file.exists():
        print(f"[insert-me] error: portfolio_plan.json not found: {plan_file}", file=sys.stderr)
        return 1

    plan_data = _json.loads(plan_file.read_text(encoding="utf-8"))
    portfolio_plan = PortfolioPlan.from_dict(plan_data)
    plan_dir = plan_file.parent

    output_root: Path = args.output_root or (Path.cwd() / "portfolio_out_replay")

    print(f"[insert-me] [replay] loading portfolio plan from: {plan_file}")
    print(f"  {portfolio_plan.planned_count} cases, requested {portfolio_plan.requested_count}")

    if dry_run:
        print("[insert-me] --dry-run: plan loaded, skipping execution.")
        _write_portfolio_acceptance_summary(output_root, portfolio_plan, {})
        _write_portfolio_shortfall_report(output_root, portfolio_plan, {})
        _write_portfolio_index(output_root, portfolio_plan, plan_file, {}, "dry-run-replay")
        return 0

    print(f"\n[insert-me] [replay] executing {portfolio_plan.planned_count} cases ...")
    all_outcomes = _execute_portfolio_cases(args, portfolio_plan, plan_dir, output_root)
    return _finish_generate_portfolio(output_root, portfolio_plan, all_outcomes, "replay", plan_file)


def _execute_portfolio_cases(
    args: argparse.Namespace,
    portfolio_plan,
    plan_dir: Path,
    output_root: Path,
) -> dict[str, dict]:
    """
    Execute all cases in a portfolio plan.

    Returns per-case outcomes keyed by case_id.  Also runs _finish_generate_corpus
    for each target so that per-target corpus artifacts are written.
    """
    import json as _json
    from insert_me.planning.corpus_planner import CorpusPlan

    # Group entries by target_name for per-target batch execution
    from collections import defaultdict
    entries_by_target: dict[str, list] = defaultdict(list)
    for entry in portfolio_plan.entries:
        entries_by_target[entry.target_name].append(entry)

    # Build a lightweight CorpusPlan stub per target from the sub-plan files
    all_outcomes: dict[str, dict] = {}

    for ts in portfolio_plan.target_summaries:
        target_name = ts.name
        target_source = Path(ts.path)
        target_entries = entries_by_target.get(target_name, [])

        target_out = output_root / "targets" / target_name
        target_plan_dir = plan_dir / "targets" / target_name / "_plan"
        sub_plan_file = target_plan_dir / "corpus_plan.json"

        print(f"\n  [target: {target_name}] {len(target_entries)} case(s)")

        if not sub_plan_file.exists():
            print(f"  WARNING: sub-plan not found at {sub_plan_file} -- skipping target", file=sys.stderr)
            for entry in target_entries:
                all_outcomes[entry.case_id] = {
                    "strategy": entry.strategy,
                    "target_file": entry.target_file,
                    "target_name": target_name,
                    "classification": "ERROR",
                    "error": f"sub-plan missing: {sub_plan_file}",
                }
            continue

        # Load the per-target CorpusPlan
        try:
            plan_data = _json.loads(sub_plan_file.read_text(encoding="utf-8"))
            corpus_plan = CorpusPlan.from_dict(plan_data)
        except Exception as exc:
            print(f"  WARNING: failed to load sub-plan {sub_plan_file}: {exc}", file=sys.stderr)
            for entry in target_entries:
                all_outcomes[entry.case_id] = {
                    "strategy": entry.strategy,
                    "target_file": entry.target_file,
                    "target_name": target_name,
                    "classification": "ERROR",
                    "error": str(exc),
                }
            continue

        # Execute cases for this target
        case_outcomes = _execute_plan_cases(args, corpus_plan, target_plan_dir, target_source, target_out)

        # Tag outcomes with target_name and merge
        for case_id, outcome in case_outcomes.items():
            outcome["target_name"] = target_name
            all_outcomes[case_id] = outcome

        # Write per-target corpus artifacts
        _finish_generate_corpus(target_out, corpus_plan, case_outcomes, "portfolio", sub_plan_file)

    return all_outcomes


def _finish_generate_portfolio(
    output_root: Path,
    portfolio_plan,
    all_outcomes: dict[str, dict],
    run_mode: str,
    plan_file: Path,
) -> int:
    """Write portfolio-level artifacts and print summary. Returns exit code."""
    accepted = sum(1 for o in all_outcomes.values() if o.get("classification") == "VALID")
    rejected = sum(
        1 for o in all_outcomes.values()
        if o.get("classification") not in ("VALID", "ERROR", "UNKNOWN")
        and not o.get("error")
    )
    errors = sum(1 for o in all_outcomes.values() if o.get("error") is not None)
    total = len(all_outcomes)

    print(f"\n  requested  : {portfolio_plan.requested_count}")
    print(f"  planned    : {portfolio_plan.planned_count}")
    print(f"  executed   : {total}")
    print(f"  accepted   : {accepted}")
    print(f"  rejected   : {rejected}")
    if errors:
        print(f"  errors     : {errors}")
    print(f"\n[insert-me] portfolio written to: {output_root}")

    _write_portfolio_acceptance_summary(output_root, portfolio_plan, all_outcomes)
    _write_portfolio_shortfall_report(output_root, portfolio_plan, all_outcomes)
    _write_portfolio_index(output_root, portfolio_plan, plan_file, all_outcomes, run_mode)

    print(f"  portfolio_acceptance_summary.json : {output_root / 'portfolio_acceptance_summary.json'}")
    print(f"  portfolio_shortfall_report.json   : {output_root / 'portfolio_shortfall_report.json'}")
    print(f"  portfolio_index.json              : {output_root / 'portfolio_index.json'}")

    return 0 if errors == 0 else 1


def _write_portfolio_acceptance_summary(
    output_root: Path,
    portfolio_plan,
    all_outcomes: dict[str, dict],
) -> None:
    """Write portfolio_acceptance_summary.json with per-target and per-strategy breakdowns."""
    import json as _json

    accepted = sum(1 for o in all_outcomes.values() if o.get("classification") == "VALID" and not o.get("error"))
    rejected = sum(
        1 for o in all_outcomes.values()
        if o.get("classification") not in ("VALID", "ERROR", "UNKNOWN") and not o.get("error")
    )
    errors = sum(1 for o in all_outcomes.values() if o.get("error") is not None)

    by_target: dict[str, dict] = {}
    for outcome in all_outcomes.values():
        tname = outcome.get("target_name", "unknown")
        if tname not in by_target:
            by_target[tname] = {"accepted": 0, "rejected": 0, "error": 0}
        if outcome.get("error"):
            by_target[tname]["error"] += 1
        elif outcome.get("classification") == "VALID":
            by_target[tname]["accepted"] += 1
        else:
            by_target[tname]["rejected"] += 1

    by_strategy: dict[str, dict] = {}
    for outcome in all_outcomes.values():
        s = outcome.get("strategy", "unknown")
        if s not in by_strategy:
            by_strategy[s] = {"accepted": 0, "rejected": 0, "error": 0}
        if outcome.get("error"):
            by_strategy[s]["error"] += 1
        elif outcome.get("classification") == "VALID":
            by_strategy[s]["accepted"] += 1
        else:
            by_strategy[s]["rejected"] += 1

    shortfall_amount = max(0, portfolio_plan.requested_count - accepted)

    summary = {
        "schema_version": "1.0",
        "schema": "portfolio_acceptance_summary",
        "portfolio_id": portfolio_plan.portfolio_id,
        "targets_hash": portfolio_plan.targets_hash,
        "requested_count": portfolio_plan.requested_count,
        "planned_count": portfolio_plan.planned_count,
        "projected_accepted_count": portfolio_plan.projected_accepted_count,
        "attempted_count": len(all_outcomes),
        "accepted_count": accepted,
        "rejected_count": rejected,
        "error_count": errors,
        "requested_count_met": accepted >= portfolio_plan.requested_count,
        "shortfall_amount": shortfall_amount,
        "honest": shortfall_amount > 0,
        "shortfall_categories": portfolio_plan.shortfall.get("categories", {}),
        "global_strategy_allocation": portfolio_plan.global_strategy_allocation,
        "by_target": by_target,
        "by_strategy": by_strategy,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "portfolio_acceptance_summary.json").write_text(
        _json.dumps(summary, indent=2), encoding="utf-8"
    )


def _write_portfolio_shortfall_report(
    output_root: Path,
    portfolio_plan,
    all_outcomes: dict[str, dict],
) -> None:
    """Write portfolio_shortfall_report.json with plan + execution shortfall breakdown."""
    import json as _json

    accepted = sum(
        1 for o in all_outcomes.values()
        if o.get("classification") == "VALID" and not o.get("error")
    )
    plan_shortfall = max(0, portfolio_plan.requested_count - portfolio_plan.planned_count)
    exec_shortfall = max(0, portfolio_plan.planned_count - accepted)
    total_shortfall = max(0, portfolio_plan.requested_count - accepted)

    # Execution-level categories
    exec_cats: dict[str, int] = {}
    for outcome in all_outcomes.values():
        cl = outcome.get("classification", "UNKNOWN")
        err = outcome.get("error")
        if err:
            exec_cats["pipeline_error"] = exec_cats.get("pipeline_error", 0) + 1
        elif cl == "NOOP":
            exec_cats["patcher_noop"] = exec_cats.get("patcher_noop", 0) + 1
        elif cl == "INVALID":
            exec_cats["audit_invalid"] = exec_cats.get("audit_invalid", 0) + 1
        elif cl == "AMBIGUOUS":
            exec_cats["audit_ambiguous"] = exec_cats.get("audit_ambiguous", 0) + 1
        elif cl not in ("VALID", "UNKNOWN"):
            exec_cats["unknown"] = exec_cats.get("unknown", 0) + 1

    # Per-target shortfall
    by_target_shortfall: dict[str, dict] = {}
    for ts in portfolio_plan.target_summaries:
        tname = ts.name
        t_outcomes = {k: v for k, v in all_outcomes.items() if v.get("target_name") == tname}
        t_accepted = sum(1 for o in t_outcomes.values() if o.get("classification") == "VALID" and not o.get("error"))
        by_target_shortfall[tname] = {
            "allocated": ts.allocated_count,
            "planned": ts.planned_count,
            "accepted": t_accepted,
            "shortfall": max(0, ts.allocated_count - t_accepted),
        }

    plan_cats = portfolio_plan.shortfall.get("categories", {})
    parts = []
    if plan_shortfall > 0:
        causes = ", ".join(plan_cats.keys()) or "none identified"
        parts.append(
            f"Plan shortfall: {plan_shortfall} case(s) not planned (causes: {causes})"
        )
    if exec_shortfall > 0:
        causes = ", ".join(exec_cats.keys()) or "none identified"
        parts.append(
            f"Execution shortfall: {exec_shortfall} case(s) planned but not accepted (causes: {causes})"
        )
    if not parts:
        parts.append(
            f"Requested count ({portfolio_plan.requested_count}) was achieved "
            f"with {accepted} accepted case(s)."
        )
    explanation = ". ".join(parts) + "."

    report = {
        "schema_version": "1.0",
        "schema": "portfolio_shortfall_report",
        "portfolio_id": portfolio_plan.portfolio_id,
        "requested_count": portfolio_plan.requested_count,
        "planned_count": portfolio_plan.planned_count,
        "attempted_count": len(all_outcomes),
        "accepted_count": accepted,
        "requested_count_met": accepted >= portfolio_plan.requested_count,
        "shortfall_amount": total_shortfall,
        "plan_shortfall": {
            "amount": plan_shortfall,
            "categories": plan_cats,
        },
        "execution_shortfall": {
            "amount": exec_shortfall,
            "categories": exec_cats,
        },
        "by_target_shortfall": by_target_shortfall,
        "shortfall_explanation": explanation,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "portfolio_shortfall_report.json").write_text(
        _json.dumps(report, indent=2), encoding="utf-8"
    )


def _write_portfolio_index(
    output_root: Path,
    portfolio_plan,
    plan_file: Path,
    all_outcomes: dict[str, dict],
    run_mode: str,
) -> None:
    """Write portfolio_index.json — machine-readable portfolio manifest."""
    import json as _json
    import hashlib

    accepted = sum(
        1 for o in all_outcomes.values()
        if o.get("classification") == "VALID" and not o.get("error")
    )
    rejected = sum(
        1 for o in all_outcomes.values()
        if o.get("classification") not in ("VALID", "ERROR", "UNKNOWN") and not o.get("error")
    )
    errors = sum(1 for o in all_outcomes.values() if o.get("error") is not None)

    # Portfolio fingerprint (from plan; stable even across replay runs)
    portfolio_fingerprint = portfolio_plan.fingerprint

    # Acceptance fingerprint (post-execution)
    accepted_ids = sorted(
        k for k, v in all_outcomes.items()
        if v.get("classification") == "VALID" and not v.get("error")
    )
    acceptance_fingerprint = hashlib.sha256(
        _json.dumps(accepted_ids).encode()
    ).hexdigest()[:16]

    # Per-target summary
    per_target: dict[str, dict] = {}
    for ts in portfolio_plan.target_summaries:
        tname = ts.name
        t_outcomes = {k: v for k, v in all_outcomes.items() if v.get("target_name") == tname}
        t_accepted = sum(1 for o in t_outcomes.values() if o.get("classification") == "VALID" and not o.get("error"))
        per_target[tname] = {
            "path": ts.path,
            "allocated_count": ts.allocated_count,
            "planned_count": ts.planned_count,
            "attempted_count": len(t_outcomes),
            "accepted_count": t_accepted,
            "corpus_index": str(
                output_root / "targets" / tname / "corpus_index.json"
            ),
        }

    # Per-strategy summary
    per_strategy: dict[str, dict] = {}
    for outcome in all_outcomes.values():
        s = outcome.get("strategy", "unknown")
        if s not in per_strategy:
            per_strategy[s] = {"attempted": 0, "accepted": 0}
        per_strategy[s]["attempted"] += 1
        if outcome.get("classification") == "VALID" and not outcome.get("error"):
            per_strategy[s]["accepted"] += 1

    replay_cmd = (
        f"insert-me generate-portfolio --from-plan {plan_file} "
        f"--output-root {output_root}"
    )

    index = {
        "schema_version": "1.0",
        "schema": "portfolio_index",
        "run_mode": run_mode,
        "portfolio_id": portfolio_plan.portfolio_id,
        "targets_hash": portfolio_plan.targets_hash,
        "counts": {
            "requested": portfolio_plan.requested_count,
            "planned": portfolio_plan.planned_count,
            "attempted": len(all_outcomes),
            "accepted": accepted,
            "rejected": rejected,
            "errors": errors,
        },
        "fingerprints": {
            "portfolio_fingerprint": portfolio_fingerprint,
            "acceptance_fingerprint": acceptance_fingerprint,
        },
        "per_target": per_target,
        "per_strategy": per_strategy,
        "artifacts": {
            "portfolio_plan": str(plan_file),
            "portfolio_acceptance_summary": str(output_root / "portfolio_acceptance_summary.json"),
            "portfolio_shortfall_report": str(output_root / "portfolio_shortfall_report.json"),
            "portfolio_index": str(output_root / "portfolio_index.json"),
            "targets_dir": str(output_root / "targets"),
        },
        "reproducibility": {
            "deterministic": True,
            "replay_command": replay_cmd,
            "note": (
                "Same targets-file + same count + same constraints => same portfolio_plan.json. "
                "Use --from-plan to replay this run exactly."
            ),
        },
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "portfolio_index.json").write_text(
        _json.dumps(index, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
