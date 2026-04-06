"""
CLI entrypoint for insert_me.

Commands
--------
run             Run the vulnerability insertion pipeline for a given seed file + source tree.
validate-bundle Validate the schema conformance of an existing output bundle.
audit           Pretty-print the audit record from an output bundle.

Canonical interface (primary)
------------------------------
    insert-me run --seed-file PATH --source PATH [--output PATH] [--config PATH] [--no-llm] [--dry-run]

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
            "Expand a seed definition against a C/C++ source tree, produce a\n"
            "dry-run output bundle with all expected JSON artifacts.\n\n"
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


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
