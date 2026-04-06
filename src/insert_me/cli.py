"""
CLI entrypoint for insert_me.

Commands
--------
run             Run the full pipeline for a given seed + spec + source tree.
validate-bundle Validate the schema conformance of an existing output bundle.
audit           Pretty-print the audit record from an output bundle.

Usage examples
--------------
    insert-me run --seed 42 --spec specs/cwe-122.toml --source /path/to/project
    insert-me run --seed 42 --spec specs/cwe-122.toml --source . --no-llm
    insert-me validate-bundle output/abc123/
    insert-me audit output/abc123/audit.json
"""

import argparse
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="insert-me",
        description="Deterministic seeded vulnerability generation for C/C++.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # --- run ---
    run_p = subparsers.add_parser(
        "run",
        help="Run the full vulnerability insertion pipeline.",
        description=(
            "Expand a seed against a vulnerability spec and a C/C++ source tree, "
            "produce a bad/good pair, ground truth, and audit record."
        ),
    )
    run_p.add_argument(
        "--seed",
        type=int,
        required=True,
        metavar="INT",
        help="Deterministic seed integer.",
    )
    run_p.add_argument(
        "--spec",
        type=Path,
        required=True,
        metavar="PATH",
        help="Path to vulnerability spec TOML file.",
    )
    run_p.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root of the C/C++ source tree to mutate.",
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
        help="Load config and spec, print resolved settings, then exit without running.",
    )
    run_p.set_defaults(func=_cmd_run)

    # --- validate-bundle ---
    vb_p = subparsers.add_parser(
        "validate-bundle",
        help="Validate schema conformance of an output bundle directory.",
    )
    vb_p.add_argument(
        "bundle",
        type=Path,
        metavar="BUNDLE_DIR",
        help="Path to the output bundle directory.",
    )
    vb_p.set_defaults(func=_cmd_validate_bundle)

    # --- audit ---
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
    # TODO(phase2): load config
    # TODO(phase2): load and validate spec
    # TODO(phase3): instantiate Seeder and run
    # TODO(phase4): instantiate Patcher and run
    # TODO(phase5): instantiate Validator and run
    # TODO(phase6): instantiate Auditor and run
    # TODO(phase7): optionally invoke LLM adapter for enrichment
    print("[insert-me] 'run' command is not yet implemented.")
    print(f"  seed   = {args.seed}")
    print(f"  spec   = {args.spec}")
    print(f"  source = {args.source}")
    print(f"  no-llm = {args.no_llm}")
    print(f"  dry-run = {args.dry_run}")
    return 0


def _cmd_validate_bundle(args: argparse.Namespace) -> int:
    # TODO(phase6): load bundle, validate ground_truth.json and audit.json against schemas
    print(f"[insert-me] 'validate-bundle' not yet implemented. Bundle: {args.bundle}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    # TODO(phase6): load and pretty-print audit.json
    print(f"[insert-me] 'audit' not yet implemented. File: {args.audit_file}")
    return 0


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
