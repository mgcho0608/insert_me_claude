#!/usr/bin/env python3
"""
inspect_target.py -- preflight suitability check for a local C/C++ source tree.

Thin wrapper around ``insert-me inspect-target``.  Useful as a standalone
script when the insert_me package is installed in editable mode.

Usage
-----
    python scripts/inspect_target.py --source /path/to/local/project
    python scripts/inspect_target.py --source /path/to/project --output inspect_out/

Output
------
Human-readable summary printed to stdout.
If --output is given, ``target_suitability.json`` is written to that directory.

Exit codes
----------
  0 -- target is usable (no blockers); warnings may be present
  1 -- target has blockers (no usable candidate sites or no source files found)
  2 -- bad arguments (--source not found or not a directory)
"""

import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="inspect_target.py",
        description="Preflight suitability check for a C/C++ source tree.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/inspect_target.py --source /path/to/my/project\n"
            "  python scripts/inspect_target.py --source /path/to/project "
            "--output inspect_out/\n\n"
            "This script is a thin wrapper around:\n"
            "  insert-me inspect-target --source PATH [--output PATH]"
        ),
    )
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Root of the C/C++ source tree to inspect.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="If provided, write target_suitability.json to this directory.",
    )
    args = parser.parse_args()

    # Validate early to give a clean error message
    if not args.source.exists():
        print(f"[inspect_target] error: --source not found: {args.source}", file=sys.stderr)
        sys.exit(2)
    if not args.source.is_dir():
        print(
            f"[inspect_target] error: --source must be a directory: {args.source}",
            file=sys.stderr,
        )
        sys.exit(2)

    # Delegate to the CLI implementation
    try:
        from insert_me.cli import _inspect_source_tree, _format_inspection_report
    except ImportError:
        print(
            "[inspect_target] error: insert_me package not installed. "
            "Run: pip install -e . from the repository root.",
            file=sys.stderr,
        )
        sys.exit(2)

    import json

    report = _inspect_source_tree(args.source)
    print(_format_inspection_report(report))

    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
        out_path = args.output / "target_suitability.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[inspect_target] suitability report written to: {out_path}")

    sys.exit(1 if report["suitability"]["blockers"] else 0)


if __name__ == "__main__":
    main()
