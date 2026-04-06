"""
Normalized detector report loading and validation.

insert_me uses a single normalized JSON format for detector reports in Phase 7A.
Tools must convert their native output to this format before passing to the
Evaluator. This keeps the evaluation logic simple and vendor-independent.

Schema: schemas/detector_report.schema.json

Normalized format summary
--------------------------
{
  "schema_version": "1.0",
  "tool": "cppcheck",
  "tool_version": "2.10",          # optional
  "generated_at": "2026-04-06...", # optional
  "source_root": "/path/to/src",   # optional; used for display only
  "findings": [
    {
      "finding_id": "f001",         # optional
      "file": "foo.c",              # relative path (or basename)
      "line": 42,                   # optional
      "cwe_id": "CWE-416",          # optional; pattern "CWE-\\d+"
      "severity": "error",          # optional
      "message": "...",             # optional; used for semantic matching
      "rule_id": "memleak"          # optional; tool-specific rule identifier
    }
  ]
}

Phase 7B note: a thin import/converter layer for native vendor formats
(cppcheck XML, Coverity JSON, etc.) is deferred and will live here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_detector_report(path: Path) -> dict[str, Any]:
    """
    Load a normalized detector report from a JSON file.

    Parameters
    ----------
    path:
        Path to the detector report JSON file.

    Returns
    -------
    dict
        Parsed report. Schema-validity is NOT checked here; call
        :func:`validate_detector_report` separately when needed.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    if not path.exists():
        raise FileNotFoundError(f"Detector report not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate_detector_report(report: dict[str, Any]) -> None:
    """
    Schema-validate a detector report dict.

    Parameters
    ----------
    report:
        Parsed detector report dict.

    Raises
    ------
    jsonschema.ValidationError
        If the report does not conform to detector_report.schema.json.
    """
    from insert_me.schema import validate_artifact, SCHEMA_DETECTOR_REPORT
    validate_artifact(report, SCHEMA_DETECTOR_REPORT)
