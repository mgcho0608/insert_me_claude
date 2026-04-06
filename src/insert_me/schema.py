"""
Schema loading and JSON validation for insert_me artifacts.

All machine-readable artifacts are validated against versioned JSON schemas
bundled in the package under the schemas/ directory at the repository root.

Naming conventions
------------------
Core pipeline artifacts (four new schemas, .schema.json suffix):
    seed.schema.json            Input seed/case definition
    patch_plan.schema.json      Seeder output (planned transformations)
    validation_result.schema.json   Validator output
    audit_result.schema.json    Auditor classification (VALID/NOOP/AMBIGUOUS/INVALID)

Legacy output artifacts (.json suffix, kept for backwards compatibility):
    vuln_spec.json              Ground truth annotation (Auditor structural output)
    audit_record.json           Provenance record (Auditor run record)

Use the SCHEMA_* constants as keys — never hardcode schema names in call sites.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Bundled schemas directory.
# Resolves to: <repo_root>/schemas/  (two parents up from src/insert_me/)
_SCHEMAS_DIR = Path(__file__).parent.parent.parent / "schemas"


# ---------------------------------------------------------------------------
# Schema name constants
# ---------------------------------------------------------------------------

# Core pipeline artifact schemas (introduced in step 2)
SCHEMA_SEED = "seed"
SCHEMA_PATCH_PLAN = "patch_plan"
SCHEMA_VALIDATION_RESULT = "validation_result"
SCHEMA_AUDIT_RESULT = "audit_result"

# Legacy output artifact schemas (introduced in step 1)
SCHEMA_GROUND_TRUTH = "vuln_spec"
SCHEMA_AUDIT_RECORD = "audit_record"
SCHEMA_LABELS = "labels"

# Ordered resolution priority: .schema.json tried first, then .json
_SUFFIXES = [".schema.json", ".json"]


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def schema_path(name: str) -> Path:
    """
    Resolve the filesystem path for a schema by name.

    Tries ``<name>.schema.json`` first, then ``<name>.json``.

    Parameters
    ----------
    name:
        Schema name, one of the SCHEMA_* constants.

    Returns
    -------
    Path
        Resolved path to the schema file.

    Raises
    ------
    FileNotFoundError
        If neither candidate path exists.
    """
    for suffix in _SUFFIXES:
        candidate = _SCHEMAS_DIR / f"{name}{suffix}"
        if candidate.exists():
            return candidate
    tried = [str(_SCHEMAS_DIR / f"{name}{s}") for s in _SUFFIXES]
    raise FileNotFoundError(
        f"Schema '{name}' not found. Tried:\n" + "\n".join(f"  {p}" for p in tried)
    )


def load_schema(name: str, version: str = "1.0") -> dict[str, Any]:
    """
    Load a bundled JSON schema by name.

    Parameters
    ----------
    name:
        Schema name, one of the SCHEMA_* constants.
    version:
        Schema version string. Currently informational only — versioned schema
        files (e.g. ``seed_v2.0.schema.json``) are a future extension.

    Returns
    -------
    dict
        Parsed JSON schema object.

    Raises
    ------
    FileNotFoundError
        If no schema file exists for the requested name.
    json.JSONDecodeError
        If the schema file exists but is not valid JSON.
    """
    path = schema_path(name)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def list_schemas() -> list[str]:
    """
    Return the names of all schema files present in the schemas directory.

    Returns
    -------
    list[str]
        Sorted list of schema base names (without suffix), e.g. ``['audit_record',
        'audit_result', 'patch_plan', ...]``.
    """
    names: set[str] = set()
    if not _SCHEMAS_DIR.exists():
        return []
    for suffix in _SUFFIXES:
        for p in _SCHEMAS_DIR.glob(f"*{suffix}"):
            stem = p.name[: -len(suffix)]
            names.add(stem)
    return sorted(names)


# ---------------------------------------------------------------------------
# Artifact validation
# ---------------------------------------------------------------------------

def validate_artifact(artifact: dict[str, Any], schema_name: str) -> None:
    """
    Validate an artifact dict against the named schema.

    Parameters
    ----------
    artifact:
        Parsed artifact dict (e.g. from ``json.load``).
    schema_name:
        One of the SCHEMA_* constants.

    Raises
    ------
    jsonschema.ValidationError
        If the artifact does not conform to the schema.
    FileNotFoundError
        If the schema file cannot be found.
    ImportError
        If ``jsonschema`` is not installed.
    """
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "jsonschema is required for artifact validation. "
            "Install it with: pip install jsonschema"
        ) from exc

    version = artifact.get("schema_version", "1.0")
    schema = load_schema(schema_name, version=version)
    jsonschema.validate(instance=artifact, schema=schema)


def validate_artifact_file(path: Path, schema_name: str) -> None:
    """
    Load a JSON file and validate it against the named schema.

    Parameters
    ----------
    path:
        Path to the JSON artifact file.
    schema_name:
        One of the SCHEMA_* constants.

    Raises
    ------
    FileNotFoundError
        If the artifact file does not exist.
    json.JSONDecodeError
        If the artifact file is not valid JSON.
    jsonschema.ValidationError
        If the artifact does not conform to the schema.
    """
    if not path.exists():
        raise FileNotFoundError(f"Artifact file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        artifact = json.load(fh)
    validate_artifact(artifact, schema_name)


# ---------------------------------------------------------------------------
# Bundle validation
# ---------------------------------------------------------------------------

# Mapping: artifact filename → schema name for bundle-level validation.
# All five core artifacts are produced by the dry-run pipeline.
# validate_bundle silently skips any artifact that is absent, so
# bundles from older pipeline versions remain compatible.
_BUNDLE_ARTIFACT_MAP: dict[str, str] = {
    "patch_plan.json": SCHEMA_PATCH_PLAN,
    "validation_result.json": SCHEMA_VALIDATION_RESULT,
    "audit_result.json": SCHEMA_AUDIT_RESULT,
    "ground_truth.json": SCHEMA_GROUND_TRUTH,
    "audit.json": SCHEMA_AUDIT_RECORD,
}

# labels.json is present only when the LLM adapter ran with write_labels=true.
_BUNDLE_OPTIONAL_ARTIFACT_MAP: dict[str, str] = {
    "labels.json": SCHEMA_LABELS,
}


def validate_bundle(bundle_dir: Path, *, strict: bool = False) -> list[str]:
    """
    Validate all recognised artifacts in an output bundle directory.

    Strict mode
    -----------
    If ``strict=True`` OR if ``audit.json`` is present in the bundle
    (auto-detection: a complete insert_me bundle always has audit.json),
    all five core artifacts are required to be present. Missing core
    artifacts are reported as errors.

    Without strict mode (empty or foreign directory), only present artifacts
    are validated; absent ones are silently skipped.

    Parameters
    ----------
    bundle_dir:
        Path to the output bundle directory (the run-id subdirectory).
    strict:
        Force strict mode regardless of bundle contents.

    Returns
    -------
    list[str]
        List of error strings. Empty list means all present artifacts
        are valid (and none are missing, in strict mode).
    """
    errors: list[str] = []

    if not bundle_dir.exists():
        return [f"Bundle directory not found: {bundle_dir}"]
    if not bundle_dir.is_dir():
        return [f"Bundle path is not a directory: {bundle_dir}"]

    # Auto-detect: if audit.json is present, treat as a complete insert_me bundle.
    # Complete bundles must have all five core artifacts.
    is_insert_me_bundle = (bundle_dir / "audit.json").exists()

    # Strict mode only applies when at least one core artifact is present.
    # This avoids false errors on empty or foreign directories.
    any_core_present = any(
        (bundle_dir / fn).exists() for fn in _BUNDLE_ARTIFACT_MAP
    )
    effective_strict = (strict or is_insert_me_bundle) and any_core_present

    # Core artifacts
    for filename, schema_name in _BUNDLE_ARTIFACT_MAP.items():
        artifact_path = bundle_dir / filename
        if not artifact_path.exists():
            if effective_strict:
                errors.append(
                    f"{filename}: missing from bundle "
                    "(expected in a complete insert_me output bundle)"
                )
            continue
        _validate_and_collect(artifact_path, schema_name, errors)

    # Optional artifacts — validate if present; absence is never an error
    for filename, schema_name in _BUNDLE_OPTIONAL_ARTIFACT_MAP.items():
        artifact_path = bundle_dir / filename
        if artifact_path.exists():
            _validate_and_collect(artifact_path, schema_name, errors)

    return errors


def _validate_and_collect(path: Path, schema_name: str, errors: list[str]) -> None:
    """Validate one artifact file and append any error to the errors list."""
    try:
        validate_artifact_file(path, schema_name)
    except FileNotFoundError as exc:
        errors.append(f"{path.name}: {exc}")
    except json.JSONDecodeError as exc:
        errors.append(f"{path.name}: JSON parse error — {exc}")
    except Exception as exc:  # jsonschema.ValidationError and others
        errors.append(f"{path.name}: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Example loading (for tests and documentation)
# ---------------------------------------------------------------------------

_EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


def load_example(relative_path: str) -> dict[str, Any]:
    """
    Load a JSON example file from the examples/ directory.

    Parameters
    ----------
    relative_path:
        Path relative to the examples/ directory,
        e.g. ``"seeds/cwe122_heap_overflow.json"``.

    Returns
    -------
    dict
        Parsed example artifact.

    Raises
    ------
    FileNotFoundError
        If the example file does not exist.
    """
    path = _EXAMPLES_DIR / relative_path
    if not path.exists():
        raise FileNotFoundError(f"Example file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
