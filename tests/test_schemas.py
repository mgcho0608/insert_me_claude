"""
Schema loading and validation tests for insert_me.

Coverage
--------
- All schema files are present and parse as valid JSON.
- load_schema() resolves both .schema.json and .json naming conventions.
- list_schemas() returns the expected set.
- validate_artifact() passes on all bundled example files.
- validate_artifact() raises on deliberately invalid inputs.
- validate_artifact_file() convenience wrapper works correctly.
- load_example() loads example files correctly.
- validate_bundle() handles missing, valid, and invalid bundle directories.
"""

from __future__ import annotations

import json
import copy
import pytest
from pathlib import Path

from insert_me.schema import (
    SCHEMA_SEED,
    SCHEMA_PATCH_PLAN,
    SCHEMA_VALIDATION_RESULT,
    SCHEMA_AUDIT_RESULT,
    SCHEMA_GROUND_TRUTH,
    SCHEMA_AUDIT_RECORD,
    load_schema,
    schema_path,
    list_schemas,
    validate_artifact,
    validate_artifact_file,
    validate_bundle,
    load_example,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas"
EXAMPLES_DIR = REPO_ROOT / "examples"


# ---------------------------------------------------------------------------
# Schema file presence and JSON validity
# ---------------------------------------------------------------------------

EXPECTED_SCHEMAS = [
    "seed",
    "patch_plan",
    "validation_result",
    "audit_result",
    "vuln_spec",
    "audit_record",
]


@pytest.mark.parametrize("name", EXPECTED_SCHEMAS)
def test_schema_file_exists(name):
    """Every expected schema file must exist on disk."""
    path = schema_path(name)
    assert path.exists(), f"Schema file not found for '{name}'"


@pytest.mark.parametrize("name", EXPECTED_SCHEMAS)
def test_schema_file_is_valid_json(name):
    """Every schema file must parse as valid JSON."""
    path = schema_path(name)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, dict)
    assert "$schema" in data or "type" in data, "Schema should have $schema or type"


@pytest.mark.parametrize("name", EXPECTED_SCHEMAS)
def test_load_schema_returns_dict(name):
    """load_schema must return a non-empty dict for every registered schema."""
    schema = load_schema(name)
    assert isinstance(schema, dict)
    assert len(schema) > 0


def test_load_schema_not_found_raises():
    """load_schema must raise FileNotFoundError for unknown schema names."""
    with pytest.raises(FileNotFoundError):
        load_schema("this_schema_does_not_exist")


def test_list_schemas_contains_expected():
    """list_schemas must include all expected schema names."""
    found = list_schemas()
    for name in EXPECTED_SCHEMAS:
        assert name in found, f"'{name}' missing from list_schemas()"


def test_list_schemas_is_sorted():
    """list_schemas must return a sorted list."""
    found = list_schemas()
    assert found == sorted(found)


# ---------------------------------------------------------------------------
# Example loading
# ---------------------------------------------------------------------------

SEED_EXAMPLES = [
    "seeds/cwe122_heap_overflow.json",
    "seeds/cwe416_use_after_free.json",
    "seeds/cwe190_integer_overflow.json",
]

OUTPUT_EXAMPLES = [
    "expected_outputs/patch_plan_example.json",
    "expected_outputs/validation_result_pass.json",
    "expected_outputs/validation_result_fail.json",
    "expected_outputs/audit_result_valid.json",
    "expected_outputs/audit_result_ambiguous.json",
]


@pytest.mark.parametrize("rel_path", SEED_EXAMPLES + OUTPUT_EXAMPLES)
def test_load_example_succeeds(rel_path):
    """load_example must return a dict for every bundled example file."""
    data = load_example(rel_path)
    assert isinstance(data, dict)
    assert "schema_version" in data


def test_load_example_not_found_raises():
    """load_example must raise FileNotFoundError for non-existent examples."""
    with pytest.raises(FileNotFoundError):
        load_example("seeds/this_does_not_exist.json")


# ---------------------------------------------------------------------------
# Seed schema — validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_path", SEED_EXAMPLES)
def test_seed_example_passes_validation(rel_path):
    """All bundled seed examples must pass the seed schema."""
    artifact = load_example(rel_path)
    validate_artifact(artifact, SCHEMA_SEED)  # must not raise


def test_seed_missing_required_field_fails():
    """A seed missing 'cwe_id' must fail validation."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    del bad["cwe_id"]
    with pytest.raises(Exception):  # jsonschema.ValidationError
        validate_artifact(bad, SCHEMA_SEED)


def test_seed_invalid_cwe_pattern_fails():
    """A seed with a malformed CWE ID must fail validation."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    bad["cwe_id"] = "122"  # missing "CWE-" prefix
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_SEED)


def test_seed_invalid_pattern_type_fails():
    """A seed with an unrecognised pattern_type must fail validation."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    bad["target_pattern"]["pattern_type"] = "not_a_real_pattern"
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_SEED)


def test_seed_invalid_difficulty_fails():
    """A seed with an unrecognised difficulty value must fail validation."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    bad["metadata"]["difficulty"] = "impossible"
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_SEED)


def test_seed_unknown_top_level_field_fails():
    """A seed with an extra unknown top-level field must fail (additionalProperties: false)."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    bad["unknown_field"] = "surprise"
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_SEED)


# ---------------------------------------------------------------------------
# Patch plan schema — validation
# ---------------------------------------------------------------------------

def test_patch_plan_example_passes_validation():
    """Bundled patch plan example must pass the patch_plan schema."""
    artifact = load_example("expected_outputs/patch_plan_example.json")
    validate_artifact(artifact, SCHEMA_PATCH_PLAN)


def test_patch_plan_invalid_status_fails():
    """A patch plan with an unrecognised status must fail validation."""
    artifact = load_example("expected_outputs/patch_plan_example.json")
    bad = copy.deepcopy(artifact)
    bad["status"] = "RUNNING"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_PATCH_PLAN)


def test_patch_plan_missing_targets_fails():
    """A patch plan missing the 'targets' field must fail validation."""
    artifact = load_example("expected_outputs/patch_plan_example.json")
    bad = copy.deepcopy(artifact)
    del bad["targets"]
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_PATCH_PLAN)


def test_patch_plan_target_line_zero_fails():
    """A patch plan target with line=0 (< minimum of 1) must fail validation."""
    artifact = load_example("expected_outputs/patch_plan_example.json")
    bad = copy.deepcopy(artifact)
    bad["targets"][0]["line"] = 0
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_PATCH_PLAN)


# ---------------------------------------------------------------------------
# Validation result schema — validation
# ---------------------------------------------------------------------------

def test_validation_result_pass_example_passes():
    """Bundled validation_result_pass example must pass the validation_result schema."""
    artifact = load_example("expected_outputs/validation_result_pass.json")
    validate_artifact(artifact, SCHEMA_VALIDATION_RESULT)


def test_validation_result_fail_example_passes():
    """Bundled validation_result_fail example must also be schema-valid (the failure is in overall, not the schema)."""
    artifact = load_example("expected_outputs/validation_result_fail.json")
    validate_artifact(artifact, SCHEMA_VALIDATION_RESULT)


def test_validation_result_invalid_overall_fails():
    """A validation result with unrecognised overall value must fail."""
    artifact = load_example("expected_outputs/validation_result_pass.json")
    bad = copy.deepcopy(artifact)
    bad["overall"] = "PARTIAL"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_VALIDATION_RESULT)


def test_validation_result_invalid_check_status_fails():
    """A validation result with an unrecognised check status must fail."""
    artifact = load_example("expected_outputs/validation_result_pass.json")
    bad = copy.deepcopy(artifact)
    bad["checks"][0]["status"] = "warning"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_VALIDATION_RESULT)


def test_validation_result_missing_checks_fails():
    """A validation result missing 'checks' must fail."""
    artifact = load_example("expected_outputs/validation_result_pass.json")
    bad = copy.deepcopy(artifact)
    del bad["checks"]
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_VALIDATION_RESULT)


# ---------------------------------------------------------------------------
# Audit result schema — validation
# ---------------------------------------------------------------------------

def test_audit_result_valid_example_passes():
    """Bundled audit_result_valid example must pass the audit_result schema."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    validate_artifact(artifact, SCHEMA_AUDIT_RESULT)


def test_audit_result_ambiguous_example_passes():
    """Bundled audit_result_ambiguous example must pass the audit_result schema."""
    artifact = load_example("expected_outputs/audit_result_ambiguous.json")
    validate_artifact(artifact, SCHEMA_AUDIT_RESULT)


def test_audit_result_invalid_classification_fails():
    """An audit result with an unrecognised classification must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    bad["classification"] = "MAYBE"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


def test_audit_result_invalid_confidence_fails():
    """An audit result with an unrecognised confidence level must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    bad["confidence"] = "very_high"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


def test_audit_result_invalid_evidence_source_fails():
    """An audit result with an unrecognised evidence source must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    bad["evidence"][0]["source"] = "unknown_tool"
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


def test_audit_result_invalid_evidence_weight_fails():
    """An audit result with an unrecognised evidence weight must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    bad["evidence"][0]["weight"] = "definitive"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


def test_audit_result_missing_evidence_fails():
    """An audit result missing 'evidence' must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    del bad["evidence"]
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


def test_audit_result_invalid_reviewer_type_fails():
    """An audit result with an unrecognised reviewer type must fail."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    bad = copy.deepcopy(artifact)
    bad["reviewer"]["type"] = "robot"  # not in enum
    with pytest.raises(Exception):
        validate_artifact(bad, SCHEMA_AUDIT_RESULT)


# ---------------------------------------------------------------------------
# validate_artifact_file convenience wrapper
# ---------------------------------------------------------------------------

def test_validate_artifact_file_with_valid_seed(tmp_path):
    """validate_artifact_file must succeed for a valid seed file."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    p = tmp_path / "seed.json"
    p.write_text(json.dumps(artifact), encoding="utf-8")
    validate_artifact_file(p, SCHEMA_SEED)  # must not raise


def test_validate_artifact_file_not_found_raises(tmp_path):
    """validate_artifact_file must raise FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        validate_artifact_file(tmp_path / "no_such_file.json", SCHEMA_SEED)


def test_validate_artifact_file_invalid_json_raises(tmp_path):
    """validate_artifact_file must raise for files that are not valid JSON."""
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        validate_artifact_file(p, SCHEMA_SEED)


def test_validate_artifact_file_schema_violation_raises(tmp_path):
    """validate_artifact_file must raise for files that violate the schema."""
    artifact = load_example("seeds/cwe122_heap_overflow.json")
    bad = copy.deepcopy(artifact)
    del bad["cwe_id"]
    p = tmp_path / "bad_seed.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(Exception):
        validate_artifact_file(p, SCHEMA_SEED)


# ---------------------------------------------------------------------------
# validate_bundle
# ---------------------------------------------------------------------------

def test_validate_bundle_empty_dir_returns_no_errors(tmp_path):
    """An empty bundle directory (no recognised artifacts present) should not error."""
    errors = validate_bundle(tmp_path)
    assert errors == []


def test_validate_bundle_missing_dir_returns_error():
    """A non-existent bundle directory must return an error, not raise."""
    errors = validate_bundle(Path("/tmp/insert_me_no_such_bundle_xyz"))
    assert len(errors) == 1
    assert "not found" in errors[0].lower()


def test_validate_bundle_not_a_dir_returns_error(tmp_path):
    """A bundle path that points to a file (not a dir) must return an error."""
    f = tmp_path / "not_a_dir.json"
    f.write_text("{}", encoding="utf-8")
    errors = validate_bundle(f)
    assert len(errors) == 1
    assert "not a directory" in errors[0].lower()


def test_validate_bundle_valid_audit_result(tmp_path):
    """A bundle containing a valid audit_result.json must produce no errors."""
    artifact = load_example("expected_outputs/audit_result_valid.json")
    (tmp_path / "audit_result.json").write_text(
        json.dumps(artifact), encoding="utf-8"
    )
    errors = validate_bundle(tmp_path)
    assert errors == [], f"Unexpected errors: {errors}"


def test_validate_bundle_invalid_artifact_reports_error(tmp_path):
    """A bundle containing a schema-invalid file must report an error for it."""
    bad = {"schema_version": "1.0"}  # missing all required fields for audit_result
    (tmp_path / "audit_result.json").write_text(
        json.dumps(bad), encoding="utf-8"
    )
    errors = validate_bundle(tmp_path)
    assert any("audit_result.json" in e for e in errors)
