"""
Smoke tests — verify package basics and the canonical README quick-start path.

Coverage
--------
- Package importability and version constants
- CLI help and entry point
- Core helper determinism (run ID, BundlePaths)
- NoOpAdapter contract
- Config defaults
- Demo-fixture integration: run CLI against examples/demo/src, check bundle shape,
  validate-bundle success  (proves the README "Try It Now" section is accurate)
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DEMO_SEED = REPO_ROOT / "examples" / "seeds" / "cwe122_heap_overflow.json"
DEMO_SOURCE = REPO_ROOT / "examples" / "demo" / "src"


def test_package_importable():
    """The package must import without errors."""
    import insert_me  # noqa: F401


def test_version_defined():
    """__version__ must be a non-empty string."""
    import insert_me
    assert isinstance(insert_me.__version__, str)
    assert insert_me.__version__


def test_artifact_schema_version_defined():
    """ARTIFACT_SCHEMA_VERSION must be defined."""
    from insert_me import ARTIFACT_SCHEMA_VERSION
    assert ARTIFACT_SCHEMA_VERSION


def test_cli_help():
    """CLI --help must exit 0 and print usage."""
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "insert-me" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_noop_adapter_importable():
    """NoOpAdapter must be importable and satisfy LLMAdapter interface."""
    from insert_me.llm.adapter import NoOpAdapter
    adapter = NoOpAdapter()
    assert adapter.name == "noop"
    result = adapter.enrich_labels(
        cwe_id="CWE-122",
        mutation_type="heap_overflow",
        original_fragment="buf = malloc(n);",
        mutated_fragment="buf = malloc(n - 1);",
    )
    assert result is not None
    assert result.description == ""


def test_config_defaults():
    """load_config with no file must return a Config with defaults."""
    from insert_me.config import load_config
    cfg = load_config(config_path=None)
    assert cfg.llm.enabled is False
    assert cfg.llm.adapter == "noop"


def test_bundle_paths_from_run_id(tmp_path):
    """BundlePaths must resolve all expected subdirectory paths."""
    from insert_me.artifacts import BundlePaths
    bundle = BundlePaths.from_run_id(output_root=tmp_path, run_id="test1234")
    assert bundle.root == tmp_path / "test1234"
    assert bundle.bad_dir == tmp_path / "test1234" / "bad"
    assert bundle.good_dir == tmp_path / "test1234" / "good"
    assert bundle.ground_truth == tmp_path / "test1234" / "ground_truth.json"
    assert bundle.audit == tmp_path / "test1234" / "audit.json"


def test_derive_run_id_deterministic(tmp_path):
    """derive_run_id must return the same value for the same inputs."""
    from insert_me.artifacts import derive_run_id
    spec = tmp_path / "spec.toml"
    spec.write_text("[meta]\nid = 'test'\n")
    id1 = derive_run_id(seed=42, spec_path=spec, source_path=tmp_path, pipeline_version="0.1.0")
    id2 = derive_run_id(seed=42, spec_path=spec, source_path=tmp_path, pipeline_version="0.1.0")
    assert id1 == id2


def test_derive_run_id_seed_sensitive(tmp_path):
    """derive_run_id must produce different values for different seeds."""
    from insert_me.artifacts import derive_run_id
    spec = tmp_path / "spec.toml"
    spec.write_text("[meta]\nid = 'test'\n")
    id1 = derive_run_id(seed=1, spec_path=spec, source_path=tmp_path, pipeline_version="0.1.0")
    id2 = derive_run_id(seed=2, spec_path=spec, source_path=tmp_path, pipeline_version="0.1.0")
    assert id1 != id2


# ---------------------------------------------------------------------------
# Demo-fixture integration — proves README "Try It Now" section is accurate
# ---------------------------------------------------------------------------


def test_demo_seed_and_source_exist():
    """The demo seed file and source fixture referenced in README must exist."""
    assert DEMO_SEED.exists(), f"Demo seed not found: {DEMO_SEED}"
    assert DEMO_SOURCE.exists(), f"Demo source dir not found: {DEMO_SOURCE}"
    c_files = list(DEMO_SOURCE.glob("*.c"))
    assert len(c_files) > 0, f"Demo source dir has no .c files: {DEMO_SOURCE}"


def test_demo_cli_run_produces_bundle(tmp_path):
    """CLI run (dry-run mode) against the demo fixture must exit 0 and write all artifacts."""
    result = subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(DEMO_SEED),
            "--source", str(DEMO_SOURCE),
            "--output", str(tmp_path / "output"),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"CLI exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    bundles = list((tmp_path / "output").iterdir())
    assert len(bundles) == 1, f"Expected exactly one bundle dir, got: {bundles}"
    bundle = bundles[0]

    for artifact in (
        "patch_plan.json",
        "validation_result.json",
        "audit_result.json",
        "ground_truth.json",
        "audit.json",
    ):
        assert (bundle / artifact).exists(), f"Missing artifact: {artifact}"

    assert (bundle / "bad").is_dir()
    assert (bundle / "good").is_dir()


def test_demo_bundle_has_planned_targets(tmp_path):
    """Dry-run: patch_plan.json must have status PLANNED and real Seeder targets."""
    subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(DEMO_SEED),
            "--source", str(DEMO_SOURCE),
            "--output", str(tmp_path / "output"),
            "--dry-run",
        ],
        capture_output=True,
        check=True,
    )
    bundle = next((tmp_path / "output").iterdir())
    plan = json.loads((bundle / "patch_plan.json").read_text(encoding="utf-8"))

    assert plan["status"] == "PLANNED", (
        f"Expected PLANNED (dry-run), got {plan['status']}."
    )
    assert len(plan["targets"]) > 0, "Expected at least one Seeder target"
    for t in plan["targets"]:
        assert 0.0 <= t["candidate_score"] <= 1.0
        assert t["line"] >= 1
        assert t["file"]


def test_demo_validate_bundle_passes(tmp_path):
    """validate-bundle must exit 0 on a bundle generated from the demo fixture."""
    subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(DEMO_SEED),
            "--source", str(DEMO_SOURCE),
            "--output", str(tmp_path / "output"),
            "--dry-run",
        ],
        capture_output=True,
        check=True,
    )
    bundle = next((tmp_path / "output").iterdir())

    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"validate-bundle failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "valid" in result.stdout.lower()


def test_demo_real_mode_applies_mutation(tmp_path):
    """Real mode (no --dry-run): mutation applied, bad/ and good/ differ."""
    result = subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(DEMO_SEED),
            "--source", str(DEMO_SOURCE),
            "--output", str(tmp_path / "output"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"CLI exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    bundle = next((tmp_path / "output").iterdir())

    # patch_plan status must be APPLIED
    plan = json.loads((bundle / "patch_plan.json").read_text(encoding="utf-8"))
    assert plan["status"] == "APPLIED"

    # ground_truth must have one real mutation record
    gt = json.loads((bundle / "ground_truth.json").read_text(encoding="utf-8"))
    assert len(gt["mutations"]) == 1
    m = gt["mutations"][0]
    assert m["mutation_type"] == "alloc_size_undercount"
    assert "malloc(" in m["original_fragment"]
    assert "- 1)" in m["mutated_fragment"]

    # bad/ and good/ must contain the C file
    bad_files = list((bundle / "bad").rglob("*.c"))
    good_files = list((bundle / "good").rglob("*.c"))
    assert len(bad_files) > 0
    assert len(good_files) > 0

    # The C file in bad/ must differ from good/
    bad_c = bad_files[0]
    good_c = bundle / "good" / bad_c.relative_to(bundle / "bad")
    assert bad_c.read_text(encoding="utf-8") != good_c.read_text(encoding="utf-8")


def test_demo_real_mode_validate_bundle_passes(tmp_path):
    """validate-bundle must exit 0 on a real-mode bundle."""
    subprocess.run(
        [
            sys.executable, "-m", "insert_me.cli", "run",
            "--seed-file", str(DEMO_SEED),
            "--source", str(DEMO_SOURCE),
            "--output", str(tmp_path / "output"),
        ],
        capture_output=True,
        check=True,
    )
    bundle = next((tmp_path / "output").iterdir())
    result = subprocess.run(
        [sys.executable, "-m", "insert_me.cli", "validate-bundle", str(bundle)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"validate-bundle failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
