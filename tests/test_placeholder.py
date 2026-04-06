"""
Placeholder tests — verify the package skeleton is importable and
the CLI entrypoint is reachable.

These are smoke tests only. Real unit/integration tests will be added
per-phase as implementation progresses (see ROADMAP.md).
"""

import subprocess
import sys


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
