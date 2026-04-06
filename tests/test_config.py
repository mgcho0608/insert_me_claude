"""
Configuration loading tests — Phase 6 readiness hardening.

Coverage
--------
- tomllib/tomli compatibility shim: config module imports cleanly regardless of
  whether tomllib (3.11+) or tomli (3.10 back-port) is available.
- ValidatorConfig has no stale check_syntax/check_trivial/check_scope fields
  (those were documented but never wired to the Validator; removed in hardening pass).
- load_config() returns correct defaults with no file.
- load_config() reads real TOML sections correctly.
- apply_cli_overrides() wires values into Config correctly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Compatibility shim
# ---------------------------------------------------------------------------

class TestTomlibCompatibility:
    def test_config_module_imports_cleanly(self):
        """config.py must import without error on Python 3.10, 3.11, 3.12."""
        import insert_me.config as cfg_mod  # noqa: F401 — import is the test
        assert cfg_mod is not None

    def test_load_config_uses_toml_parsing(self, tmp_path):
        """load_config() must parse a real TOML file (exercises tomllib/tomli path)."""
        toml_file = tmp_path / "insert_me.toml"
        toml_file.write_text(
            "[llm]\nenabled = false\nadapter = \"noop\"\n",
            encoding="utf-8",
        )
        from insert_me.config import load_config
        cfg = load_config(config_path=toml_file)
        assert cfg.llm.enabled is False
        assert cfg.llm.adapter == "noop"

    def test_toml_pipeline_section_parsed(self, tmp_path):
        """Pipeline section in TOML must be read into PipelineConfig."""
        toml_file = tmp_path / "insert_me.toml"
        custom_out = tmp_path / "custom_output"
        toml_file.write_text(
            f'[pipeline]\noutput_root = {str(custom_out)!r}\n',
            encoding="utf-8",
        )
        from insert_me.config import load_config
        cfg = load_config(config_path=toml_file)
        assert cfg.pipeline.output_root == custom_out

    def test_missing_config_file_raises(self, tmp_path):
        """load_config() must raise FileNotFoundError for a non-existent path."""
        from insert_me.config import load_config
        with pytest.raises(FileNotFoundError):
            load_config(config_path=tmp_path / "nonexistent.toml")


# ---------------------------------------------------------------------------
# ValidatorConfig — stale field removal
# ---------------------------------------------------------------------------

class TestValidatorConfigClean:
    def test_validator_config_has_no_check_syntax(self):
        """check_syntax was removed (it was never wired to the Validator)."""
        from insert_me.config import ValidatorConfig
        cfg = ValidatorConfig()
        assert not hasattr(cfg, "check_syntax"), (
            "check_syntax was removed as dead config; it must not exist on ValidatorConfig"
        )

    def test_validator_config_has_no_check_trivial(self):
        """check_trivial was removed (it was never wired to the Validator)."""
        from insert_me.config import ValidatorConfig
        cfg = ValidatorConfig()
        assert not hasattr(cfg, "check_trivial"), (
            "check_trivial was removed as dead config; it must not exist on ValidatorConfig"
        )

    def test_validator_config_has_no_check_scope(self):
        """check_scope was removed (it was never wired to the Validator)."""
        from insert_me.config import ValidatorConfig
        cfg = ValidatorConfig()
        assert not hasattr(cfg, "check_scope"), (
            "check_scope was removed as dead config; it must not exist on ValidatorConfig"
        )

    def test_validator_config_instantiates_with_no_args(self):
        """ValidatorConfig() with no arguments must succeed."""
        from insert_me.config import ValidatorConfig
        cfg = ValidatorConfig()
        assert cfg is not None

    def test_validator_section_in_toml_ignored_not_error(self, tmp_path):
        """A [validator] section in a TOML config must not raise — it is silently ignored."""
        toml_file = tmp_path / "insert_me.toml"
        toml_file.write_text(
            "[validator]\n# no configurable fields in Phase 5\n",
            encoding="utf-8",
        )
        from insert_me.config import load_config
        cfg = load_config(config_path=toml_file)
        assert cfg is not None  # must not raise


# ---------------------------------------------------------------------------
# Default config correctness
# ---------------------------------------------------------------------------

class TestConfigDefaults:
    def test_defaults_llm_disabled(self):
        from insert_me.config import load_config
        cfg = load_config()
        assert cfg.llm.enabled is False

    def test_defaults_auditor_write_labels_false(self):
        from insert_me.config import load_config
        cfg = load_config()
        assert cfg.auditor.write_labels is False

    def test_defaults_output_root_is_output(self):
        from insert_me.config import load_config
        cfg = load_config()
        assert cfg.pipeline.output_root == Path("output")


# ---------------------------------------------------------------------------
# apply_cli_overrides
# ---------------------------------------------------------------------------

class TestApplyCliOverrides:
    def test_seed_file_override(self, tmp_path):
        from insert_me.config import load_config, apply_cli_overrides
        seed = tmp_path / "seed.json"
        seed.write_text("{}", encoding="utf-8")
        cfg = load_config()
        apply_cli_overrides(cfg, seed_file=seed)
        assert cfg.pipeline.seed_file == seed

    def test_no_llm_override_disables_llm(self):
        from insert_me.config import load_config, apply_cli_overrides
        cfg = load_config()
        cfg.llm.enabled = True  # artificially enable
        apply_cli_overrides(cfg, no_llm=True)
        assert cfg.llm.enabled is False
