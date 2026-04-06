"""
Configuration loading for insert_me.

Config is loaded from a TOML file. All keys have defaults defined here so that
the pipeline is fully runnable from a minimal config or from the built-in defaults
with no user-supplied file.

Load order (later entries override earlier):
    1. Built-in defaults (this module)
    2. User config file (if --config is supplied)
    3. CLI flags (e.g. --no-llm overrides [llm].enabled)

Config sections
---------------
[pipeline]
    seed            int     — overridable by --seed
    spec_path       str     — path to spec TOML
    source_path     str     — path to source tree root
    output_root     str     — where to write output bundles (default: ./output)
    run_id          str     — override auto-derived run ID (default: derived)

[llm]
    enabled         bool    — master switch; false → always use NoOpAdapter
    adapter         str     — adapter name: "noop" | "openai_compat" | ...
    endpoint        str     — base URL for LLM API (if applicable)
    model           str     — model identifier (adapter-specific)
    timeout_seconds int     — request timeout

[validator]
    check_syntax    bool    — enable syntactic well-formedness check
    check_trivial   bool    — reject trivially broken mutations
    check_scope     bool    — enable file-scope sanity check

[auditor]
    write_labels    bool    — write labels.json (requires LLM enabled)
    output_format   str     — "json" (only supported value for now)
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    seed: Optional[int] = None
    spec_path: Optional[Path] = None
    source_path: Optional[Path] = None
    output_root: Path = Path("output")
    run_id: Optional[str] = None


@dataclass
class LLMConfig:
    enabled: bool = False
    adapter: str = "noop"
    endpoint: str = ""
    model: str = ""
    timeout_seconds: int = 30


@dataclass
class ValidatorConfig:
    check_syntax: bool = True
    check_trivial: bool = True
    check_scope: bool = True


@dataclass
class AuditorConfig:
    write_labels: bool = False
    output_format: str = "json"


@dataclass
class Config:
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    validator: ValidatorConfig = field(default_factory=ValidatorConfig)
    auditor: AuditorConfig = field(default_factory=AuditorConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[Path] = None) -> Config:
    """
    Load configuration from a TOML file, merged over built-in defaults.

    Parameters
    ----------
    config_path:
        Path to user-supplied config TOML. If None, returns defaults only.

    Returns
    -------
    Config
        Fully-populated Config dataclass.

    Raises
    ------
    FileNotFoundError
        If config_path is supplied but does not exist.
    ValueError
        If the config file contains unrecognised keys (strict mode).
    """
    # TODO(phase2): implement full loader with key validation and type coercion
    if config_path is not None:
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with open(config_path, "rb") as fh:
            raw = tomllib.load(fh)
        _ = raw  # TODO(phase2): merge raw into Config dataclass
    return Config()


def apply_cli_overrides(config: Config, **overrides: object) -> Config:
    """
    Apply CLI-level overrides on top of a loaded Config.

    Parameters
    ----------
    config:
        Base Config to override.
    **overrides:
        Flat key=value pairs. Supported keys:
            seed, spec_path, source_path, output_root, run_id, no_llm

    Returns
    -------
    Config
        Updated Config (mutated in place and returned).
    """
    # TODO(phase2): implement override application
    return config
