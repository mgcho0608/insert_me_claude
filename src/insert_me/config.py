"""
Configuration loading for insert_me.

Config is loaded from a TOML file. All keys have defaults defined here so that
the pipeline is fully runnable from a minimal config or from the built-in
defaults with no user-supplied file.

Load order (later entries override earlier):
    1. Built-in defaults (this module)
    2. User config file (if --config is supplied)
    3. CLI flags (e.g. --no-llm overrides [llm].enabled)

Config sections
---------------
[pipeline]
    seed_file       str     — path to seed JSON file (canonical primary input)
    seed            int     — legacy: integer seed (use seed_file instead)
    spec_path       str     — legacy: path to spec TOML (use seed_file instead)
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
    seed_file: Optional[Path] = None    # canonical: path to seed JSON file
    seed: Optional[int] = None          # legacy: integer seed
    spec_path: Optional[Path] = None    # legacy: path to spec TOML
    source_path: Optional[Path] = None
    output_root: Path = field(default_factory=lambda: Path("output"))
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
        If the config file contains unrecognised section keys.
    """
    cfg = Config()
    if config_path is None:
        return cfg

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "rb") as fh:
        raw = tomllib.load(fh)

    if "pipeline" in raw:
        p = raw["pipeline"]
        if "seed_file" in p:
            cfg.pipeline.seed_file = Path(p["seed_file"])
        if "seed" in p:
            cfg.pipeline.seed = int(p["seed"])
        if "spec_path" in p:
            cfg.pipeline.spec_path = Path(p["spec_path"])
        if "source_path" in p:
            cfg.pipeline.source_path = Path(p["source_path"])
        if "output_root" in p:
            cfg.pipeline.output_root = Path(p["output_root"])
        if "run_id" in p:
            cfg.pipeline.run_id = str(p["run_id"])

    if "llm" in raw:
        l = raw["llm"]
        if "enabled" in l:
            cfg.llm.enabled = bool(l["enabled"])
        if "adapter" in l:
            cfg.llm.adapter = str(l["adapter"])
        if "endpoint" in l:
            cfg.llm.endpoint = str(l["endpoint"])
        if "model" in l:
            cfg.llm.model = str(l["model"])
        if "timeout_seconds" in l:
            cfg.llm.timeout_seconds = int(l["timeout_seconds"])

    if "validator" in raw:
        v = raw["validator"]
        if "check_syntax" in v:
            cfg.validator.check_syntax = bool(v["check_syntax"])
        if "check_trivial" in v:
            cfg.validator.check_trivial = bool(v["check_trivial"])
        if "check_scope" in v:
            cfg.validator.check_scope = bool(v["check_scope"])

    if "auditor" in raw:
        a = raw["auditor"]
        if "write_labels" in a:
            cfg.auditor.write_labels = bool(a["write_labels"])
        if "output_format" in a:
            cfg.auditor.output_format = str(a["output_format"])

    return cfg


def apply_cli_overrides(config: Config, **overrides: object) -> Config:
    """
    Apply CLI-level overrides on top of a loaded Config.

    Parameters
    ----------
    config:
        Base Config to override (mutated in place and returned).
    **overrides:
        Flat key=value pairs. Supported keys:
            seed_file, seed, spec_path, source_path, output_root, run_id,
            no_llm

    Returns
    -------
    Config
        Updated Config.
    """
    if overrides.get("seed_file") is not None:
        config.pipeline.seed_file = Path(overrides["seed_file"])  # type: ignore[arg-type]
    if overrides.get("seed") is not None:
        config.pipeline.seed = int(overrides["seed"])  # type: ignore[arg-type]
    if overrides.get("spec_path") is not None:
        config.pipeline.spec_path = Path(overrides["spec_path"])  # type: ignore[arg-type]
    if overrides.get("source_path") is not None:
        config.pipeline.source_path = Path(overrides["source_path"])  # type: ignore[arg-type]
    if overrides.get("output_root") is not None:
        config.pipeline.output_root = Path(overrides["output_root"])  # type: ignore[arg-type]
    if overrides.get("run_id") is not None:
        config.pipeline.run_id = str(overrides["run_id"])
    if overrides.get("no_llm"):
        config.llm.enabled = False
    return config
