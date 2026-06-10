"""Load a TargetConfig from a YAML file.

Config loading is a system boundary: YAML is read with ``yaml.safe_load`` and
validated into ``TargetConfig``. Any problem — missing file, malformed YAML, a
non-mapping top level, or a schema violation — fails fast with ``ConfigError``.
"""

from pathlib import Path

import yaml
from pydantic import ValidationError

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import TargetConfig


def load_target_config(path: str | Path) -> TargetConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Target config not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in target config '{config_path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Target config '{config_path}' must be a YAML mapping at the top level.")

    try:
        return TargetConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid target config '{config_path}': {exc}") from exc
