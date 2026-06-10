"""Unit tests for load_target_config: valid configs and boundary failures."""

from pathlib import Path

import pytest

from agentic_security_eval.config.loader import load_target_config
from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import TargetConfig

CONFIGS = Path(__file__).resolve().parents[2] / "configs"


def test_loads_valid_vulnerable_config():
    config = load_target_config(CONFIGS / "fake_vulnerable.yaml")
    assert isinstance(config, TargetConfig)
    assert config.target_id == "fake_vulnerable_agent"
    assert config.adapter_type == "python_workflow"
    assert config.capabilities.tools is True
    assert config.capabilities.memory is True


def test_loads_valid_hardened_config():
    config = load_target_config(CONFIGS / "fake_hardened.yaml")
    assert config.target_id == "fake_hardened_agent"
    assert config.entrypoint == "examples.fake_targets:create_hardened_agent"


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_target_config(tmp_path / "does_not_exist.yaml")


def test_invalid_yaml_raises_config_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("target_id: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_target_config(bad)


def test_non_mapping_yaml_raises_config_error(tmp_path):
    bad = tmp_path / "list.yaml"
    bad.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_target_config(bad)


def test_invalid_schema_raises_config_error(tmp_path):
    bad = tmp_path / "schema.yaml"
    # missing required adapter_type and capabilities
    bad.write_text("target_id: x\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_target_config(bad)
