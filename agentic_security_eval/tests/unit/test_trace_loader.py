"""Unit tests for load_trace_evaluation_input: valid bundle and boundary failures."""

import json
from pathlib import Path

import pytest

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import TraceEvaluationInput
from agentic_security_eval.trace_io.loader import load_trace_evaluation_input

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def _valid_bundle() -> dict:
    return {
        "attack_case": {
            "id": "c1", "category": "ASI02", "surface": "tool_output",
            "objective": "o", "payload": "p", "expected_risk": "r",
        },
        "attack_trace": {
            "target_id": "t", "run_id": "r1", "attack_case_id": "c1", "final_output": "ok",
        },
    }


def test_loads_valid_trace_bundle():
    result = load_trace_evaluation_input(TRACES / "asi02_tool_misuse_trace.json")
    assert isinstance(result, TraceEvaluationInput)
    assert result.attack_case.category.value == "ASI02"
    assert result.attack_trace.tool_calls[0].tool_name == "mock_send_email"


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_trace_evaluation_input(tmp_path / "does_not_exist.json")


def test_invalid_json_raises_config_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_trace_evaluation_input(bad)


def test_non_object_json_raises_config_error(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_trace_evaluation_input(bad)


def test_invalid_schema_raises_config_error(tmp_path):
    bad = tmp_path / "schema.json"
    # missing required attack_trace and most attack_case fields
    bad.write_text(json.dumps({"attack_case": {"id": "c1"}}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_trace_evaluation_input(bad)


def test_attack_case_id_mismatch_raises_config_error(tmp_path):
    bundle = _valid_bundle()
    bundle["attack_trace"]["attack_case_id"] = "different-id"
    bad = tmp_path / "mismatch.json"
    bad.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_trace_evaluation_input(bad)
