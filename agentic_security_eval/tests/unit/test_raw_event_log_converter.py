"""Unit tests for the raw agent-log loader and converter."""

import json
from pathlib import Path

import pytest

from agentic_security_eval.converters.raw_event_log import (
    RawAgentLog,
    load_raw_agent_log,
    raw_log_to_trace_input,
)
from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import TraceEvaluationInput

RAW = Path(__file__).resolve().parents[2] / "examples" / "raw_logs"


def _base_log() -> dict:
    return {
        "target_id": "t",
        "run_id": "r1",
        "scenario_id": "s1",
        "attack_case": {
            "id": "c1", "category": "ASI02", "surface": "tool_output",
            "objective": "o", "payload": "p", "expected_risk": "r",
        },
        "events": [{"type": "final_output", "content": "ok"}],
        "metadata": {},
    }


def _log_with_events(events: list[dict]) -> RawAgentLog:
    data = _base_log()
    data["events"] = events
    return RawAgentLog.model_validate(data)


def _convert(name: str) -> TraceEvaluationInput:
    return raw_log_to_trace_input(load_raw_agent_log(RAW / name))


def test_loads_asi01_raw_log():
    log = load_raw_agent_log(RAW / "asi01_goal_hijack_raw_log.json")
    assert isinstance(log, RawAgentLog)
    assert log.attack_case.category.value == "ASI01"


def test_loads_asi02_raw_log():
    assert load_raw_agent_log(RAW / "asi02_tool_misuse_raw_log.json").attack_case.category.value == "ASI02"


def test_loads_asi06_raw_log():
    assert load_raw_agent_log(RAW / "asi06_memory_poisoning_raw_log.json").attack_case.category.value == "ASI06"


def test_loads_hardened_raw_log():
    assert load_raw_agent_log(RAW / "hardened_raw_log.json").attack_case.id == "raw_hardened_001"


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_raw_agent_log(tmp_path / "nope.json")


def test_invalid_json_raises_config_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_raw_agent_log(bad)


def test_non_object_json_raises_config_error(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_raw_agent_log(bad)


def test_unsupported_event_type_raises_config_error(tmp_path):
    data = _base_log()
    data["events"] = [{"type": "weird_event", "content": "x"}]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_raw_agent_log(bad)


def test_missing_required_field_raises_config_error(tmp_path):
    data = _base_log()
    data["events"] = [{"type": "message", "role": "user"}]  # missing content
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_raw_agent_log(bad)


def test_conversion_preserves_explicit_event_ids():
    log = _log_with_events([
        {"type": "message", "id": "custom-msg", "role": "user", "content": "hi"},
        {"type": "tool_call", "id": "custom-tool", "tool_name": "x", "metadata": {"unsafe": True}},
    ])
    trace_input = raw_log_to_trace_input(log)
    assert trace_input.attack_trace.messages[0].id == "custom-msg"
    assert trace_input.attack_trace.tool_calls[0].id == "custom-tool"


def test_conversion_generates_deterministic_ids_when_missing():
    log = _log_with_events([
        {"type": "message", "role": "user", "content": "a"},
        {"type": "message", "role": "assistant", "content": "b"},
        {"type": "memory_event", "operation": "write", "key": "k", "value": "v"},
    ])
    trace_input = raw_log_to_trace_input(log)
    assert [m.id for m in trace_input.attack_trace.messages] == ["msg-1", "msg-2"]
    assert trace_input.attack_trace.memory_events[0].id == "mem-1"


def test_multiple_final_outputs_use_last_and_set_metadata_note():
    log = _log_with_events([
        {"type": "final_output", "content": "first"},
        {"type": "final_output", "content": "last"},
    ])
    trace_input = raw_log_to_trace_input(log)
    assert trace_input.attack_trace.final_output == "last"
    assert trace_input.attack_trace.metadata.get("multiple_final_outputs") is True


def test_converted_asi02_has_unsafe_tool_call():
    trace_input = _convert("asi02_tool_misuse_raw_log.json")
    assert any(tc.metadata.get("unsafe") is True for tc in trace_input.attack_trace.tool_calls)


def test_converted_asi06_has_unsafe_memory_event():
    trace_input = _convert("asi06_memory_poisoning_raw_log.json")
    assert any(me.metadata.get("unsafe") is True for me in trace_input.attack_trace.memory_events)


def test_converted_hardened_has_no_unsafe_events():
    trace_input = _convert("hardened_raw_log.json")
    assert all(tc.metadata.get("unsafe") is not True for tc in trace_input.attack_trace.tool_calls)
    assert all(me.metadata.get("unsafe") is not True for me in trace_input.attack_trace.memory_events)


def test_duplicate_explicit_ids_raise_config_error():
    log = _log_with_events([
        {"type": "message", "id": "msg-1", "role": "user", "content": "a"},
        {"type": "tool_call", "id": "msg-1", "tool_name": "mock_tool", "metadata": {"unsafe": True}},
    ])
    with pytest.raises(ConfigError):
        raw_log_to_trace_input(log)


def test_explicit_message_id_forces_generated_to_skip():
    log = _log_with_events([
        {"type": "message", "id": "msg-1", "role": "user", "content": "a"},
        {"type": "message", "role": "assistant", "content": "b"},
    ])
    trace_input = raw_log_to_trace_input(log)
    assert [m.id for m in trace_input.attack_trace.messages] == ["msg-1", "msg-2"]


def test_explicit_tool_id_forces_generated_to_skip():
    log = _log_with_events([
        {"type": "tool_call", "id": "tool-1", "tool_name": "x", "metadata": {"unsafe": True}},
        {"type": "tool_call", "tool_name": "y", "metadata": {"unsafe": True}},
    ])
    trace_input = raw_log_to_trace_input(log)
    assert [t.id for t in trace_input.attack_trace.tool_calls] == ["tool-1", "tool-2"]


def test_ids_are_unique_across_all_trace_channels():
    log = _log_with_events([
        {"type": "message", "role": "user", "content": "a"},
        {"type": "message", "id": "msg-1", "role": "assistant", "content": "b"},
        {"type": "tool_call", "tool_name": "x", "metadata": {"unsafe": True}},
        {"type": "memory_event", "operation": "write", "key": "k", "value": "v"},
        {"type": "retrieval_event", "source": "web", "content": "c"},
        {"type": "inter_agent_message", "from_agent": "A", "to_agent": "B", "content": "c"},
    ])
    trace = raw_log_to_trace_input(log).attack_trace
    all_ids = (
        [m.id for m in trace.messages]
        + [t.id for t in trace.tool_calls]
        + [m.id for m in trace.memory_events]
        + [r.id for r in trace.retrieval_events]
        + [i.id for i in trace.inter_agent_messages]
    )
    assert len(all_ids) == len(set(all_ids))
    # the auto-generated message id skipped the explicit "msg-1"
    assert "msg-2" in all_ids


# --------------------------------------------------------------------------- #
# Phase 14.3: Generic Agent Event Log standardization
# --------------------------------------------------------------------------- #
def test_schema_version_defaults_when_absent():
    # Existing logs without schema_version remain valid (default applied).
    log = load_raw_agent_log(RAW / "asi02_tool_misuse_raw_log.json")
    assert log.schema_version == "0.1"


def test_explicit_supported_schema_version_is_accepted():
    log = _log_with_events([{"type": "final_output", "content": "ok"}])
    assert log.schema_version == "0.1"
    data = _base_log()
    data["schema_version"] = "0.1"
    assert RawAgentLog.model_validate(data).schema_version == "0.1"


def test_unsupported_schema_version_raises_config_error(tmp_path):
    data = _base_log()
    data["schema_version"] = "9.9"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_raw_agent_log(bad)


def test_combined_fixture_populates_retrieval_inter_agent_and_error_channels():
    trace = _convert("generic_event_log_combined_raw_log.json").attack_trace
    assert len(trace.retrieval_events) == 1
    assert trace.retrieval_events[0].source == "https://example.com/feed"
    assert len(trace.inter_agent_messages) == 1
    assert trace.inter_agent_messages[0].from_agent == "researcher"
    assert trace.errors == ["retrieval timeout on secondary source"]
    assert trace.final_output == "Here is a neutral summary of the research notes."


def test_converter_does_not_synthesize_unsafe_metadata_or_signals():
    log = _log_with_events([
        {"type": "tool_call", "tool_name": "benign_tool", "arguments": {"x": 1}, "result": "ok"},
        {"type": "memory_event", "operation": "write", "key": "k", "value": "v"},
    ])
    trace = raw_log_to_trace_input(log).attack_trace
    tool_meta = trace.tool_calls[0].metadata
    mem_meta = trace.memory_events[0].metadata
    assert "unsafe" not in tool_meta and "signal" not in tool_meta
    assert "unsafe" not in mem_meta and "signal" not in mem_meta


def test_converter_preserves_event_metadata_verbatim():
    # Target-provided metadata (including an explicit unsafe self-label) is passed
    # through unchanged; the converter neither adds nor strips it.
    log = _log_with_events([
        {"type": "tool_call", "tool_name": "x", "metadata": {"unsafe": True, "custom": "v"}},
    ])
    trace = raw_log_to_trace_input(log).attack_trace
    assert trace.tool_calls[0].metadata == {"unsafe": True, "custom": "v"}


def test_input_order_is_authoritative():
    # A tool_call interleaved between two messages must not reorder the messages.
    log = _log_with_events([
        {"type": "message", "role": "user", "content": "first"},
        {"type": "tool_call", "tool_name": "t"},
        {"type": "message", "role": "assistant", "content": "second"},
    ])
    trace = raw_log_to_trace_input(log).attack_trace
    assert [m.content for m in trace.messages] == ["first", "second"]
