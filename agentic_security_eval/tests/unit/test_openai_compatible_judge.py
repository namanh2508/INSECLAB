"""Unit tests for OpenAICompatibleJudgeProvider using fake transports only."""

import json
from typing import Any

import pytest

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.errors import JudgeError
from agentic_security_eval.core.models import AgentTrace, AttackCase, Evidence, JudgeDecision, JudgeRequest
from agentic_security_eval.oracle.judge import JudgeProvider
from agentic_security_eval.oracle.openai_compatible_judge import OpenAICompatibleJudgeProvider

VALID_DECISION = {
    "is_vulnerable": True,
    "category": "ASI02",
    "severity": "high",
    "confidence": 0.9,
    "exploitability_score": 0.8,
    "evidence_ids": ["ev-001"],
    "explanation": "unsafe tool call",
    "recommendation": "gate tools",
}
REQUIRED_KEYS = [
    "is_vulnerable",
    "category",
    "severity",
    "confidence",
    "exploitability_score",
    "evidence_ids",
    "explanation",
    "recommendation",
]
FORBIDDEN_ALIAS_KEYS = {"vulnerable", "rationale", "risk", "score", "evidence"}


class FakeTransport:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        content = json.dumps(VALID_DECISION)
        self.response = response or {"choices": [{"message": {"content": content}}]}
        self.calls: list[tuple[str, dict[str, Any], dict[str, str], float]] = []

    def complete(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        self.calls.append((url, payload, headers, timeout_seconds))
        return self.response


class LeakyTransport:
    def complete(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        raise JudgeError("transport failed with test-key in message")


def _request() -> JudgeRequest:
    case = AttackCase(
        id="case-1",
        category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT,
        objective="test tool misuse",
        payload="payload",
        expected_risk="tool misuse",
    )
    evidence = Evidence(
        id="ev-001",
        source=EvidenceSource.TOOL_CALL,
        ref_id="tool-1",
        locator="tool_calls[0]",
        snippet="mock_send_email({'to': 'external@example.com'})",
        reason="unsafe call",
        metadata={"signal": "unsafe_tool_call", "direct": True},
    )
    return JudgeRequest(
        attack_case=case,
        attack_trace=AgentTrace(target_id="target-1", run_id="run-1"),
        evidence=[evidence],
    )


def _provider(transport: Any, **kwargs) -> OpenAICompatibleJudgeProvider:
    return OpenAICompatibleJudgeProvider(
        model=kwargs.pop("model", "judge-model"),
        base_url=kwargs.pop("base_url", "https://example.test/v1"),
        api_key=kwargs.pop("api_key", "test-key"),
        transport=transport,
        **kwargs,
    )


def test_provider_satisfies_judge_provider_protocol():
    assert isinstance(_provider(FakeTransport()), JudgeProvider)


def test_provider_uses_chat_completions_endpoint_and_strips_trailing_slash():
    transport = FakeTransport()
    _provider(transport, base_url="http://localhost:1234/v1/").judge(_request())
    assert transport.calls[0][0] == "http://localhost:1234/v1/chat/completions"


def test_provider_sends_model_messages_authorization_and_timeout():
    transport = FakeTransport()
    _provider(transport, timeout_seconds=12.5).judge(_request())
    url, payload, headers, timeout_seconds = transport.calls[0]
    assert url == "https://example.test/v1/chat/completions"
    assert payload["model"] == "judge-model"
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"
    assert headers["Authorization"] == "Bearer test-key"
    assert headers["Content-Type"] == "application/json"
    assert timeout_seconds == 12.5


def test_provider_does_not_leak_api_key_in_errors():
    provider = _provider(LeakyTransport())
    with pytest.raises(JudgeError) as exc:
        provider.judge(_request())
    assert "test-key" not in str(exc.value)
    assert "[redacted]" in str(exc.value)


def test_provider_parses_valid_json_response_into_judge_decision():
    decision = _provider(FakeTransport()).judge(_request())
    assert isinstance(decision, JudgeDecision)
    assert decision.category == ASICategory.ASI02
    assert decision.severity == Severity.HIGH
    assert decision.evidence_ids == ["ev-001"]


def test_provider_raises_judge_error_on_missing_model():
    with pytest.raises(JudgeError):
        _provider(FakeTransport(), model="")


def test_provider_raises_judge_error_on_invalid_response_format_mode():
    with pytest.raises(JudgeError):
        _provider(FakeTransport(), response_format_mode="xml")


def test_provider_raises_judge_error_on_malformed_response_shape():
    provider = _provider(FakeTransport(response={"choices": [{"message": {}}]}))
    with pytest.raises(JudgeError):
        provider.judge(_request())


def test_provider_raises_judge_error_on_invalid_model_json():
    provider = _provider(FakeTransport(response={"choices": [{"message": {"content": "{not json"}}]}))
    with pytest.raises(JudgeError):
        provider.judge(_request())


def test_response_format_none_omits_response_format():
    transport = FakeTransport()
    _provider(transport, response_format_mode="none").judge(_request())
    assert "response_format" not in transport.calls[0][1]


def test_response_format_json_object_is_sent():
    transport = FakeTransport()
    _provider(transport, response_format_mode="json_object").judge(_request())
    assert transport.calls[0][1]["response_format"] == {"type": "json_object"}


def test_response_format_json_schema_is_strict_and_excludes_metadata_requirement():
    transport = FakeTransport()
    _provider(transport, response_format_mode="json_schema").judge(_request())
    response_format = transport.calls[0][1]["response_format"]
    schema = response_format["json_schema"]["schema"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True
    assert schema["additionalProperties"] is False
    assert schema["required"] == REQUIRED_KEYS
    assert "metadata" not in schema["required"]
    assert schema["properties"]["category"]["enum"] == ["ASI01", "ASI02", "ASI06"]
    assert schema["properties"]["confidence"]["minimum"] == 0
    assert schema["properties"]["confidence"]["maximum"] == 1
    assert schema["properties"]["exploitability_score"]["minimum"] == 0
    assert schema["properties"]["exploitability_score"]["maximum"] == 1
    assert not (FORBIDDEN_ALIAS_KEYS & set(schema["properties"]))


def test_default_transport_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(JudgeError):
        OpenAICompatibleJudgeProvider(model="judge-model")


def test_explicit_api_key_wins_over_env_var(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    transport = FakeTransport()
    _provider(transport, api_key="explicit-key").judge(_request())
    assert transport.calls[0][2]["Authorization"] == "Bearer explicit-key"
