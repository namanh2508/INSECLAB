"""Unit tests for CLI judge-provider selection."""

import json
from pathlib import Path

import pytest

from agentic_security_eval import cli
from agentic_security_eval.cli import main
from agentic_security_eval.core.enums import Severity
from agentic_security_eval.core.models import JudgeDecision, JudgeRequest

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"
RAW = Path(__file__).resolve().parents[2] / "examples" / "raw_logs"


def _install_dummy_openai_provider(monkeypatch):
    instances = []

    class DummyOpenAIProvider:
        name = "openai-compatible"

        def __init__(self, model: str, base_url: str, api_key_env: str, response_format_mode: str) -> None:
            self.model = model
            self.base_url = base_url
            self.api_key_env = api_key_env
            self.response_format_mode = response_format_mode
            instances.append(self)

        def judge(self, request: JudgeRequest) -> JudgeDecision:
            return JudgeDecision(
                is_vulnerable=False,
                category=request.attack_case.category,
                severity=Severity.INFO,
                confidence=0.0,
                exploitability_score=0.0,
                evidence_ids=[],
                explanation="dummy openai-compatible verdict",
                recommendation="none",
            )

    monkeypatch.setattr(cli, "OpenAICompatibleJudgeProvider", DummyOpenAIProvider)
    return instances


def test_default_cli_still_uses_fake_provider_and_succeeds(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", str(TRACES / "asi02_tool_misuse_trace.json"), "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_findings"] == 1


def test_openai_compatible_without_model_returns_nonzero(tmp_path):
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi02_tool_misuse_trace.json"),
        "--output", str(out),
        "--judge-provider", "openai-compatible",
    ])
    assert rc != 0


def test_unsupported_judge_provider_returns_nonzero(tmp_path):
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi02_tool_misuse_trace.json"),
        "--output", str(out),
        "--judge-provider", "unknown",
    ])
    assert rc != 0


def test_convert_trace_does_not_accept_judge_options(tmp_path):
    out = tmp_path / "converted.json"
    with pytest.raises(SystemExit):
        main([
            "convert-trace",
            "--input", str(RAW / "asi02_tool_misuse_raw_log.json"),
            "--output", str(out),
            "--judge-provider", "fake",
        ])


def test_eval_trace_can_use_openai_compatible_provider_without_network(monkeypatch, tmp_path):
    instances = _install_dummy_openai_provider(monkeypatch)
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi02_tool_misuse_trace.json"),
        "--output", str(out),
        "--judge-provider", "openai-compatible",
        "--judge-model", "judge-model",
        "--judge-base-url", "http://localhost:1234/v1",
        "--judge-api-key-env", "LOCAL_LLM_API_KEY",
        "--judge-response-format", "none",
    ])
    assert rc == 0
    assert instances[0].model == "judge-model"
    assert instances[0].base_url == "http://localhost:1234/v1"
    assert instances[0].api_key_env == "LOCAL_LLM_API_KEY"
    assert instances[0].response_format_mode == "none"


def test_eval_raw_trace_parses_openai_compatible_options_without_network(monkeypatch, tmp_path):
    instances = _install_dummy_openai_provider(monkeypatch)
    out = tmp_path / "report.json"
    rc = main([
        "eval-raw-trace",
        "--input", str(RAW / "asi02_tool_misuse_raw_log.json"),
        "--output", str(out),
        "--judge-provider", "openai-compatible",
        "--judge-model", "judge-model",
    ])
    assert rc == 0
    assert instances
