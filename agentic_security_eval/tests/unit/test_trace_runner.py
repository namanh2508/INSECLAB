"""Unit tests for TraceEvaluationRunner: per-trace findings, no live target."""

import inspect
from pathlib import Path

from agentic_security_eval.core.enums import ASICategory, Severity
from agentic_security_eval.evaluator import trace_runner as trace_runner_module
from agentic_security_eval.evaluator.trace_runner import TraceEvaluationRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter
from agentic_security_eval.trace_io.loader import load_trace_evaluation_input

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def _run(name: str):
    trace_input = load_trace_evaluation_input(TRACES / name)
    return TraceEvaluationRunner(target_id="recorded", judge_provider=FakeJudgeProvider()).run(trace_input)


def test_asi01_trace_produces_one_medium_finding():
    report = _run("asi01_goal_hijack_trace.json")
    assert report.total_findings == 1
    assert report.findings[0].category == ASICategory.ASI01
    assert report.findings[0].severity == Severity.MEDIUM


def test_asi02_trace_produces_one_high_finding():
    report = _run("asi02_tool_misuse_trace.json")
    assert report.total_findings == 1
    assert report.findings[0].category == ASICategory.ASI02
    assert report.findings[0].severity == Severity.HIGH
    assert report.findings[0].evidence  # finding stays evidence-grounded


def test_asi06_trace_produces_one_critical_finding():
    report = _run("asi06_memory_poisoning_trace.json")
    assert report.total_findings == 1
    assert report.findings[0].category == ASICategory.ASI06
    assert report.findings[0].severity == Severity.CRITICAL


def test_hardened_trace_produces_zero_findings():
    report = _run("hardened_trace.json")
    assert report.total_findings == 0


def test_report_total_cases_is_one():
    assert _run("asi02_tool_misuse_trace.json").total_cases == 1


def test_report_is_json_serializable():
    assert JsonReportWriter().to_json(_run("asi02_tool_misuse_trace.json"))


def test_trace_runner_does_not_use_adapter_or_baseline():
    source = inspect.getsource(trace_runner_module)
    assert "PythonWorkflowAdapter" not in source
    assert "BaselineRunner" not in source
