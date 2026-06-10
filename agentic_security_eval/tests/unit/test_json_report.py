"""Unit tests for JsonReportWriter: valid JSON and file output."""

import json

import pytest

from agentic_security_eval.core.enums import (
    ASICategory,
    AttackSurface,
    EvidenceSource,
    Severity,
)
from agentic_security_eval.core.errors import ReportError
from agentic_security_eval.core.models import AttackCase, Evidence, Finding
from agentic_security_eval.evaluator.aggregator import ReportAggregator
from agentic_security_eval.reporting.json_report import JsonReportWriter


def _report():
    case = AttackCase(
        id="c1", category=ASICategory.ASI02, surface=AttackSurface.TOOL_OUTPUT,
        objective="o", payload="p", expected_risk="r",
    )
    evidence = Evidence(
        id="ev-001", source=EvidenceSource.TOOL_CALL, ref_id="tool-1", snippet="s",
        locator="l", reason="r", metadata={"signal": "unsafe_tool_call", "direct": True},
    )
    finding = Finding(
        id="finding__c1", attack_case_id="c1", category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT, severity=Severity.HIGH, confidence=0.9,
        exploitability_score=0.8, is_vulnerable=True, evidence=[evidence],
        explanation="x", recommendation="y",
    )
    return ReportAggregator().build("vuln", [case], [finding])


def test_to_json_returns_valid_json():
    data = json.loads(JsonReportWriter().to_json(_report()))
    assert data["report_id"] == "report__vuln"


def test_write_creates_json_file(tmp_path):
    path = JsonReportWriter().write(_report(), tmp_path / "out" / "report.json")
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target_id"] == "vuln"


def test_written_json_contains_required_fields(tmp_path):
    path = JsonReportWriter().write(_report(), tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("report_id", "target_id", "total_cases", "total_findings", "findings"):
        assert key in data
    assert data["findings"][0]["id"] == "finding__c1"


def test_write_creates_nested_parent_directories(tmp_path):
    target = tmp_path / "a" / "b" / "c" / "report.json"
    path = JsonReportWriter().write(_report(), target)
    assert path == target
    assert path.exists()
    assert path.parent == tmp_path / "a" / "b" / "c"


def test_write_wraps_oserror_in_report_error(tmp_path):
    # A regular file occupies a path component, so mkdir/write fails with OSError.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")
    with pytest.raises(ReportError):
        JsonReportWriter().write(_report(), blocker / "sub" / "report.json")
