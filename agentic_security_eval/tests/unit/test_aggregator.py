"""Unit tests for ReportAggregator: deterministic counts and summaries."""

from agentic_security_eval.core.enums import (
    ASICategory,
    AttackSurface,
    EvidenceSource,
    Severity,
)
from agentic_security_eval.core.models import AttackCase, Evidence, Finding
from agentic_security_eval.evaluator.aggregator import ReportAggregator

aggregator = ReportAggregator()


def _case(cid: str, category: ASICategory, surface: AttackSurface) -> AttackCase:
    return AttackCase(
        id=cid, category=category, surface=surface,
        objective="o", payload="p", expected_risk="r",
    )


def _finding(fid: str, category: ASICategory, surface: AttackSurface, severity: Severity) -> Finding:
    evidence = Evidence(
        id="ev-001", source=EvidenceSource.FINAL_OUTPUT, ref_id="final_output",
        snippet="s", locator="l", reason="r", metadata={"signal": "x", "direct": True},
    )
    return Finding(
        id=fid, attack_case_id=fid, category=category, surface=surface, severity=severity,
        confidence=0.9, exploitability_score=0.8, is_vulnerable=True, evidence=[evidence],
        explanation="x", recommendation="y",
    )


CASES = [
    _case("c1", ASICategory.ASI01, AttackSurface.USER_PROMPT),
    _case("c2", ASICategory.ASI02, AttackSurface.TOOL_OUTPUT),
    _case("c3", ASICategory.ASI06, AttackSurface.MEMORY_WRITE),
    _case("c4", ASICategory.ASI02, AttackSurface.TOOL_OUTPUT),
]
FINDINGS = [
    _finding("f1", ASICategory.ASI01, AttackSurface.USER_PROMPT, Severity.MEDIUM),
    _finding("f2", ASICategory.ASI02, AttackSurface.TOOL_OUTPUT, Severity.HIGH),
    _finding("f3", ASICategory.ASI06, AttackSurface.MEMORY_WRITE, Severity.CRITICAL),
]


def test_total_cases_and_findings_are_correct():
    report = aggregator.build("vuln", CASES, FINDINGS)
    assert report.report_id == "report__vuln"
    assert report.target_id == "vuln"
    assert report.total_cases == 4
    assert report.total_findings == 3


def test_tested_categories_are_deterministic():
    report = aggregator.build("vuln", CASES, FINDINGS)
    assert report.tested_categories == [ASICategory.ASI01, ASICategory.ASI02, ASICategory.ASI06]


def test_tested_surfaces_are_deterministic():
    report = aggregator.build("vuln", CASES, FINDINGS)
    assert report.tested_surfaces == [
        AttackSurface.USER_PROMPT,
        AttackSurface.TOOL_OUTPUT,
        AttackSurface.MEMORY_WRITE,
    ]


def test_category_summary_counts_correctly():
    report = aggregator.build("vuln", CASES, FINDINGS)
    asi02 = report.category_summary["ASI02"]
    assert asi02.total_cases == 2
    assert asi02.total_findings == 1
    assert asi02.by_severity == {"high": 1}


def test_severity_distribution_counts_correctly():
    report = aggregator.build("vuln", CASES, FINDINGS)
    assert report.severity_distribution == {"medium": 1, "high": 1, "critical": 1}


def test_surface_summary_counts_findings_by_surface():
    report = aggregator.build("vuln", CASES, FINDINGS)
    assert report.surface_summary == {"user_prompt": 1, "tool_output": 1, "memory_write": 1}
    assert report.metadata.get("surface_summary_basis") == "findings"


def test_empty_cases_and_findings_produce_valid_empty_report():
    report = aggregator.build("empty", [], [])
    assert report.report_id == "report__empty"
    assert report.total_cases == 0
    assert report.total_findings == 0
    assert report.findings == []
    assert report.tested_categories == []
    assert report.tested_surfaces == []
    assert report.category_summary == {}
    assert report.severity_distribution == {}
    assert report.surface_summary == {}
