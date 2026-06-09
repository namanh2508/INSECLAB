"""Unit tests for FindingBuilder: cited-evidence-only, minimal trace snippet."""

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.models import AttackCase, Evidence, Finding, JudgeDecision
from agentic_security_eval.oracle.finding_builder import FindingBuilder

builder = FindingBuilder()


def _case() -> AttackCase:
    return AttackCase(
        id="case-asi02", category=ASICategory.ASI02, surface=AttackSurface.TOOL_OUTPUT,
        objective="o", payload="p", expected_risk="r",
    )


def _evidence(eid: str) -> Evidence:
    return Evidence(
        id=eid, source=EvidenceSource.TOOL_CALL, ref_id="tool-1", snippet="snip",
        locator="tool_calls[0]", reason="r", metadata={"signal": "unsafe_tool_call", "direct": True},
    )


def _decision(evidence_ids=("ev-001",), is_vulnerable=True) -> JudgeDecision:
    return JudgeDecision(
        is_vulnerable=is_vulnerable, category=ASICategory.ASI02, severity=Severity.HIGH,
        confidence=0.9, exploitability_score=0.8, evidence_ids=list(evidence_ids),
        explanation="x", recommendation="y",
    )


def test_builds_finding_from_valid_decision():
    finding = builder.build(_case(), _decision(), [_evidence("ev-001")], ["note"])
    assert isinstance(finding, Finding)
    assert finding.id == "finding__case-asi02"
    assert finding.category == ASICategory.ASI02
    assert finding.surface == AttackSurface.TOOL_OUTPUT
    assert finding.severity == Severity.HIGH
    assert finding.validator_notes == ["note"]


def test_returns_none_for_none_decision():
    assert builder.build(_case(), None, [], []) is None


def test_returns_none_for_non_vulnerable_decision():
    assert builder.build(_case(), _decision(is_vulnerable=False), [_evidence("ev-001")], []) is None


def test_includes_only_cited_evidence():
    finding = builder.build(
        _case(), _decision(evidence_ids=("ev-001",)), [_evidence("ev-001"), _evidence("ev-002")], []
    )
    assert [e.id for e in finding.evidence] == ["ev-001"]


def test_creates_minimal_trace_snippet():
    finding = builder.build(_case(), _decision(), [_evidence("ev-001")], [])
    assert finding.trace_snippet == [
        {
            "evidence_id": "ev-001",
            "source": "tool_call",
            "ref_id": "tool-1",
            "locator": "tool_calls[0]",
            "snippet": "snip",
        }
    ]
