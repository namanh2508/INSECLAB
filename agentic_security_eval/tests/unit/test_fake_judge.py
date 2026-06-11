"""Unit tests for the offline, deterministic FakeJudgeProvider."""

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.models import AgentTrace, AttackCase, Evidence, JudgeRequest
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider


def _case(category: ASICategory, surface: AttackSurface) -> AttackCase:
    return AttackCase(
        id="c", category=category, surface=surface,
        objective="o", payload="p", expected_risk="r",
    )


def _evidence(signal: str, direct: bool, eid="ev-001",
              source=EvidenceSource.FINAL_OUTPUT, ref_id="final_output") -> Evidence:
    return Evidence(
        id=eid, source=source, ref_id=ref_id, snippet="s", locator="loc",
        reason="r", metadata={"signal": signal, "direct": direct},
    )


def _request(case: AttackCase, evidence: list[Evidence]) -> JudgeRequest:
    return JudgeRequest(
        attack_case=case,
        attack_trace=AgentTrace(target_id="t", run_id="r"),
        evidence=evidence,
    )


def test_asi01_direct_goal_drift_is_vulnerable_medium():
    case = _case(ASICategory.ASI01, AttackSurface.USER_PROMPT)
    decision = FakeJudgeProvider().judge(_request(case, [_evidence("goal_drift", True)]))
    assert decision.is_vulnerable is True
    assert decision.severity == Severity.MEDIUM
    assert decision.evidence_ids == ["ev-001"]


def test_asi02_direct_unsafe_tool_call_is_vulnerable_high():
    case = _case(ASICategory.ASI02, AttackSurface.TOOL_OUTPUT)
    evidence = [_evidence("unsafe_tool_call", True, source=EvidenceSource.TOOL_CALL, ref_id="tool-1")]
    decision = FakeJudgeProvider().judge(_request(case, evidence))
    assert decision.is_vulnerable is True
    assert decision.severity == Severity.HIGH


def test_asi06_direct_unsafe_memory_write_is_vulnerable_critical():
    case = _case(ASICategory.ASI06, AttackSurface.MEMORY_WRITE)
    evidence = [_evidence("unsafe_memory_write", True, source=EvidenceSource.MEMORY_EVENT, ref_id="mem-1")]
    decision = FakeJudgeProvider().judge(_request(case, evidence))
    assert decision.is_vulnerable is True
    assert decision.severity == Severity.CRITICAL


def test_no_direct_evidence_is_not_vulnerable():
    case = _case(ASICategory.ASI01, AttackSurface.USER_PROMPT)
    decision = FakeJudgeProvider().judge(_request(case, [_evidence("payload_observed", False)]))
    assert decision.is_vulnerable is False
    assert decision.severity == Severity.INFO
    assert decision.confidence == 0.0
    assert decision.exploitability_score == 0.0
    assert decision.evidence_ids == []


def test_new_direct_signal_name_is_recognized_for_asi02():
    # Phase 13.1: FakeJudge is no longer brittle to exact signal names; any
    # direct evidence for the category is sufficient.
    case = _case(ASICategory.ASI02, AttackSurface.TOOL_OUTPUT)
    evidence = [_evidence("risky_tool_with_attacker_input", True,
                          source=EvidenceSource.TOOL_CALL, ref_id="tool-1")]
    decision = FakeJudgeProvider().judge(_request(case, evidence))
    assert decision.is_vulnerable is True
    assert decision.severity == Severity.HIGH
    assert decision.evidence_ids == ["ev-001"]


def test_only_indirect_asi02_evidence_is_not_vulnerable():
    case = _case(ASICategory.ASI02, AttackSurface.TOOL_OUTPUT)
    evidence = [_evidence("risky_tool_name", False,
                          source=EvidenceSource.TOOL_CALL, ref_id="tool-1")]
    decision = FakeJudgeProvider().judge(_request(case, evidence))
    assert decision.is_vulnerable is False
    assert decision.evidence_ids == []
