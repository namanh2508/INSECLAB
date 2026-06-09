"""Phase 1 judge-contract tests.

A minimal dummy judge must satisfy the ``JudgeProvider`` protocol and return a
``JudgeDecision`` for a ``JudgeRequest``. No real LLM calls in Phase 1.
"""

from agentic_security_eval.core.enums import ASICategory, AttackSurface, Severity
from agentic_security_eval.core.models import (
    AgentTrace,
    AttackCase,
    JudgeDecision,
    JudgeRequest,
)
from agentic_security_eval.oracle.judge import JudgeProvider


class DummyJudge:
    """Minimal judge implementing only the required contract."""

    name = "dummy"

    def judge(self, request: JudgeRequest) -> JudgeDecision:
        return JudgeDecision(
            is_vulnerable=False,
            category=request.attack_case.category,
            severity=Severity.INFO,
            confidence=0.0,
            exploitability_score=0.0,
            evidence_ids=[],
            explanation="dummy verdict",
            recommendation="none",
        )


def make_request() -> JudgeRequest:
    case = AttackCase(
        id="c1",
        category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT,
        objective="o",
        payload="p",
        expected_risk="r",
    )
    return JudgeRequest(
        attack_case=case,
        attack_trace=AgentTrace(target_id="t", run_id="run-1"),
        evidence=[],
    )


def test_dummy_satisfies_judge_provider_protocol():
    assert isinstance(DummyJudge(), JudgeProvider)


def test_dummy_judge_returns_decision_for_request():
    decision = DummyJudge().judge(make_request())
    assert isinstance(decision, JudgeDecision)
    assert decision.category == ASICategory.ASI02
    assert decision.is_vulnerable is False
