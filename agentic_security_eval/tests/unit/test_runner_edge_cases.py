"""Edge-case tests for EvaluatorRunner: empty input and fail-fast propagation.

Uses minimal in-test dummies (no real fake targets) so the runner's control flow
is exercised in isolation.
"""

import pytest

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.errors import AdapterError, JudgeError
from agentic_security_eval.core.models import AgentTrace, AttackCase, JudgeRequest
from agentic_security_eval.evaluator.runner import EvaluatorRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter


class _DummyAdapter:
    """Minimal adapter that returns a benign trace; can fail on attack cases."""

    def __init__(self, fail_on_attack: bool = False) -> None:
        self._fail_on_attack = fail_on_attack
        self._last_case: AttackCase | None = None

    def setup(self) -> None:
        pass

    def reset(self) -> None:
        self._last_case = None

    def run_scenario(self, attack_case: AttackCase) -> None:
        if self._fail_on_attack and attack_case.metadata.get("baseline") is not True:
            raise AdapterError("dummy adapter failure")
        self._last_case = attack_case

    def get_trace(self) -> AgentTrace:
        case_id = self._last_case.id if self._last_case else "none"
        return AgentTrace(target_id="dummy", run_id="run-dummy", attack_case_id=case_id, final_output="ok")


class _RaisingJudge:
    """Judge that always fails, to test fail-fast propagation."""

    name = "raising"

    def judge(self, request: JudgeRequest):
        raise JudgeError("dummy judge failure")


def _case() -> AttackCase:
    return AttackCase(
        id="case-1", category=ASICategory.ASI01, surface=AttackSurface.USER_PROMPT,
        objective="o", payload="p", expected_risk="r",
    )


def test_empty_cases_returns_valid_empty_report():
    report = EvaluatorRunner("t", _DummyAdapter(), FakeJudgeProvider()).run([])
    assert report.total_cases == 0
    assert report.total_findings == 0
    assert report.findings == []
    # a valid empty report must still serialize
    assert JsonReportWriter().to_json(report)


def test_runner_fails_fast_on_judge_error():
    runner = EvaluatorRunner("t", _DummyAdapter(), _RaisingJudge())
    with pytest.raises(JudgeError):
        runner.run([_case()])


def test_runner_fails_fast_on_adapter_error():
    runner = EvaluatorRunner("t", _DummyAdapter(fail_on_attack=True), FakeJudgeProvider())
    with pytest.raises(AdapterError):
        runner.run([_case()])
