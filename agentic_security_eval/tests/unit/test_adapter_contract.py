"""Phase 1 adapter-contract tests.

A minimal dummy adapter must satisfy the ``TargetAdapter`` protocol, and
``run_scenario`` must accept an ``AttackCase`` (not raw payload/surface).
"""

from agentic_security_eval.adapters.base import TargetAdapter
from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import AgentTrace, AttackCase


class DummyAdapter:
    """Minimal in-memory adapter implementing only the required contract."""

    def __init__(self) -> None:
        self.ready = False
        self.ran: list[str] = []

    def setup(self) -> None:
        self.ready = True

    def reset(self) -> None:
        self.ran = []

    def run_scenario(self, attack_case: AttackCase) -> None:
        self.ran.append(attack_case.id)

    def get_trace(self) -> AgentTrace:
        return AgentTrace(target_id="dummy", run_id="run-0", attack_case_id=self.ran[-1] if self.ran else None)


def make_case() -> AttackCase:
    return AttackCase(
        id="c1",
        category=ASICategory.ASI01,
        surface=AttackSurface.USER_PROMPT,
        objective="o",
        payload="p",
        expected_risk="r",
    )


def test_dummy_satisfies_target_adapter_protocol():
    assert isinstance(DummyAdapter(), TargetAdapter)


def test_run_scenario_accepts_attack_case_and_produces_trace():
    adapter = DummyAdapter()
    adapter.setup()
    adapter.reset()
    adapter.run_scenario(make_case())

    trace = adapter.get_trace()
    assert adapter.ready is True
    assert adapter.ran == ["c1"]
    assert isinstance(trace, AgentTrace)
    assert trace.attack_case_id == "c1"
