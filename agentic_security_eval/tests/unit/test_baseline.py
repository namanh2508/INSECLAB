"""Unit tests for BaselineRunner: benign reference trace from both profiles."""

from agentic_security_eval.adapters.python_workflow import PythonWorkflowAdapter
from agentic_security_eval.core.models import AgentTrace, Capabilities, TargetConfig
from agentic_security_eval.evaluator.baseline import BASELINE_CASE, BaselineRunner

VULN_EP = "examples.fake_targets:create_vulnerable_agent"
HARD_EP = "examples.fake_targets:create_hardened_agent"


def _adapter(entrypoint: str) -> PythonWorkflowAdapter:
    config = TargetConfig(
        target_id="t", adapter_type="python_workflow", entrypoint=entrypoint,
        capabilities=Capabilities(tools=True, memory=True),
    )
    adapter = PythonWorkflowAdapter(config)
    adapter.setup()
    return adapter


def test_baseline_produces_agent_trace():
    trace = BaselineRunner(_adapter(VULN_EP)).run()
    assert isinstance(trace, AgentTrace)


def test_baseline_trace_has_baseline_case_id():
    trace = BaselineRunner(_adapter(VULN_EP)).run()
    assert trace.attack_case_id == "baseline__benign"
    assert BASELINE_CASE.metadata.get("baseline") is True


def test_baseline_trace_has_no_unsafe_tool_or_memory():
    for entrypoint in (VULN_EP, HARD_EP):
        trace = BaselineRunner(_adapter(entrypoint)).run()
        assert trace.tool_calls == []
        assert trace.memory_events == []
