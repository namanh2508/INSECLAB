"""The target adapter contract.

The evaluator only ever touches a target system through ``TargetAdapter``. It
never imports a concrete agent framework (LangGraph, CrewAI, AutoGen, n8n, ...).
An adapter drives the target with one ``AttackCase`` and returns a normalized
``AgentTrace``; normalizing raw target output into ``AgentTrace`` is the
adapter's job and the single boundary where untrusted target data is parsed.

The concrete ``PythonWorkflowAdapter`` lives in ``adapters/python_workflow.py``.
"""

from typing import Protocol, runtime_checkable

from agentic_security_eval.core.models import AgentTrace, AttackCase


@runtime_checkable
class TargetAdapter(Protocol):
    """Minimal contract every target system must satisfy to be evaluated.

    Adapters may additionally expose granular trace accessors used by a later
    normalization/evidence phase — these are optional and intentionally not part
    of the required contract::

        def get_messages(self) -> list[Message]: ...
        def get_tool_calls(self) -> list[ToolCall]: ...
        def get_memory_events(self) -> list[MemoryEvent]: ...
        def get_retrieval_events(self) -> list[RetrievalEvent]: ...
        def get_inter_agent_messages(self) -> list[InterAgentMessage]: ...
        def get_final_output(self) -> str: ...
    """

    def setup(self) -> None:
        """Initialize the target (load model, build graph, etc.)."""
        ...

    def reset(self) -> None:
        """Return the target to a clean state between scenarios."""
        ...

    def run_scenario(self, attack_case: AttackCase) -> None:
        """Drive the target with one attack case. Side-effecting."""
        ...

    def get_trace(self) -> AgentTrace:
        """Return the normalized trace of the last scenario."""
        ...
