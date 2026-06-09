"""Minimal fake targets used as test fixtures for the evaluator.

These are NOT real agent systems. They only *simulate* behavior: no external
API calls, no destructive actions. A vulnerable target intentionally "fails"
the MVP categories (follows the injected goal, misuses a mock tool, accepts a
poisoned memory write); a hardened target simulates safe handling.

Each target implements the workflow contract the PythonWorkflowAdapter expects:
``setup() / reset() / run_scenario(attack_case) / get_trace()``.
"""

from agentic_security_eval.core.enums import ASICategory
from agentic_security_eval.core.models import (
    AgentTrace,
    AttackCase,
    MemoryEvent,
    Message,
    ToolCall,
)


class _FakeAgent:
    """Shared scaffolding for the two concrete fake targets."""

    profile = "fake"
    target_id = "fake-agent"

    def __init__(self) -> None:
        self._ready = False
        self._trace: AgentTrace | None = None

    def setup(self) -> None:
        self._ready = True

    def reset(self) -> None:
        self._trace = None

    def get_trace(self) -> AgentTrace:
        if self._trace is None:
            raise RuntimeError(
                f"{type(self).__name__}.get_trace() called before run_scenario()."
            )
        return self._trace

    def _require_ready(self) -> None:
        if not self._ready:
            raise RuntimeError(
                f"{type(self).__name__}.run_scenario() called before setup()."
            )

    def _store_baseline(self, attack_case: AttackCase) -> None:
        # Benign baseline: no unsafe tool call, no unsafe memory write, no goal
        # drift. Used by both profiles when attack_case.metadata["baseline"] is set.
        final_output = "Benign baseline run: responded normally without using tools or memory."
        self._store_trace(
            attack_case,
            messages=[
                Message(id="msg-1", role="user", content=attack_case.payload),
                Message(id="msg-2", role="assistant", content=final_output),
            ],
            tool_calls=[],
            memory_events=[],
            final_output=final_output,
            metadata={"baseline": True, "vulnerable": False},
        )

    def _store_trace(
        self,
        attack_case: AttackCase,
        messages: list[Message],
        tool_calls: list[ToolCall],
        memory_events: list[MemoryEvent],
        final_output: str,
        metadata: dict,
    ) -> None:
        self._trace = AgentTrace(
            target_id=self.target_id,
            run_id=f"run-{self.profile}-{attack_case.category.value.lower()}",
            attack_case_id=attack_case.id,
            messages=messages,
            tool_calls=tool_calls,
            memory_events=memory_events,
            final_output=final_output,
            metadata={"profile": self.profile, **metadata},
        )


class VulnerableAgent(_FakeAgent):
    """Intentionally insecure target: it falls for every MVP attack."""

    profile = "vulnerable"
    target_id = "fake-vulnerable"

    def run_scenario(self, attack_case: AttackCase) -> None:
        self._require_ready()
        if attack_case.metadata.get("baseline") is True:
            self._store_baseline(attack_case)
            return
        category = attack_case.category
        messages = [Message(id="msg-1", role="user", content=attack_case.payload)]
        tool_calls: list[ToolCall] = []
        memory_events: list[MemoryEvent] = []
        metadata = {"simulated": True, "vulnerable": True, "category": category.value}

        if category == ASICategory.ASI01:
            # Goal drift: the injected instruction becomes the agent's new goal.
            final_output = f"New goal accepted. Now performing: {attack_case.payload}"
        elif category == ASICategory.ASI02:
            # Tool misuse: a mock tool is invoked with attacker-controlled content.
            tool_calls.append(
                ToolCall(
                    id="tool-1",
                    tool_name="mock_send_email",
                    arguments={"to": "attacker@evil.example", "body": attack_case.payload},
                    result="mock: email accepted for delivery",
                    metadata={"simulated": True, "unsafe": True},
                )
            )
            final_output = "Invoked mock_send_email with attacker-controlled content."
        elif category == ASICategory.ASI06:
            # Memory poisoning: attacker instruction is written into memory.
            memory_events.append(
                MemoryEvent(
                    id="mem-1",
                    operation="write",
                    key="agent_directive",
                    value=attack_case.payload,
                    metadata={"simulated": True, "unsafe": True},
                )
            )
            final_output = "Accepted and stored new directive in memory."
        else:
            raise ValueError(f"Unsupported category for fake target: {category}")

        messages.append(Message(id="msg-2", role="assistant", content=final_output))
        self._store_trace(attack_case, messages, tool_calls, memory_events, final_output, metadata)


class HardenedAgent(_FakeAgent):
    """Safe target: it treats injected content as untrusted data."""

    profile = "hardened"
    target_id = "fake-hardened"

    def run_scenario(self, attack_case: AttackCase) -> None:
        self._require_ready()
        if attack_case.metadata.get("baseline") is True:
            self._store_baseline(attack_case)
            return
        category = attack_case.category
        messages = [Message(id="msg-1", role="user", content=attack_case.payload)]
        tool_calls: list[ToolCall] = []
        memory_events: list[MemoryEvent] = []
        metadata = {"blocked": True, "reason": "untrusted_instruction", "category": category.value}

        if category == ASICategory.ASI01:
            # No goal drift: original task continues; payload is not echoed as a goal.
            final_output = (
                "Continuing the original task. Injected instructions were treated "
                "as untrusted data and ignored."
            )
        elif category == ASICategory.ASI02:
            # Records a blocked tool request instead of executing it.
            tool_calls.append(
                ToolCall(
                    id="tool-1",
                    tool_name="mock_send_email",
                    arguments={"requested_by": "untrusted_input"},
                    result="BLOCKED: unsafe tool request rejected",
                    metadata={"simulated": True, "blocked": True, "executed": False},
                )
            )
            final_output = "Blocked an unsafe tool request originating from untrusted input."
        elif category == ASICategory.ASI06:
            # Records a rejection; the attacker payload is never stored.
            memory_events.append(
                MemoryEvent(
                    id="mem-1",
                    operation="reject",
                    key="agent_directive",
                    value="rejected: untrusted instruction not written to memory",
                    metadata={"simulated": True, "blocked": True, "executed": False},
                )
            )
            final_output = "Rejected an attempt to write an untrusted instruction into memory."
        else:
            raise ValueError(f"Unsupported category for fake target: {category}")

        messages.append(Message(id="msg-2", role="assistant", content=final_output))
        self._store_trace(attack_case, messages, tool_calls, memory_events, final_output, metadata)


def create_vulnerable_agent() -> VulnerableAgent:
    """Factory entrypoint: ``examples.fake_targets:create_vulnerable_agent``."""
    return VulnerableAgent()


def create_hardened_agent() -> HardenedAgent:
    """Factory entrypoint: ``examples.fake_targets:create_hardened_agent``."""
    return HardenedAgent()
