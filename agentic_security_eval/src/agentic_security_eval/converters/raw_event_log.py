"""Generic raw agent-log schema and converter to TraceEvaluationInput.

A ``RawAgentLog`` is a convenience format: a flat list of typed ``RawEvent``s plus
the ``AttackCase`` under test. It saves users from hand-writing a full
``TraceEvaluationInput`` bundle. Loading is a boundary — bad file / JSON /
schema / event type fails fast with ``ConfigError``. This is intentionally
generic; real framework converters should target the same output shape.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, model_validator

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import (
    AgentTrace,
    AttackCase,
    InterAgentMessage,
    MemoryEvent,
    Message,
    RetrievalEvent,
    ToolCall,
    TraceEvaluationInput,
)

# event type -> field names that must be present on the raw event
_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "message": ("role", "content"),
    "tool_call": ("tool_name",),
    "memory_event": ("operation", "key"),
    "retrieval_event": ("source", "content"),
    "inter_agent_message": ("from_agent", "to_agent", "content"),
    "final_output": ("content",),
    "error": ("content",),
}


class RawEvent(BaseModel):
    """One event in a raw agent log. Only the fields for its ``type`` matter."""

    type: str
    id: str | None = None
    role: str | None = None
    content: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any | None = None
    operation: str | None = None
    key: str | None = None
    value: Any | None = None
    query: str | None = None
    source: str | None = None
    from_agent: str | None = None
    to_agent: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_type_and_required(self) -> "RawEvent":
        if self.type not in _REQUIRED_FIELDS:
            supported = ", ".join(sorted(_REQUIRED_FIELDS))
            raise ValueError(f"unsupported event type '{self.type}'; supported: {supported}.")
        missing = [name for name in _REQUIRED_FIELDS[self.type] if getattr(self, name) is None]
        if missing:
            raise ValueError(f"event type '{self.type}' requires field(s): {', '.join(missing)}.")
        return self


class RawAgentLog(BaseModel):
    """A simple raw agent log: metadata, the attack case, and a list of events."""

    target_id: str
    run_id: str
    scenario_id: str | None = None
    attack_case: AttackCase
    events: list[RawEvent] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


def load_raw_agent_log(path: str | Path) -> RawAgentLog:
    log_path = Path(path)
    if not log_path.is_file():
        raise ConfigError(f"Raw agent log not found: {log_path}")

    try:
        raw = json.loads(log_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in raw agent log '{log_path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Raw agent log '{log_path}' must be a JSON object at the top level.")

    try:
        return RawAgentLog.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid raw agent log '{log_path}': {exc}") from exc


# id-bearing event type -> generated-id prefix
_ID_PREFIXES = {
    "message": "msg",
    "tool_call": "tool",
    "memory_event": "mem",
    "retrieval_event": "retrieval",
    "inter_agent_message": "inter-agent",
}


def _assign_event_ids(events: list[RawEvent]) -> list[str | None]:
    """Return one stable id per id-bearing event (None for final_output/error).

    Explicit ids are preserved; missing ids are generated deterministically
    (``msg-1``, ``tool-1`` ...) and skip any id already taken by an explicit id
    or an earlier generated one. Duplicate explicit ids are invalid.
    """
    # Reserve every explicit id up front so generated ids can avoid them.
    used: set[str] = set()
    for event in events:
        if event.type in _ID_PREFIXES and event.id is not None:
            if event.id in used:
                raise ConfigError(f"Duplicate explicit event id in raw log: {event.id!r}.")
            used.add(event.id)

    counters: dict[str, int] = {}
    ids: list[str | None] = []
    for event in events:
        prefix = _ID_PREFIXES.get(event.type)
        if prefix is None:  # final_output / error carry no trace-element id
            ids.append(None)
            continue
        if event.id is not None:
            ids.append(event.id)
            continue
        counters[prefix] = counters.get(prefix, 0) + 1
        candidate = f"{prefix}-{counters[prefix]}"
        while candidate in used:
            counters[prefix] += 1
            candidate = f"{prefix}-{counters[prefix]}"
        used.add(candidate)
        ids.append(candidate)

    assigned = [event_id for event_id in ids if event_id is not None]
    if len(assigned) != len(set(assigned)):
        raise ConfigError("Generated event ids collided with explicit ids in the raw log.")
    return ids


def raw_log_to_trace_input(raw_log: RawAgentLog) -> TraceEvaluationInput:
    """Normalize a RawAgentLog into a TraceEvaluationInput bundle."""
    event_ids = _assign_event_ids(raw_log.events)

    messages: list[Message] = []
    tool_calls: list[ToolCall] = []
    memory_events: list[MemoryEvent] = []
    retrieval_events: list[RetrievalEvent] = []
    inter_agent_messages: list[InterAgentMessage] = []
    errors: list[str] = []
    final_output = ""
    final_output_count = 0

    for event, event_id in zip(raw_log.events, event_ids):
        if event.type == "message":
            messages.append(Message(
                id=event_id, role=event.role, content=event.content, metadata=event.metadata,
            ))
        elif event.type == "tool_call":
            tool_calls.append(ToolCall(
                id=event_id, tool_name=event.tool_name, arguments=event.arguments,
                result=event.result, metadata=event.metadata,
            ))
        elif event.type == "memory_event":
            memory_events.append(MemoryEvent(
                id=event_id, operation=event.operation, key=event.key,
                value=event.value, metadata=event.metadata,
            ))
        elif event.type == "retrieval_event":
            retrieval_events.append(RetrievalEvent(
                id=event_id, query=event.query, source=event.source,
                content=event.content, metadata=event.metadata,
            ))
        elif event.type == "inter_agent_message":
            inter_agent_messages.append(InterAgentMessage(
                id=event_id, from_agent=event.from_agent, to_agent=event.to_agent,
                content=event.content, metadata=event.metadata,
            ))
        elif event.type == "final_output":
            final_output = event.content
            final_output_count += 1
        else:  # "error" — the only remaining validated type
            errors.append(event.content)

    trace_metadata = dict(raw_log.metadata)
    if final_output_count > 1:
        trace_metadata["multiple_final_outputs"] = True

    attack_trace = AgentTrace(
        target_id=raw_log.target_id,
        run_id=raw_log.run_id,
        scenario_id=raw_log.scenario_id,
        attack_case_id=raw_log.attack_case.id,
        messages=messages,
        tool_calls=tool_calls,
        memory_events=memory_events,
        retrieval_events=retrieval_events,
        inter_agent_messages=inter_agent_messages,
        final_output=final_output,
        errors=errors,
        metadata=trace_metadata,
    )
    return TraceEvaluationInput(
        attack_case=raw_log.attack_case,
        attack_trace=attack_trace,
        metadata=raw_log.metadata,
    )
