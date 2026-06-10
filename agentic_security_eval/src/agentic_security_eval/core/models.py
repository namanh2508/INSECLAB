"""Core Pydantic schemas for the evaluator.

Everything the evaluator passes between stages is one of these typed models.
``AgentTrace`` is the central abstraction: every target system is normalized
into it before evaluation. ``Evidence`` is ID-grounded — it points at a concrete
trace element by ``ref_id`` — so a later deterministic validator can reject
judge claims that are not anchored in the trace.

Models are declared in dependency order so forward references resolve without
``model_rebuild()``.
"""

from typing import Any

from pydantic import BaseModel, Field, model_validator

from .enums import ASICategory, AttackSurface, EvidenceSource, Severity


# --------------------------------------------------------------------------- #
# Target configuration
# --------------------------------------------------------------------------- #
class Capabilities(BaseModel):
    """What a target can do — drives which attack surfaces are in scope."""

    tools: bool = False
    memory: bool = False
    retrieval: bool = False
    uploaded_files: bool = False
    inter_agent_messages: bool = False
    plugin_skill_metadata: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetConfig(BaseModel):
    """Declarative description of a target system the evaluator will probe."""

    target_id: str
    adapter_type: str
    entrypoint: str | None = None
    endpoint: str | None = None
    capabilities: Capabilities
    allowed_surfaces: list[AttackSurface] = Field(default_factory=list)
    policy_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Trace elements
# --------------------------------------------------------------------------- #
class Message(BaseModel):
    """A single conversational message in the trace."""

    id: str
    role: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A tool/function invocation made by the target."""

    id: str
    tool_name: str
    arguments: dict[str, Any]
    result: Any | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryEvent(BaseModel):
    """A read from or write to the target's memory store."""

    id: str
    operation: str
    key: str
    value: Any
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievalEvent(BaseModel):
    """A retrieval/RAG fetch of external content into the target's context."""

    id: str
    query: str | None = None
    source: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InterAgentMessage(BaseModel):
    """A message passed between two agents in a multi-agent target."""

    id: str
    from_agent: str
    to_agent: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTrace(BaseModel):
    """Normalized record of one target run. The central evaluator abstraction.

    Every target system, regardless of framework, is normalized into this shape
    by its adapter before any evaluation logic runs.
    """

    target_id: str
    run_id: str
    scenario_id: str | None = None
    attack_case_id: str | None = None
    messages: list[Message] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    memory_events: list[MemoryEvent] = Field(default_factory=list)
    retrieval_events: list[RetrievalEvent] = Field(default_factory=list)
    inter_agent_messages: list[InterAgentMessage] = Field(default_factory=list)
    final_output: str = ""
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Attack case
# --------------------------------------------------------------------------- #
class AttackCase(BaseModel):
    """One concrete attack to run against a target on a specific surface."""

    id: str
    category: ASICategory
    surface: AttackSurface
    objective: str
    payload: str
    expected_risk: str
    surface_policy: str | None = None
    tags: list[str] = Field(default_factory=list)
    mutation_parent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Oracle: evidence, judge request/decision, finding
# --------------------------------------------------------------------------- #
class Evidence(BaseModel):
    """An ID-grounded pointer into the trace supporting a finding.

    ``ref_id`` is the ``id`` of the trace element (Message, ToolCall, ...) this
    evidence is drawn from; ``locator`` is a human-readable path to it.
    """

    id: str
    source: EvidenceSource
    ref_id: str
    snippet: str
    locator: str
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class JudgeRequest(BaseModel):
    """Everything an LLM judge needs to rule on a single attack."""

    attack_case: AttackCase
    baseline_trace: AgentTrace | None = None
    attack_trace: AgentTrace
    evidence: list[Evidence]
    category_policy: str | None = None
    surface_policy: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class JudgeDecision(BaseModel):
    """Raw, not-yet-trusted verdict returned by a judge provider."""

    is_vulnerable: bool
    category: ASICategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    exploitability_score: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str]
    explanation: str
    recommendation: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A validated vulnerability finding built from a JudgeDecision."""

    id: str
    attack_case_id: str
    category: ASICategory
    surface: AttackSurface
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    exploitability_score: float = Field(ge=0.0, le=1.0)
    is_vulnerable: bool
    evidence: list[Evidence]
    explanation: str
    recommendation: str
    trace_snippet: list[dict[str, Any]] = Field(default_factory=list)
    validator_notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
class CategorySummary(BaseModel):
    """Per-category roll-up of cases and findings for the report."""

    total_cases: int = 0
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


class EvalReport(BaseModel):
    """Top-level JSON report — the primary output of the evaluator."""

    schema_version: str = "0.1.0"
    report_id: str
    target_id: str
    total_cases: int
    total_findings: int
    tested_categories: list[ASICategory]
    tested_surfaces: list[AttackSurface]
    findings: list[Finding]
    category_summary: dict[str, CategorySummary] = Field(default_factory=dict)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    surface_summary: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Trace evaluation input (canonical ingestion contract)
# --------------------------------------------------------------------------- #
class TraceEvaluationInput(BaseModel):
    """A pre-recorded trace bundle the evaluator can assess without a live target.

    This is the canonical ingestion contract: external agent systems (or their
    converters) normalize into this shape before evaluation.
    """

    attack_case: AttackCase
    attack_trace: AgentTrace
    baseline_trace: AgentTrace | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_attack_case_id(self) -> "TraceEvaluationInput":
        trace_case_id = self.attack_trace.attack_case_id
        if trace_case_id is not None and trace_case_id != self.attack_case.id:
            raise ValueError(
                f"attack_trace.attack_case_id ({trace_case_id!r}) must equal "
                f"attack_case.id ({self.attack_case.id!r})."
            )
        return self
