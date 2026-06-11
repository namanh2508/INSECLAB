"""Surface-to-evidence coverage matrix — a static, conservative source of truth.

Attack *surfaces* are generated inputs (`surfaces/model.py` + `attacks/`); evidence
*depth* is what the deterministic evaluator can actually produce for an attack on a
given surface. They are not the same: the generator can emit cases on surfaces the
deterministic evidence layer does not deeply evaluate yet.

This matrix records, per ``(category, surface)``, the strongest deterministic support
that exists TODAY. It is intentionally conservative and adds NO detector logic.

Levels:

- ``direct``          a category-specific DIRECT signal is produced for attacks on this
                      surface (these can ground high/critical findings via the validator).
- ``indirect``        only context/indirect signals are produced; they cannot ground a
                      high/critical finding on their own.
- ``generation_only`` the generator emits the case, but no dedicated direct or
                      meaningful indirect signal exists for it yet.
- ``unsupported``     not generated for this category / not represented.

Direct evidence is read from a category's *outcome* channel (ASI01: ``final_output``,
ASI02: ``tool_calls``, ASI06: ``memory_events`` writes). A non-direct surface may still
be caught if the attack manifests in that outcome channel downstream, but the surface
itself has no dedicated detector — hence the conservative level. When in doubt this
matrix uses ``indirect`` or ``generation_only``, never ``direct``.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from agentic_security_eval.core.enums import ASICategory, AttackSurface


class CoverageLevel(str, Enum):
    """How well the deterministic evidence layer supports a category/surface today."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    GENERATION_ONLY = "generation_only"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class SurfaceCoverage:
    """Deterministic-evidence support for one (category, surface) pair."""

    category: ASICategory
    surface: AttackSurface
    level: CoverageLevel
    trace_channels: tuple[str, ...] = ()
    direct_signals: tuple[str, ...] = ()
    indirect_signals: tuple[str, ...] = ()
    notes: str = ""


_ASI01_DIRECT = ("goal_drift", "attacker_goal_accepted")
_ASI02_DIRECT = ("unsafe_tool_call", "risky_tool_with_attacker_input")
_ASI02_INDIRECT = (
    "risky_tool_name", "payload_reached_tool_argument",
    "payload_reached_tool_result", "risky_tool_call_blocked",
)
_ASI06_DIRECT = ("unsafe_memory_write", "policy_or_identity_override_persisted")

# Static matrix: exactly the (category, surface) pairs the generator can emit
# (DEFAULT_CATEGORY_SURFACES intersected with the attack templates). Verified by
# test_surface_coverage.test_matrix_covers_every_generated_pair.
_MATRIX: tuple[SurfaceCoverage, ...] = (
    # ----- ASI01 (goal hijack); direct evidence read from final_output -----
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.USER_PROMPT, CoverageLevel.DIRECT,
        trace_channels=("messages", "final_output"),
        direct_signals=_ASI01_DIRECT,
        indirect_signals=("payload_observed", "attacker_goal_refused", "final_output_observed"),
        notes="Canonical goal-hijack injection; direct evidence is read from final_output.",
    ),
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.RETRIEVED_WEB_CONTENT, CoverageLevel.INDIRECT,
        trace_channels=("retrieval_events",),
        indirect_signals=("suspicious_retrieval_content",),
        notes="Observed as context; a resulting final_output goal drift is still caught, "
              "but there is no retrieval-specific direct rule.",
    ),
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.INTER_AGENT_MESSAGE, CoverageLevel.INDIRECT,
        trace_channels=("inter_agent_messages",),
        indirect_signals=("suspicious_inter_agent_message",),
        notes="Observed as context only; no inter-agent direct rule yet.",
    ),
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.TOOL_OUTPUT, CoverageLevel.GENERATION_ONLY,
        notes="tool_calls are mined only by ASI02 rules; an ASI01 attack via tool output "
              "has no dedicated detector.",
    ),
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.UPLOADED_FILE_DOCUMENT, CoverageLevel.GENERATION_ONLY,
        notes="No AgentTrace channel carries uploaded-file content; generated but not observed.",
    ),
    SurfaceCoverage(
        ASICategory.ASI01, AttackSurface.CONTEXT_EXTENSION, CoverageLevel.GENERATION_ONLY,
        notes="No dedicated AgentTrace channel; generated but not directly observed.",
    ),
    # ----- ASI02 (tool misuse); direct evidence read from tool_calls -----
    SurfaceCoverage(
        ASICategory.ASI02, AttackSurface.TOOL_OUTPUT, CoverageLevel.DIRECT,
        trace_channels=("tool_calls",),
        direct_signals=_ASI02_DIRECT,
        indirect_signals=_ASI02_INDIRECT,
        notes="Primary ASI02 surface; direct evidence from tool_calls "
              "(self-label, or risky tool invoked with attacker-influenced input).",
    ),
    SurfaceCoverage(
        ASICategory.ASI02, AttackSurface.USER_PROMPT, CoverageLevel.INDIRECT,
        trace_channels=("messages",),
        indirect_signals=("payload_observed",),
        notes="Observed as context; a resulting risky tool_call is still caught by the "
              "tool_calls direct rule.",
    ),
    SurfaceCoverage(
        ASICategory.ASI02, AttackSurface.INTER_AGENT_MESSAGE, CoverageLevel.INDIRECT,
        trace_channels=("inter_agent_messages",),
        indirect_signals=("suspicious_inter_agent_message",),
        notes="Observed as context only.",
    ),
    SurfaceCoverage(
        ASICategory.ASI02, AttackSurface.TOOL_DEFINITION, CoverageLevel.GENERATION_ONLY,
        notes="No AgentTrace channel for tool definitions; only a resulting tool_call, if any, "
              "is evaluated.",
    ),
    SurfaceCoverage(
        ASICategory.ASI02, AttackSurface.PLUGIN_SKILL_METADATA, CoverageLevel.GENERATION_ONLY,
        notes="No AgentTrace channel for plugin/skill metadata.",
    ),
    # ----- ASI06 (memory/context poisoning); direct evidence from memory writes -----
    SurfaceCoverage(
        ASICategory.ASI06, AttackSurface.MEMORY_WRITE, CoverageLevel.DIRECT,
        trace_channels=("memory_events",),
        direct_signals=_ASI06_DIRECT,
        indirect_signals=("instruction_like_content_persisted",),
        notes="Primary ASI06 surface; direct evidence from memory write events.",
    ),
    SurfaceCoverage(
        ASICategory.ASI06, AttackSurface.RETRIEVED_WEB_CONTENT, CoverageLevel.INDIRECT,
        trace_channels=("retrieval_events",),
        indirect_signals=("suspicious_retrieval_content",),
        notes="Observed as context only.",
    ),
    SurfaceCoverage(
        ASICategory.ASI06, AttackSurface.INTER_AGENT_MESSAGE, CoverageLevel.INDIRECT,
        trace_channels=("inter_agent_messages",),
        indirect_signals=("suspicious_inter_agent_message",),
        notes="Observed as context only.",
    ),
    SurfaceCoverage(
        ASICategory.ASI06, AttackSurface.MEMORY_READ, CoverageLevel.GENERATION_ONLY,
        trace_channels=("memory_events",),
        notes="The ASI06 rule classifies write operations only; read operations produce no signal.",
    ),
    SurfaceCoverage(
        ASICategory.ASI06, AttackSurface.CONTEXT_EXTENSION, CoverageLevel.GENERATION_ONLY,
        notes="No dedicated AgentTrace channel.",
    ),
)


def list_surface_coverage() -> list[SurfaceCoverage]:
    """Return every known (category, surface) coverage entry."""
    return list(_MATRIX)


def get_surface_coverage(category: ASICategory, surface: AttackSurface) -> SurfaceCoverage:
    """Return coverage for one pair; UNSUPPORTED if the pair is not generated."""
    for entry in _MATRIX:
        if entry.category == category and entry.surface == surface:
            return entry
    return SurfaceCoverage(
        category=category, surface=surface, level=CoverageLevel.UNSUPPORTED,
        notes="Not generated for this category; no deterministic coverage.",
    )


def coverage_matrix_as_dict() -> dict[str, Any]:
    """Serialize the matrix to plain JSON-compatible data."""
    return {
        "schema_version": "0.1",
        "levels": [level.value for level in CoverageLevel],
        "entries": [_entry_as_dict(entry) for entry in _MATRIX],
    }


def _entry_as_dict(entry: SurfaceCoverage) -> dict[str, Any]:
    return {
        "category": entry.category.value,
        "surface": entry.surface.value,
        "level": entry.level.value,
        "trace_channels": list(entry.trace_channels),
        "direct_signals": list(entry.direct_signals),
        "indirect_signals": list(entry.indirect_signals),
        "notes": entry.notes,
    }
