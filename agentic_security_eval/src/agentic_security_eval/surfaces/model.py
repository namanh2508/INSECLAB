"""AttackSurfaceModel — which attack surfaces are in scope for a target.

Each ASI category has a default, ordered list of candidate surfaces. A surface
is selected only if (a) the target's ``Capabilities`` support it and (b) — when
``TargetConfig.allowed_surfaces`` is non-empty — it is on that allow-list. The
default mapping is never widened; surfaces outside a category's mapping are
never emitted (including ``system_prompt``, which is out of scope for the MVP).
"""

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import Capabilities, TargetConfig

# Default, ordered candidate surfaces per category.
DEFAULT_CATEGORY_SURFACES: dict[ASICategory, list[AttackSurface]] = {
    ASICategory.ASI01: [
        AttackSurface.USER_PROMPT,
        AttackSurface.RETRIEVED_WEB_CONTENT,
        AttackSurface.UPLOADED_FILE_DOCUMENT,
        AttackSurface.TOOL_OUTPUT,
        AttackSurface.INTER_AGENT_MESSAGE,
        AttackSurface.CONTEXT_EXTENSION,
    ],
    ASICategory.ASI02: [
        AttackSurface.TOOL_OUTPUT,
        AttackSurface.TOOL_DEFINITION,
        AttackSurface.PLUGIN_SKILL_METADATA,
        AttackSurface.INTER_AGENT_MESSAGE,
        AttackSurface.USER_PROMPT,
    ],
    ASICategory.ASI06: [
        AttackSurface.MEMORY_WRITE,
        AttackSurface.MEMORY_READ,
        AttackSurface.RETRIEVED_WEB_CONTENT,
        AttackSurface.INTER_AGENT_MESSAGE,
        AttackSurface.CONTEXT_EXTENSION,
    ],
}

# A surface is available if ANY of its required capability flags is set.
# An empty tuple means "always available" (no capability required).
# Surfaces absent from this map are never selected by default (e.g. system_prompt).
_SURFACE_REQUIREMENTS: dict[AttackSurface, tuple[str, ...]] = {
    AttackSurface.USER_PROMPT: (),
    AttackSurface.RETRIEVED_WEB_CONTENT: ("retrieval",),
    AttackSurface.UPLOADED_FILE_DOCUMENT: ("uploaded_files",),
    AttackSurface.TOOL_OUTPUT: ("tools",),
    AttackSurface.TOOL_DEFINITION: ("tools",),
    AttackSurface.MEMORY_READ: ("memory",),
    AttackSurface.MEMORY_WRITE: ("memory",),
    AttackSurface.PLUGIN_SKILL_METADATA: ("plugin_skill_metadata",),
    AttackSurface.INTER_AGENT_MESSAGE: ("inter_agent_messages",),
    AttackSurface.CONTEXT_EXTENSION: ("retrieval", "memory", "inter_agent_messages"),
}


def _is_supported(surface: AttackSurface, capabilities: Capabilities) -> bool:
    if surface not in _SURFACE_REQUIREMENTS:
        return False
    required = _SURFACE_REQUIREMENTS[surface]
    if not required:
        return True
    return any(getattr(capabilities, attr) for attr in required)


class AttackSurfaceModel:
    """Selects in-scope attack surfaces for a target, per category."""

    def __init__(self, config: TargetConfig) -> None:
        self.capabilities = config.capabilities
        self.allowed = set(config.allowed_surfaces)

    def surfaces_for(self, category: ASICategory) -> list[AttackSurface]:
        selected = []
        for surface in DEFAULT_CATEGORY_SURFACES[category]:
            if not _is_supported(surface, self.capabilities):
                continue
            if self.allowed and surface not in self.allowed:
                continue
            selected.append(surface)
        return selected

    def surfaces_by_category(
        self, categories: list[ASICategory] | None = None
    ) -> dict[ASICategory, list[AttackSurface]]:
        categories = categories or list(DEFAULT_CATEGORY_SURFACES.keys())
        return {category: self.surfaces_for(category) for category in categories}
