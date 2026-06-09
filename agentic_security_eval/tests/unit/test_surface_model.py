"""Unit tests for AttackSurfaceModel capability filtering and allow-listing."""

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import Capabilities, TargetConfig
from agentic_security_eval.surfaces.model import AttackSurfaceModel

FULL_CAPS = Capabilities(
    tools=True,
    memory=True,
    retrieval=True,
    uploaded_files=True,
    inter_agent_messages=True,
    plugin_skill_metadata=True,
)


def _model(caps: Capabilities, allowed=None) -> AttackSurfaceModel:
    config = TargetConfig(
        target_id="t",
        adapter_type="python_workflow",
        capabilities=caps,
        allowed_surfaces=allowed or [],
    )
    return AttackSurfaceModel(config)


def test_user_prompt_always_available_without_capabilities():
    model = _model(Capabilities())
    assert AttackSurface.USER_PROMPT in model.surfaces_for(ASICategory.ASI01)
    assert AttackSurface.USER_PROMPT in model.surfaces_for(ASICategory.ASI02)


def test_tools_capability_enables_tool_surfaces():
    surfaces = _model(Capabilities(tools=True)).surfaces_for(ASICategory.ASI02)
    assert AttackSurface.TOOL_OUTPUT in surfaces
    assert AttackSurface.TOOL_DEFINITION in surfaces


def test_memory_capability_enables_memory_surfaces():
    surfaces = _model(Capabilities(memory=True)).surfaces_for(ASICategory.ASI06)
    assert AttackSurface.MEMORY_READ in surfaces
    assert AttackSurface.MEMORY_WRITE in surfaces


def test_retrieval_capability_enables_retrieved_web_content():
    surfaces = _model(Capabilities(retrieval=True)).surfaces_for(ASICategory.ASI01)
    assert AttackSurface.RETRIEVED_WEB_CONTENT in surfaces


def test_uploaded_files_capability_enables_uploaded_file_document():
    surfaces = _model(Capabilities(uploaded_files=True)).surfaces_for(ASICategory.ASI01)
    assert AttackSurface.UPLOADED_FILE_DOCUMENT in surfaces


def test_inter_agent_messages_capability_enables_inter_agent_message():
    surfaces = _model(Capabilities(inter_agent_messages=True)).surfaces_for(ASICategory.ASI01)
    assert AttackSurface.INTER_AGENT_MESSAGE in surfaces


def test_allowed_surfaces_restricts_emitted_surfaces():
    model = _model(FULL_CAPS, allowed=[AttackSurface.USER_PROMPT])
    # ASI01 has user_prompt in its default mapping -> only that survives.
    assert model.surfaces_for(ASICategory.ASI01) == [AttackSurface.USER_PROMPT]
    # ASI06 has no user_prompt in its mapping -> allow-list removes everything.
    assert model.surfaces_for(ASICategory.ASI06) == []


def test_system_prompt_not_selected_by_default():
    model = _model(FULL_CAPS)
    for category in ASICategory:
        assert AttackSurface.SYSTEM_PROMPT not in model.surfaces_for(category)


def test_surfaces_by_category_covers_requested_categories():
    result = _model(Capabilities(tools=True)).surfaces_by_category(
        [ASICategory.ASI01, ASICategory.ASI02]
    )
    assert set(result.keys()) == {ASICategory.ASI01, ASICategory.ASI02}
    assert all(
        isinstance(surface, AttackSurface)
        for surfaces in result.values()
        for surface in surfaces
    )
