"""Unit tests for AttackGenerator: capability-aware, deterministic expansion."""

from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import AttackCase, Capabilities, TargetConfig


def _generator(caps: Capabilities) -> AttackGenerator:
    config = TargetConfig(target_id="t", adapter_type="python_workflow", capabilities=caps)
    return AttackGenerator(config)


def test_generates_asi01_user_prompt_cases_by_default():
    cases = _generator(Capabilities()).generate(categories=[ASICategory.ASI01])
    assert cases
    assert all(c.category == ASICategory.ASI01 for c in cases)
    assert all(c.surface == AttackSurface.USER_PROMPT for c in cases)


def test_generates_asi02_tool_cases_when_tools_enabled():
    cases = _generator(Capabilities(tools=True)).generate(categories=[ASICategory.ASI02])
    surfaces = {c.surface for c in cases}
    assert AttackSurface.TOOL_OUTPUT in surfaces
    assert AttackSurface.TOOL_DEFINITION in surfaces


def test_does_not_generate_asi02_tool_output_when_tools_disabled():
    cases = _generator(Capabilities()).generate(categories=[ASICategory.ASI02])
    assert all(c.surface != AttackSurface.TOOL_OUTPUT for c in cases)


def test_generates_asi06_memory_cases_when_memory_enabled():
    cases = _generator(Capabilities(memory=True)).generate(categories=[ASICategory.ASI06])
    surfaces = {c.surface for c in cases}
    assert AttackSurface.MEMORY_WRITE in surfaces
    assert AttackSurface.MEMORY_READ in surfaces


def test_does_not_generate_asi06_memory_write_when_memory_disabled():
    cases = _generator(Capabilities()).generate(categories=[ASICategory.ASI06])
    assert all(c.surface != AttackSurface.MEMORY_WRITE for c in cases)


def test_respects_requested_categories():
    cases = _generator(Capabilities(tools=True, memory=True)).generate(
        categories=[ASICategory.ASI02]
    )
    assert {c.category for c in cases} == {ASICategory.ASI02}


def test_respects_max_cases():
    cases = _generator(Capabilities()).generate(categories=[ASICategory.ASI01], max_cases=2)
    assert len(cases) == 2


def test_ids_are_deterministic_and_stable():
    generator = _generator(Capabilities())
    first = generator.generate(categories=[ASICategory.ASI01])
    second = generator.generate(categories=[ASICategory.ASI01])
    assert [c.id for c in first] == [c.id for c in second]
    assert first[0].id == "asi01_goal_hijack__user_prompt__seed_001"


def test_every_generated_object_is_attack_case():
    cases = _generator(
        Capabilities(tools=True, memory=True, retrieval=True)
    ).generate()
    assert cases
    assert all(isinstance(c, AttackCase) for c in cases)


def test_metadata_includes_template_and_seed_ids():
    case = _generator(Capabilities()).generate(categories=[ASICategory.ASI01])[0]
    assert case.metadata["template_id"] == "asi01_goal_hijack"
    assert case.metadata["seed_id"] == "seed_001"
