"""Unit tests for the surface-to-evidence coverage matrix."""

import json

from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import Capabilities, TargetConfig
from agentic_security_eval.surfaces.coverage import (
    CoverageLevel,
    SurfaceCoverage,
    coverage_matrix_as_dict,
    get_surface_coverage,
    list_surface_coverage,
)

_ALL_CAPS = Capabilities(
    tools=True, memory=True, retrieval=True,
    uploaded_files=True, inter_agent_messages=True, plugin_skill_metadata=True,
)


def _generated_pairs() -> set[tuple[ASICategory, AttackSurface]]:
    config = TargetConfig(target_id="t", adapter_type="python_workflow", capabilities=_ALL_CAPS)
    cases = AttackGenerator(config).generate(
        categories=[ASICategory.ASI01, ASICategory.ASI02, ASICategory.ASI06]
    )
    return {(case.category, case.surface) for case in cases}


def test_matrix_covers_exactly_every_generated_pair():
    matrix_pairs = {(e.category, e.surface) for e in list_surface_coverage()}
    assert matrix_pairs == _generated_pairs()


def test_asi01_user_prompt_is_direct():
    cov = get_surface_coverage(ASICategory.ASI01, AttackSurface.USER_PROMPT)
    assert cov.level is CoverageLevel.DIRECT
    assert "goal_drift" in cov.direct_signals
    assert "attacker_goal_accepted" in cov.direct_signals


def test_asi02_tool_output_is_direct():
    cov = get_surface_coverage(ASICategory.ASI02, AttackSurface.TOOL_OUTPUT)
    assert cov.level is CoverageLevel.DIRECT
    assert "risky_tool_with_attacker_input" in cov.direct_signals


def test_asi06_memory_write_is_direct():
    cov = get_surface_coverage(ASICategory.ASI06, AttackSurface.MEMORY_WRITE)
    assert cov.level is CoverageLevel.DIRECT
    assert "unsafe_memory_write" in cov.direct_signals


def test_non_native_surfaces_are_not_falsely_direct():
    # retrieval / inter-agent / uploaded-file / tool-definition / plugin-metadata must
    # NOT be marked direct, since no dedicated direct rule evaluates them today.
    not_direct = [
        (ASICategory.ASI01, AttackSurface.RETRIEVED_WEB_CONTENT),
        (ASICategory.ASI01, AttackSurface.UPLOADED_FILE_DOCUMENT),
        (ASICategory.ASI01, AttackSurface.INTER_AGENT_MESSAGE),
        (ASICategory.ASI02, AttackSurface.TOOL_DEFINITION),
        (ASICategory.ASI02, AttackSurface.PLUGIN_SKILL_METADATA),
        (ASICategory.ASI02, AttackSurface.INTER_AGENT_MESSAGE),
        (ASICategory.ASI06, AttackSurface.RETRIEVED_WEB_CONTENT),
        (ASICategory.ASI06, AttackSurface.INTER_AGENT_MESSAGE),
        (ASICategory.ASI06, AttackSurface.MEMORY_READ),
    ]
    for category, surface in not_direct:
        cov = get_surface_coverage(category, surface)
        assert cov.level is not CoverageLevel.DIRECT
        assert not cov.direct_signals


def test_get_surface_coverage_returns_stable_object():
    cov = get_surface_coverage(ASICategory.ASI02, AttackSurface.TOOL_OUTPUT)
    assert isinstance(cov, SurfaceCoverage)
    assert cov.category is ASICategory.ASI02
    assert cov.surface is AttackSurface.TOOL_OUTPUT
    assert cov.level.value == "direct"
    assert cov.trace_channels == ("tool_calls",)


def test_get_surface_coverage_unknown_pair_is_unsupported():
    cov = get_surface_coverage(ASICategory.ASI01, AttackSurface.MEMORY_WRITE)
    assert cov.level is CoverageLevel.UNSUPPORTED


def test_coverage_matrix_as_dict_round_trips_and_has_all_levels():
    data = coverage_matrix_as_dict()
    assert json.loads(json.dumps(data)) == data  # JSON-serializable
    levels = {entry["level"] for entry in data["entries"]}
    assert {"direct", "indirect", "generation_only"} <= levels
