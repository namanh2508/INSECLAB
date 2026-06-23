"""Fixture-shape tests for framework-converter fixtures (Phase 14.4.0).

No conversion logic is implemented or exercised here. These tests only validate that
the shipped framework-converter fixtures parse against existing schemas. Real
LangGraph message-export fixtures are NOT yet collected (see
``docs/framework_converters.md``); only the paired AttackCase fixture — which uses our
own ``AttackCase`` schema, not a guessed framework shape — is validated.
"""

import json
from pathlib import Path

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import AttackCase

ATTACK_CASES = Path(__file__).resolve().parents[2] / "examples" / "attack_cases"


def test_langgraph_tool_attack_case_fixture_is_valid_attack_case():
    data = json.loads((ATTACK_CASES / "langgraph_tool_case.json").read_text(encoding="utf-8"))
    case = AttackCase.model_validate(data)
    assert case.category is ASICategory.ASI02
    assert case.surface is AttackSurface.TOOL_OUTPUT
    # The case is self-contained: category/surface/payload are declared, never inferred.
    assert case.objective and case.payload and case.expected_risk
