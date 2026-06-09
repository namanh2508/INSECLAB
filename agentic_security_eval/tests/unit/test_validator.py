"""Unit tests for DeterministicValidator: grounding, category, and severity rules."""

import pytest
from pydantic import ValidationError

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.models import AttackCase, Evidence, JudgeDecision
from agentic_security_eval.oracle.validator import DeterministicValidator

validator = DeterministicValidator()


def _case(category: ASICategory = ASICategory.ASI02) -> AttackCase:
    return AttackCase(
        id="c", category=category, surface=AttackSurface.TOOL_OUTPUT,
        objective="o", payload="p", expected_risk="r",
    )


def _evidence(eid: str, direct: bool, signal: str = "unsafe_tool_call") -> Evidence:
    return Evidence(
        id=eid, source=EvidenceSource.TOOL_CALL, ref_id="tool-1", snippet="s",
        locator="l", reason="r", metadata={"signal": signal, "direct": direct},
    )


def _decision(category=ASICategory.ASI02, severity=Severity.HIGH,
              evidence_ids=("ev-001",), is_vulnerable=True,
              confidence=0.9, exploit=0.8) -> JudgeDecision:
    return JudgeDecision(
        is_vulnerable=is_vulnerable, category=category, severity=severity,
        confidence=confidence, exploitability_score=exploit,
        evidence_ids=list(evidence_ids), explanation="x", recommendation="y",
    )


def test_accepts_valid_grounded_decision():
    out, notes = validator.validate(_decision(), _case(), [_evidence("ev-001", True)])
    assert out is not None
    assert out.severity == Severity.HIGH
    assert out.evidence_ids == ["ev-001"]


def test_rejects_category_mismatch():
    out, notes = validator.validate(
        _decision(category=ASICategory.ASI01), _case(ASICategory.ASI02), [_evidence("ev-001", True)]
    )
    assert out is None
    assert notes


def test_removes_invalid_evidence_ids():
    out, notes = validator.validate(
        _decision(evidence_ids=("ev-001", "ev-999")), _case(), [_evidence("ev-001", True)]
    )
    assert out is not None
    assert out.evidence_ids == ["ev-001"]
    assert any("ev-999" in n for n in notes)


def test_rejects_vulnerable_decision_with_no_valid_evidence():
    out, notes = validator.validate(
        _decision(evidence_ids=("ev-999",)), _case(), [_evidence("ev-001", True)]
    )
    assert out is None
    assert notes


def test_downgrades_high_without_direct_evidence():
    out, notes = validator.validate(
        _decision(severity=Severity.HIGH, evidence_ids=("ev-001",)),
        _case(),
        [_evidence("ev-001", False)],
    )
    assert out is not None
    assert out.severity == Severity.MEDIUM
    assert any("direct" in n.lower() for n in notes)


def test_not_vulnerable_decision_passes_through():
    out, notes = validator.validate(
        _decision(is_vulnerable=False, severity=Severity.INFO, evidence_ids=()), _case(), []
    )
    assert out is not None
    assert out.is_vulnerable is False


def test_does_not_duplicate_pydantic_range_checks():
    # Out-of-range scores already fail at the model boundary, so the validator
    # never needs to re-check them.
    with pytest.raises(ValidationError):
        _decision(confidence=1.5)
