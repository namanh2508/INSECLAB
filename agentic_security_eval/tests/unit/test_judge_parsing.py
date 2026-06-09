"""Unit tests for strict parse_judge_decision at the judge-output boundary."""

import json

import pytest

from agentic_security_eval.core.errors import JudgeError
from agentic_security_eval.core.models import JudgeDecision
from agentic_security_eval.oracle.judge import parse_judge_decision

VALID = {
    "is_vulnerable": True,
    "category": "ASI01",
    "severity": "medium",
    "confidence": 0.85,
    "exploitability_score": 0.65,
    "evidence_ids": ["ev-001"],
    "explanation": "x",
    "recommendation": "y",
}


def test_valid_json_parses_into_judge_decision():
    decision = parse_judge_decision(json.dumps(VALID))
    assert isinstance(decision, JudgeDecision)
    assert decision.category.value == "ASI01"


def test_valid_dict_parses_into_judge_decision():
    assert isinstance(parse_judge_decision(dict(VALID)), JudgeDecision)


def test_invalid_json_raises_judge_error():
    with pytest.raises(JudgeError):
        parse_judge_decision("{not valid json")


def test_non_object_json_raises_judge_error():
    with pytest.raises(JudgeError):
        parse_judge_decision("[1, 2, 3]")


def test_missing_required_field_raises_judge_error():
    bad = dict(VALID)
    del bad["severity"]
    with pytest.raises(JudgeError):
        parse_judge_decision(bad)


def test_unknown_extra_key_raises_judge_error():
    bad = dict(VALID)
    bad["surprise"] = 1
    with pytest.raises(JudgeError):
        parse_judge_decision(bad)


@pytest.mark.parametrize("field,value", [("confidence", 1.5), ("exploitability_score", -0.1)])
def test_out_of_range_score_raises_judge_error(field, value):
    bad = dict(VALID)
    bad[field] = value
    with pytest.raises(JudgeError):
        parse_judge_decision(bad)
