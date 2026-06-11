"""Structural guard for the category-gating invariant.

Rule classifiers must NOT accept a ``category`` (or ``attack_case``) parameter.
Category-gating is owned by ``EvidenceExtractor``; a classifier that could see the
category might re-couple the load-bearing invariant that lets FakeJudgeProvider
trust any direct evidence.
"""

import inspect

from agentic_security_eval.oracle.evidence_rules.asi02_tool_misuse import classify_asi02_tool_call
from agentic_security_eval.oracle.evidence_rules.asi06_memory_poisoning import classify_asi06_memory_event


def test_classifiers_do_not_accept_category_parameter():
    for fn in (classify_asi02_tool_call, classify_asi06_memory_event):
        params = set(inspect.signature(fn).parameters)
        assert "category" not in params, f"{fn.__name__} must not take a category"
        assert "attack_case" not in params, f"{fn.__name__} must not take an attack_case"
