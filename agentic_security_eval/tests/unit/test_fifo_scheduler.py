"""Unit tests for FifoScheduler order preservation and empty-queue behavior."""

import pytest

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import AttackCase
from agentic_security_eval.scheduler.fifo import FifoScheduler


def _case(index: int) -> AttackCase:
    return AttackCase(
        id=f"case-{index}",
        category=ASICategory.ASI01,
        surface=AttackSurface.USER_PROMPT,
        objective="o",
        payload="p",
        expected_risk="r",
    )


def test_preserves_order():
    cases = [_case(i) for i in range(5)]
    scheduler = FifoScheduler(cases)
    drained = []
    while scheduler.has_next():
        drained.append(scheduler.next())
    assert [c.id for c in drained] == [f"case-{i}" for i in range(5)]


def test_has_next_false_after_all_consumed():
    scheduler = FifoScheduler([_case(0)])
    assert scheduler.has_next() is True
    scheduler.next()
    assert scheduler.has_next() is False


def test_next_on_empty_scheduler_raises():
    scheduler = FifoScheduler([])
    with pytest.raises(IndexError):
        scheduler.next()


def test_works_with_empty_list():
    scheduler = FifoScheduler([])
    assert scheduler.has_next() is False
