"""FifoScheduler — hand out attack cases in their original order.

Deliberately minimal: no priority, feedback, bandit, retry, or scoring. Those
are explicitly out of scope for the MVP.
"""

from collections import deque

from agentic_security_eval.core.models import AttackCase


class FifoScheduler:
    """First-in, first-out queue of attack cases."""

    def __init__(self, cases: list[AttackCase]) -> None:
        self._queue: deque[AttackCase] = deque(cases)

    def has_next(self) -> bool:
        return bool(self._queue)

    def next(self) -> AttackCase:
        if not self._queue:
            raise IndexError("FifoScheduler.next() called on an empty scheduler.")
        return self._queue.popleft()
