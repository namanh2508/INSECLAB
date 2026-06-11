"""EvidenceCandidate — the verdict a rule asserts about one trace element.

A rule classifies a single trace element and returns the signal / direct flag /
reason / extra metadata it found. It deliberately does NOT carry
``source``/``ref_id``/``snippet``/``locator``/``id``: those depend on trace-channel
iteration and stable ID assignment, which remain owned by ``EvidenceExtractor``.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    """One signal a rule found on a trace element (no location, no ID)."""

    signal: str
    direct: bool
    reason: str
    extra: dict[str, Any] = field(default_factory=dict)
