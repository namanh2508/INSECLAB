"""Deterministic, category-specific evidence rules.

Each module classifies a single trace element (a ToolCall, a MemoryEvent, a
final-output string, ...) and returns an ``EvidenceCandidate`` describing the
signal it found. Rule modules never inspect ``attack_case.category`` and never
construct ``Evidence`` or assign IDs — category-gating, Evidence construction,
and stable ID assignment all remain in ``oracle.evidence.EvidenceExtractor``.
"""
