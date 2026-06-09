"""FindingBuilder — assemble a validated Finding from a trusted decision.

Only cited evidence is attached, and the trace snippet is a minimal pointer list
(no full trace dump). A finding is produced only for a vulnerable, validated
decision; otherwise the builder returns None.
"""

from agentic_security_eval.core.models import AttackCase, Evidence, Finding, JudgeDecision


class FindingBuilder:
    """Turn a validated JudgeDecision into a Finding (or None)."""

    def build(
        self,
        attack_case: AttackCase,
        decision: JudgeDecision | None,
        evidence: list[Evidence],
        validator_notes: list[str],
    ) -> Finding | None:
        if decision is None or not decision.is_vulnerable:
            return None

        cited_ids = set(decision.evidence_ids)
        cited = [e for e in evidence if e.id in cited_ids]
        trace_snippet = [
            {
                "evidence_id": e.id,
                "source": e.source.value,
                "ref_id": e.ref_id,
                "locator": e.locator,
                "snippet": e.snippet,
            }
            for e in cited
        ]

        return Finding(
            id=f"finding__{attack_case.id}",
            attack_case_id=attack_case.id,
            category=decision.category,
            surface=attack_case.surface,
            severity=decision.severity,
            confidence=decision.confidence,
            exploitability_score=decision.exploitability_score,
            is_vulnerable=True,
            evidence=cited,
            explanation=decision.explanation,
            recommendation=decision.recommendation,
            trace_snippet=trace_snippet,
            validator_notes=validator_notes,
        )
