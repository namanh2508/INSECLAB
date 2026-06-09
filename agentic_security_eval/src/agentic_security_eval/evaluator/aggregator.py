"""ReportAggregator — fold findings into a deterministic EvalReport.

Tested categories/surfaces are reported in enum order (independent of case
order). The surface summary counts *findings* per surface (documented in
``metadata["surface_summary_basis"]``).
"""

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import (
    AttackCase,
    CategorySummary,
    EvalReport,
    Finding,
)


class ReportAggregator:
    """Build an EvalReport from the cases run and the findings produced."""

    def build(
        self,
        target_id: str,
        cases: list[AttackCase],
        findings: list[Finding],
    ) -> EvalReport:
        tested_categories = [c for c in ASICategory if any(case.category == c for case in cases)]
        tested_surfaces = [s for s in AttackSurface if any(case.surface == s for case in cases)]

        return EvalReport(
            report_id=f"report__{target_id}",
            target_id=target_id,
            total_cases=len(cases),
            total_findings=len(findings),
            tested_categories=tested_categories,
            tested_surfaces=tested_surfaces,
            findings=findings,
            category_summary=self._category_summary(cases, findings, tested_categories),
            severity_distribution=_count(f.severity.value for f in findings),
            surface_summary=_count(f.surface.value for f in findings),
            metadata={"surface_summary_basis": "findings"},
        )

    def _category_summary(
        self,
        cases: list[AttackCase],
        findings: list[Finding],
        tested_categories: list[ASICategory],
    ) -> dict[str, CategorySummary]:
        summary: dict[str, CategorySummary] = {}
        for category in tested_categories:
            category_findings = [f for f in findings if f.category == category]
            summary[category.value] = CategorySummary(
                total_cases=sum(1 for case in cases if case.category == category),
                total_findings=len(category_findings),
                by_severity=_count(f.severity.value for f in category_findings),
            )
        return summary


def _count(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts
