"""Batch evaluation report — many per-trace EvalReports rolled into one summary.

``eval-traces`` evaluates every trace bundle in a directory and folds the
per-file ``EvalReport``s into a single ``BatchReport``: cross-file severity,
category, and evidence-signal distributions plus the embedded per-file reports.
The schema is JSON-safe and deterministic — entries keep the order they are
given (the batch runner sorts files by name first), and the distributions are
ordered by the closed enums (severity low->high, category) or alphabetically
(signals). Serialization goes through Pydantic so the embedded ``EvalReport``
schema stays the single source of truth.
"""

from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from agentic_security_eval.core.enums import ASICategory, Severity
from agentic_security_eval.core.errors import ReportError
from agentic_security_eval.core.models import EvalReport, Finding


class BatchReportEntry(BaseModel):
    """One evaluated trace file and its full EvalReport."""

    input_file: str
    report: EvalReport


class BatchReport(BaseModel):
    """Roll-up of every per-trace EvalReport produced in a batch run."""

    schema_version: str = "0.1"
    input_dir: str
    total_files: int
    total_cases: int
    total_findings: int
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    category_distribution: dict[str, int] = Field(default_factory=dict)
    signal_distribution: dict[str, int] = Field(default_factory=dict)
    reports: list[BatchReportEntry] = Field(default_factory=list)


def build_batch_report(input_dir: str, per_file: list[tuple[str, EvalReport]]) -> BatchReport:
    """Fold ``(input_file, EvalReport)`` pairs into a deterministic BatchReport.

    ``per_file`` order is preserved in ``reports``; the caller (the batch runner)
    is responsible for ordering the files deterministically before folding.
    """
    all_findings = [finding for _, report in per_file for finding in report.findings]
    return BatchReport(
        input_dir=input_dir,
        total_files=len(per_file),
        total_cases=sum(report.total_cases for _, report in per_file),
        total_findings=sum(report.total_findings for _, report in per_file),
        severity_distribution=_severity_distribution(all_findings),
        category_distribution=_category_distribution(all_findings),
        signal_distribution=_signal_distribution(all_findings),
        reports=[BatchReportEntry(input_file=name, report=report) for name, report in per_file],
    )


def write_batch_report(report: BatchReport, output_path: str | Path) -> Path:
    """Write the batch report as pretty JSON, wrapping OSError as ReportError."""
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Failed to write batch report to {path}: {exc}") from exc
    return path


def _severity_distribution(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity.value for finding in findings)
    # Ordered low->high by the Severity enum; only present severities are kept.
    return {sev.value: counts[sev.value] for sev in Severity if sev.value in counts}


def _category_distribution(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.category.value for finding in findings)
    return {cat.value: counts[cat.value] for cat in ASICategory if cat.value in counts}


def _signal_distribution(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(
        str(evidence.metadata.get("signal"))
        for finding in findings
        for evidence in finding.evidence
        if evidence.metadata.get("signal") is not None
    )
    return dict(sorted(counts.items()))
