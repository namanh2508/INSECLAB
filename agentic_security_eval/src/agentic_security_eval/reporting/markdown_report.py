"""Markdown renderer for a BatchReport — a concise, human-readable summary.

JSON remains the machine-readable output; this Markdown is for human review
(thesis/demo runs, PR comments, CI artifacts). It is deterministic and
intentionally compact, and it is defensive about untrusted content: it lists
evidence **IDs** rather than evidence snippets, the judge explanation is shown
only as a short truncated title, and every table cell is whitespace-collapsed
and pipe-escaped so untrusted finding text cannot break the table layout.
"""

from pathlib import Path

from agentic_security_eval.core.errors import ReportError
from agentic_security_eval.core.models import Finding
from agentic_security_eval.reporting.batch_report import BatchReport

_MAX_TITLE_LEN = 100
_FINDINGS_HEADER = "| File | Case ID | Category | Severity | Title | Evidence IDs |"
_FINDINGS_DIVIDER = "| --- | --- | --- | --- | --- | --- |"
_SIGNALS_HEADER = "| Signal | Count |"
_SIGNALS_DIVIDER = "| --- | --- |"
_FILES_HEADER = "| File | Cases | Findings |"
_FILES_DIVIDER = "| --- | --- | --- |"


def render_batch_markdown(report: BatchReport) -> str:
    """Render a BatchReport as a Markdown document (deterministic)."""
    lines: list[str] = [
        "# Agentic Security Evaluation Batch Report",
        "",
        "## Summary",
        "",
        f"- Input directory: `{_md_inline(report.input_dir)}`",
        f"- Total files: {report.total_files}",
        f"- Total cases: {report.total_cases}",
        f"- Total findings: {report.total_findings}",
        f"- Severity distribution: {_format_distribution(report.severity_distribution)}",
        f"- Category distribution: {_format_distribution(report.category_distribution)}",
        "",
        "## Findings",
        "",
        *_findings_table(report),
        "",
        "## Evidence summary",
        "",
        *_signals_table(report),
        "",
        "## Files evaluated",
        "",
        *_files_table(report),
        "",
    ]
    return "\n".join(lines) + "\n"


def write_markdown(markdown: str, output_path: str | Path) -> Path:
    """Write a Markdown string to disk, wrapping OSError as ReportError."""
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Failed to write Markdown report to {path}: {exc}") from exc
    return path


def _findings_table(report: BatchReport) -> list[str]:
    if report.total_findings == 0:
        return ["_No findings._"]
    rows = [_FINDINGS_HEADER, _FINDINGS_DIVIDER]
    for entry in report.reports:
        for finding in entry.report.findings:
            evidence_ids = ", ".join(evidence.id for evidence in finding.evidence)
            cells = (
                entry.input_file,
                finding.attack_case_id,
                finding.category.value,
                finding.severity.value,
                _title(finding),
                evidence_ids,
            )
            rows.append("| " + " | ".join(_md_cell(cell) for cell in cells) + " |")
    return rows


def _signals_table(report: BatchReport) -> list[str]:
    if not report.signal_distribution:
        return ["_No evidence signals._"]
    rows = [_SIGNALS_HEADER, _SIGNALS_DIVIDER]
    # Most frequent first, then alphabetical — deterministic.
    for signal, count in sorted(report.signal_distribution.items(), key=lambda kv: (-kv[1], kv[0])):
        rows.append(f"| {_md_cell(signal)} | {count} |")
    return rows


def _files_table(report: BatchReport) -> list[str]:
    rows = [_FILES_HEADER, _FILES_DIVIDER]
    for entry in report.reports:
        rows.append(
            f"| {_md_cell(entry.input_file)} | {entry.report.total_cases} | {entry.report.total_findings} |"
        )
    return rows


def _title(finding: Finding) -> str:
    """A short, single-line title from the judge explanation (whitespace-collapsed)."""
    text = _md_inline(finding.explanation)
    if not text:
        return finding.category.value
    if len(text) > _MAX_TITLE_LEN:
        text = text[: _MAX_TITLE_LEN - 1].rstrip() + "…"
    return text


def _md_cell(value: str) -> str:
    """Collapse whitespace and escape pipes so a value is safe inside a table cell."""
    return _md_inline(value).replace("|", "\\|")


def _md_inline(value: str) -> str:
    """Collapse every run of whitespace (including newlines) into single spaces."""
    return " ".join(str(value).split())


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in distribution.items())
