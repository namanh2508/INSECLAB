"""Unit tests for the batch Markdown renderer."""

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.models import AttackCase, Evidence, Finding
from agentic_security_eval.evaluator.aggregator import ReportAggregator
from agentic_security_eval.reporting.batch_report import build_batch_report
from agentic_security_eval.reporting.markdown_report import render_batch_markdown, write_markdown

_SECTIONS = (
    "# Agentic Security Evaluation Batch Report",
    "## Summary",
    "## Findings",
    "## Evidence summary",
    "## Files evaluated",
)


def _finding(explanation: str = "x", *, snippet: str = "snippet", evidence_id: str = "ev-001") -> Finding:
    evidence = Evidence(
        id=evidence_id, source=EvidenceSource.TOOL_CALL, ref_id="ref-1", snippet=snippet,
        locator="locator", reason="reason", metadata={"signal": "unsafe_tool_call", "direct": True},
    )
    return Finding(
        id="finding__c1", attack_case_id="c1", category=ASICategory.ASI02,
        surface=AttackSurface.TOOL_OUTPUT, severity=Severity.HIGH, confidence=0.9,
        exploitability_score=0.8, is_vulnerable=True, evidence=[evidence],
        explanation=explanation, recommendation="y",
    )


def _batch(findings: list[Finding], *, file_name: str = "trace.json"):
    case = AttackCase(
        id="c1", category=ASICategory.ASI02, surface=AttackSurface.TOOL_OUTPUT,
        objective="o", payload="p", expected_risk="r",
    )
    report = ReportAggregator().build("target", [case], findings)
    return build_batch_report("traces", [(file_name, report)])


def test_markdown_has_all_sections_and_findings_header():
    md = render_batch_markdown(_batch([_finding()]))
    for section in _SECTIONS:
        assert section in md
    assert "| File | Case ID | Category | Severity | Title | Evidence IDs |" in md
    assert "| Signal | Count |" in md
    assert "| File | Cases | Findings |" in md


def test_markdown_escapes_pipe_characters_in_explanation():
    md = render_batch_markdown(_batch([_finding("alpha | beta gamma")]))
    # The pipe is escaped so it cannot break the table layout.
    assert "alpha \\| beta gamma" in md
    assert "| alpha | beta gamma |" not in md


def test_markdown_lists_evidence_ids_not_snippets():
    md = render_batch_markdown(_batch([_finding(snippet="SUPER_SECRET_SNIPPET", evidence_id="ev-042")]))
    assert "ev-042" in md
    assert "SUPER_SECRET_SNIPPET" not in md


def test_markdown_collapses_newlines_in_title():
    md = render_batch_markdown(_batch([_finding("line one\nline two")]))
    assert "line one line two" in md
    assert "line one\nline two" not in md


def test_markdown_empty_findings_renders_placeholders():
    md = render_batch_markdown(_batch([]))
    for section in _SECTIONS:
        assert section in md
    assert "_No findings._" in md
    assert "_No evidence signals._" in md
    assert "- Total findings: 0" in md


def test_write_markdown_creates_file(tmp_path):
    md = render_batch_markdown(_batch([_finding()]))
    path = write_markdown(md, tmp_path / "out" / "batch.md")
    assert path.exists()
    assert path.read_text(encoding="utf-8") == md
