"""Unit tests for the batch report model and aggregation."""

import json

from agentic_security_eval.core.enums import ASICategory, AttackSurface, EvidenceSource, Severity
from agentic_security_eval.core.models import AttackCase, Evidence, Finding
from agentic_security_eval.evaluator.aggregator import ReportAggregator
from agentic_security_eval.reporting.batch_report import (
    BatchReport,
    build_batch_report,
    write_batch_report,
)

_SURFACE = {
    ASICategory.ASI01: AttackSurface.USER_PROMPT,
    ASICategory.ASI02: AttackSurface.TOOL_OUTPUT,
    ASICategory.ASI06: AttackSurface.MEMORY_WRITE,
}


def _finding(case_id: str, category: ASICategory, severity: Severity, *signals: str) -> Finding:
    evidence = [
        Evidence(
            id=f"ev-{i:03d}", source=EvidenceSource.TOOL_CALL, ref_id=f"ref-{i}",
            snippet="snippet", locator="locator", reason="reason",
            metadata={"signal": signal, "direct": True},
        )
        for i, signal in enumerate(signals, start=1)
    ]
    return Finding(
        id=f"finding__{case_id}", attack_case_id=case_id, category=category,
        surface=_SURFACE[category], severity=severity, confidence=0.9,
        exploitability_score=0.8, is_vulnerable=True, evidence=evidence,
        explanation="x", recommendation="y",
    )


def _report(target: str, case_id: str, category: ASICategory, findings: list[Finding]):
    case = AttackCase(
        id=case_id, category=category, surface=_SURFACE[category],
        objective="o", payload="p", expected_risk="r",
    )
    return ReportAggregator().build(target, [case], findings)


def _per_file() -> list[tuple[str, object]]:
    # One critical, one high, one (medium) clean-of-higher, listed out of severity order.
    return [
        ("c_asi06.json", _report("t6", "c6", ASICategory.ASI06,
                                 [_finding("c6", ASICategory.ASI06, Severity.CRITICAL, "unsafe_memory_write")])),
        ("a_asi02.json", _report("t2", "c2", ASICategory.ASI02,
                                 [_finding("c2", ASICategory.ASI02, Severity.HIGH, "unsafe_tool_call")])),
        ("b_asi01.json", _report("t1", "c1", ASICategory.ASI01,
                                 [_finding("c1", ASICategory.ASI01, Severity.MEDIUM, "goal_drift")])),
    ]


def test_build_batch_report_counts_totals():
    batch = build_batch_report("traces", _per_file())
    assert batch.total_files == 3
    assert batch.total_cases == 3
    assert batch.total_findings == 3
    assert batch.input_dir == "traces"
    assert batch.schema_version == "0.1"


def test_severity_distribution_is_ordered_low_to_high():
    batch = build_batch_report("traces", _per_file())
    # Ordered by the Severity enum regardless of the order files were folded in.
    assert list(batch.severity_distribution.items()) == [("medium", 1), ("high", 1), ("critical", 1)]


def test_category_distribution_is_ordered_by_enum():
    batch = build_batch_report("traces", _per_file())
    assert list(batch.category_distribution.items()) == [("ASI01", 1), ("ASI02", 1), ("ASI06", 1)]


def test_signal_distribution_counts_and_sorts():
    per_file = [
        ("a.json", _report("t", "ca", ASICategory.ASI02,
                           [_finding("ca", ASICategory.ASI02, Severity.HIGH, "unsafe_tool_call")])),
        ("b.json", _report("t", "cb", ASICategory.ASI02,
                           [_finding("cb", ASICategory.ASI02, Severity.HIGH, "unsafe_tool_call")])),
        ("c.json", _report("t", "cc", ASICategory.ASI06,
                           [_finding("cc", ASICategory.ASI06, Severity.CRITICAL,
                                     "unsafe_memory_write", "policy_or_identity_override_persisted")])),
    ]
    batch = build_batch_report("traces", per_file)
    # Alphabetical keys; one signal counted across two files; multi-evidence finding counts each signal.
    assert batch.signal_distribution == {
        "policy_or_identity_override_persisted": 1,
        "unsafe_memory_write": 1,
        "unsafe_tool_call": 2,
    }


def test_build_batch_report_preserves_entry_order():
    batch = build_batch_report("traces", _per_file())
    assert [entry.input_file for entry in batch.reports] == ["c_asi06.json", "a_asi02.json", "b_asi01.json"]


def test_empty_findings_yield_zero_distributions():
    per_file = [("clean.json", _report("t", "c0", ASICategory.ASI01, []))]
    batch = build_batch_report("traces", per_file)
    assert batch.total_files == 1
    assert batch.total_findings == 0
    assert batch.severity_distribution == {}
    assert batch.category_distribution == {}
    assert batch.signal_distribution == {}


def test_batch_report_round_trips_through_json(tmp_path):
    batch = build_batch_report("traces", _per_file())
    path = write_batch_report(batch, tmp_path / "out" / "batch.json")
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["total_files"] == 3
    assert data["total_findings"] == 3
    # The embedded per-file EvalReport schema is preserved unchanged.
    assert data["reports"][0]["report"]["report_id"].startswith("report__")
    reloaded = BatchReport.model_validate(data)
    assert reloaded == batch
