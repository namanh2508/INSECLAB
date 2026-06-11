"""Integration: CLI `eval-traces` over the bundled example trace directory."""

import json
from pathlib import Path

from agentic_security_eval.cli import main

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def test_cli_eval_traces_writes_json_and_markdown(tmp_path):
    out = tmp_path / "batch.json"
    md = tmp_path / "batch.md"
    rc = main([
        "eval-traces",
        "--input-dir", str(TRACES),
        "--output", str(out),
        "--markdown-output", str(md),
    ])
    assert rc == 0
    assert out.exists()
    assert md.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    expected_files = len(list(TRACES.glob("*.json")))
    assert data["total_files"] == expected_files
    assert data["total_cases"] == expected_files
    assert data["total_findings"] >= 1
    # The example set spans all three categories and a range of severities.
    assert set(data["category_distribution"]) == {"ASI01", "ASI02", "ASI06"}
    assert {"medium", "high", "critical"} <= set(data["severity_distribution"])
    assert len(data["reports"]) == expected_files

    text = md.read_text(encoding="utf-8")
    assert text.startswith("# Agentic Security Evaluation Batch Report")
    assert "## Findings" in text
    assert "## Files evaluated" in text


def test_cli_eval_traces_default_judge_is_offline(tmp_path):
    # No judge flags -> FakeJudgeProvider; the whole batch runs offline.
    out = tmp_path / "batch.json"
    rc = main(["eval-traces", "--input-dir", str(TRACES), "--output", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["total_findings"] >= 1
