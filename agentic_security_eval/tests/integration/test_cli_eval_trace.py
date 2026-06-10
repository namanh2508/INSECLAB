"""Integration: CLI `eval-trace` against example trace bundles."""

import json
from pathlib import Path

from agentic_security_eval.cli import main

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def test_cli_eval_trace_asi02_produces_one_high_finding(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", str(TRACES / "asi02_tool_misuse_trace.json"), "--output", str(out)])
    assert rc == 0
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 1
    assert data["findings"][0]["category"] == "ASI02"


def test_cli_eval_trace_hardened_produces_no_findings(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", str(TRACES / "hardened_trace.json"), "--output", str(out)])
    assert rc == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 0
