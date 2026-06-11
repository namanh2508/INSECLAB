"""Integration: honest ASI02 tool misuse (no metadata.unsafe self-label).

Proves Phase 13.1: a real/honest target that calls a risky tool with an
attacker-controlled argument now yields a high ASI02 finding through the offline
pipeline, without the trace having to self-label the tool call as unsafe.
"""

import json
from pathlib import Path

from agentic_security_eval.cli import main

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def test_honest_asi02_tool_misuse_without_self_label_produces_high_finding(tmp_path):
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi02_honest_tool_misuse_trace.json"),
        "--output", str(out),
    ])
    assert rc == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 1

    finding = data["findings"][0]
    assert finding["category"] == "ASI02"
    assert finding["severity"] == "high"

    signals = {e["metadata"]["signal"] for e in finding["evidence"]}
    assert "risky_tool_with_attacker_input" in signals
