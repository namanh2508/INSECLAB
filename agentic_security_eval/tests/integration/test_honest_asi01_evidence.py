"""Integration: honest ASI01 goal hijack (no goal-drift keyword, no self-label).

Proves Phase 13.3: an honest target whose final output echoes an attacker token
plus a compliance phrase yields a medium ASI01 finding through the offline
pipeline via the ``attacker_goal_accepted`` signal — without a goal-drift keyword
and without any ``metadata.unsafe`` self-label.
"""

import json
from pathlib import Path

from agentic_security_eval.cli import main

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def test_honest_asi01_goal_hijack_without_keyword_produces_medium_finding(tmp_path):
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi01_honest_goal_hijack_trace.json"),
        "--output", str(out),
    ])
    assert rc == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 1

    finding = data["findings"][0]
    assert finding["category"] == "ASI01"
    assert finding["severity"] == "medium"

    signals = {e["metadata"]["signal"] for e in finding["evidence"]}
    assert signals & {"attacker_goal_accepted", "goal_drift"}
