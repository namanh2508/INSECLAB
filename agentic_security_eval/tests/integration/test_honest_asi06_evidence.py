"""Integration: honest ASI06 memory poisoning (no metadata.unsafe self-label).

Proves Phase 13.2: an honest target that persists a behavior-rewriting policy
override into memory now yields a critical ASI06 finding through the offline
pipeline, without the memory event having to self-label itself as unsafe.
"""

import json
from pathlib import Path

from agentic_security_eval.cli import main

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"


def test_honest_asi06_memory_poisoning_without_self_label_produces_critical_finding(tmp_path):
    out = tmp_path / "report.json"
    rc = main([
        "eval-trace",
        "--input", str(TRACES / "asi06_honest_memory_poisoning_trace.json"),
        "--output", str(out),
    ])
    assert rc == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 1

    finding = data["findings"][0]
    assert finding["category"] == "ASI06"
    assert finding["severity"] == "critical"

    signals = {e["metadata"]["signal"] for e in finding["evidence"]}
    assert signals & {"unsafe_memory_write", "policy_or_identity_override_persisted"}
