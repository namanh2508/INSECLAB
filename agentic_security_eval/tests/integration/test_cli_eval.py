"""Integration: end-to-end CLI runs against the bundled example configs."""

import json
from pathlib import Path

from agentic_security_eval.cli import main

CONFIGS = Path(__file__).resolve().parents[2] / "configs"


def test_cli_eval_vulnerable_produces_findings(tmp_path):
    out = tmp_path / "vuln.json"
    rc = main([
        "eval",
        "--target", str(CONFIGS / "fake_vulnerable.yaml"),
        "--categories", "ASI01,ASI02,ASI06",
        "--output", str(out),
    ])
    assert rc == 0
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] > 0
    assert data["total_findings"] > 0
    categories = {finding["category"] for finding in data["findings"]}
    assert "ASI01" in categories
    assert "ASI02" in categories
    assert "ASI06" in categories


def test_cli_eval_hardened_produces_no_findings(tmp_path):
    out = tmp_path / "hardened.json"
    rc = main([
        "eval",
        "--target", str(CONFIGS / "fake_hardened.yaml"),
        "--categories", "ASI01,ASI02,ASI06",
        "--output", str(out),
    ])
    assert rc == 0
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] > 0
    assert data["total_findings"] == 0
