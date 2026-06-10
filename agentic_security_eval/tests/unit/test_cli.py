"""Unit tests for the CLI: exit codes and report output."""

import json
from pathlib import Path

from agentic_security_eval.cli import main

CONFIGS = Path(__file__).resolve().parents[2] / "configs"
VULN = str(CONFIGS / "fake_vulnerable.yaml")


def test_eval_returns_zero_for_vulnerable_config(tmp_path):
    out = tmp_path / "report.json"
    assert main(["eval", "--target", VULN, "--output", str(out)]) == 0
    assert out.exists()


def test_eval_writes_report_json(tmp_path):
    out = tmp_path / "report.json"
    main(["eval", "--target", VULN, "--output", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["report_id"] == "report__fake_vulnerable_agent"
    assert data["total_findings"] > 0


def test_invalid_category_returns_nonzero(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval", "--target", VULN, "--output", str(out), "--categories", "ASI01,NOPE"])
    assert rc != 0


def test_unsupported_adapter_type_returns_nonzero(tmp_path):
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text(
        "target_id: x\nadapter_type: unsupported\ncapabilities:\n  tools: false\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    rc = main(["eval", "--target", str(bad_config), "--output", str(out)])
    assert rc != 0


def test_http_adapter_type_missing_http_config_returns_nonzero(tmp_path):
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text(
        "target_id: x\nadapter_type: http\ncapabilities:\n  tools: false\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    rc = main(["eval", "--target", str(bad_config), "--output", str(out)])
    assert rc != 0


def test_max_cases_one_limits_report(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval", "--target", VULN, "--output", str(out), "--max-cases", "1"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
