"""Integration: CLI convert-trace / eval-raw-trace against example raw logs."""

import json
from pathlib import Path

from agentic_security_eval.cli import main

RAW = Path(__file__).resolve().parents[2] / "examples" / "raw_logs"


def test_convert_trace_produces_valid_trace_bundle(tmp_path):
    out = tmp_path / "converted.json"
    rc = main(["convert-trace", "--input", str(RAW / "asi02_tool_misuse_raw_log.json"), "--output", str(out)])
    assert rc == 0
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["attack_case"]["category"] == "ASI02"
    assert data["attack_trace"]["attack_case_id"] == data["attack_case"]["id"]
    assert any(tc["metadata"].get("unsafe") for tc in data["attack_trace"]["tool_calls"])


def test_converted_trace_evaluates_to_one_asi02_finding(tmp_path):
    converted = tmp_path / "converted.json"
    assert main(["convert-trace", "--input", str(RAW / "asi02_tool_misuse_raw_log.json"), "--output", str(converted)]) == 0

    report = tmp_path / "report.json"
    assert main(["eval-trace", "--input", str(converted), "--output", str(report)]) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["total_cases"] == 1
    assert data["total_findings"] == 1
    assert data["findings"][0]["category"] == "ASI02"


def test_converted_hardened_trace_evaluates_to_zero_findings(tmp_path):
    converted = tmp_path / "hardened.json"
    main(["convert-trace", "--input", str(RAW / "hardened_raw_log.json"), "--output", str(converted)])

    report = tmp_path / "report.json"
    main(["eval-trace", "--input", str(converted), "--output", str(report)])
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["total_findings"] == 0


def test_eval_raw_trace_asi02_produces_one_finding(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-raw-trace", "--input", str(RAW / "asi02_tool_misuse_raw_log.json"), "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_findings"] == 1
    assert data["findings"][0]["category"] == "ASI02"


def test_eval_raw_trace_hardened_produces_zero_findings(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-raw-trace", "--input", str(RAW / "hardened_raw_log.json"), "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_findings"] == 0
