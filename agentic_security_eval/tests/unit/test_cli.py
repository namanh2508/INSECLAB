"""Unit tests for the CLI: exit codes and report output."""

import json
from pathlib import Path

import pytest

from agentic_security_eval.cli import main

CONFIGS = Path(__file__).resolve().parents[2] / "configs"
VULN = str(CONFIGS / "fake_vulnerable.yaml")
TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"
RAW_LOGS = Path(__file__).resolve().parents[2] / "examples" / "raw_logs"
ASI02_TRACE = str(TRACES / "asi02_tool_misuse_trace.json")  # one ASI02 high finding
HARDENED_TRACE = str(TRACES / "hardened_trace.json")        # no findings


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


# --------------------------------------------------------------------------- #
# Phase 14.0: --fail-on CI gating
# --------------------------------------------------------------------------- #
def test_eval_trace_fail_on_high_returns_3_and_still_writes_report(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", ASI02_TRACE, "--output", str(out), "--fail-on", "high"])
    assert rc == 3
    # the report is written before the gate check
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total_findings"] == 1


def test_eval_trace_fail_on_critical_returns_0_when_severity_is_high(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", ASI02_TRACE, "--output", str(out), "--fail-on", "critical"])
    assert rc == 0


def test_eval_trace_hardened_fail_on_medium_returns_0(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", HARDENED_TRACE, "--output", str(out), "--fail-on", "medium"])
    assert rc == 0


def test_eval_trace_findings_without_fail_on_returns_0(tmp_path):
    out = tmp_path / "report.json"
    rc = main(["eval-trace", "--input", ASI02_TRACE, "--output", str(out)])
    assert rc == 0


def test_convert_trace_rejects_fail_on(tmp_path):
    with pytest.raises(SystemExit):
        main([
            "convert-trace",
            "--input", str(RAW_LOGS / "asi02_tool_misuse_raw_log.json"),
            "--output", str(tmp_path / "bundle.json"),
            "--fail-on", "high",
        ])


# --------------------------------------------------------------------------- #
# Phase 14.1: coverage command (offline, no target/judge)
# --------------------------------------------------------------------------- #
def test_coverage_command_returns_zero_and_shows_levels(capsys):
    rc = main(["coverage"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "direct" in out
    assert "indirect" in out
    assert "generation_only" in out


def test_coverage_command_json_is_parseable(capsys):
    rc = main(["coverage", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["entries"]
    levels = {entry["level"] for entry in data["entries"]}
    assert "direct" in levels and "indirect" in levels
