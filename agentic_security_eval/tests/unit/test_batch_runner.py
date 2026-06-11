"""Unit tests for trace-file discovery and the batch runner."""

import shutil
from pathlib import Path

import pytest

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.evaluator.batch_runner import BatchTraceRunner, discover_trace_files
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider

TRACES = Path(__file__).resolve().parents[2] / "examples" / "traces"
_VALID = TRACES / "asi02_tool_misuse_trace.json"


def _copy(src: Path, dest_dir: Path, name: str) -> None:
    shutil.copy(src, dest_dir / name)


def test_discover_trace_files_is_sorted(tmp_path):
    for name in ("c.json", "a.json", "b.json"):
        _copy(_VALID, tmp_path, name)
    assert [p.name for p in discover_trace_files(tmp_path)] == ["a.json", "b.json", "c.json"]


def test_discover_trace_files_missing_dir_raises(tmp_path):
    with pytest.raises(ConfigError):
        discover_trace_files(tmp_path / "does-not-exist")


def test_discover_trace_files_empty_dir_raises(tmp_path):
    with pytest.raises(ConfigError):
        discover_trace_files(tmp_path)


def test_discover_trace_files_skips_subdirectories(tmp_path):
    _copy(_VALID, tmp_path, "top.json")
    # A directory whose name ends in .json must be excluded (is_file filter)...
    (tmp_path / "dir.json").mkdir()
    # ...and a *.json nested in a real subdirectory must not be discovered.
    nested = tmp_path / "nested"
    nested.mkdir()
    _copy(_VALID, nested, "inner.json")
    assert [p.name for p in discover_trace_files(tmp_path)] == ["top.json"]


def test_batch_runner_runs_all_and_orders_by_name(tmp_path):
    # Copy out of sorted order; the runner must still process/emit them sorted.
    _copy(TRACES / "hardened_trace.json", tmp_path, "hardened_trace.json")
    _copy(TRACES / "asi06_memory_poisoning_trace.json", tmp_path, "asi06_memory_poisoning_trace.json")
    _copy(TRACES / "asi02_tool_misuse_trace.json", tmp_path, "asi02_tool_misuse_trace.json")

    batch = BatchTraceRunner(judge_provider=FakeJudgeProvider()).run(tmp_path)

    assert batch.total_files == 3
    assert batch.total_cases == 3
    assert batch.total_findings == 2  # hardened produces none
    assert [entry.input_file for entry in batch.reports] == [
        "asi02_tool_misuse_trace.json",
        "asi06_memory_poisoning_trace.json",
        "hardened_trace.json",
    ]
    assert batch.severity_distribution == {"high": 1, "critical": 1}


def test_batch_runner_invalid_file_fails_fast(tmp_path):
    _copy(_VALID, tmp_path, "a_valid.json")
    (tmp_path / "b_broken.json").write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        BatchTraceRunner(judge_provider=FakeJudgeProvider()).run(tmp_path)
    assert "b_broken.json" in str(excinfo.value)
