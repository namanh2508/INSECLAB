"""BatchTraceRunner — evaluate every trace bundle in a directory, offline.

Each ``*.json`` file directly inside the input directory is loaded as a
``TraceEvaluationInput`` and evaluated through the same hybrid oracle as
``eval-trace`` (``TraceEvaluationRunner``). Files are processed in sorted order
for deterministic output, and the per-file ``EvalReport``s are folded into one
``BatchReport``. An invalid file fails the whole batch fast with the loader's
typed ``ConfigError`` (which names the file) rather than being silently skipped —
safer for CI. No adapter, no live target, no baseline run, no network.
"""

from pathlib import Path

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import EvalReport
from agentic_security_eval.oracle.judge import JudgeProvider
from agentic_security_eval.reporting.batch_report import BatchReport, build_batch_report
from agentic_security_eval.trace_io.loader import load_trace_evaluation_input

from .trace_runner import TraceEvaluationRunner


def discover_trace_files(input_dir: str | Path) -> list[Path]:
    """Return the sorted ``*.json`` files directly inside ``input_dir``.

    Subdirectories are not searched. Raises ``ConfigError`` if the directory is
    missing or contains no trace files (an empty batch is treated as an error,
    not a silent zero-finding success).
    """
    directory = Path(input_dir)
    if not directory.is_dir():
        raise ConfigError(f"Batch input directory not found: {directory}")
    files = sorted(path for path in directory.glob("*.json") if path.is_file())
    if not files:
        raise ConfigError(f"No trace files (*.json) found in {directory}.")
    return files


class BatchTraceRunner:
    """Evaluate a directory of trace bundles and return one BatchReport."""

    def __init__(self, judge_provider: JudgeProvider) -> None:
        self.judge_provider = judge_provider

    def run(self, input_dir: str | Path) -> BatchReport:
        files = discover_trace_files(input_dir)
        per_file: list[tuple[str, EvalReport]] = []
        for path in files:
            trace_input = load_trace_evaluation_input(path)
            runner = TraceEvaluationRunner(
                target_id=trace_input.attack_trace.target_id,
                judge_provider=self.judge_provider,
            )
            per_file.append((path.name, runner.run(trace_input)))
        return build_batch_report(str(Path(input_dir)), per_file)
