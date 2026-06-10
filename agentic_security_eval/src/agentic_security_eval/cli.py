"""Thin argparse CLI: run an evaluation from a YAML TargetConfig.

    agentic-sec-eval eval --target <config.yaml> --output <report.json>

This wires the existing MVP pipeline with the offline ``FakeJudgeProvider`` only.
Expected failures (bad config/category/adapter, adapter/judge/report errors) are
reported as a short stderr message and a non-zero exit code — no tracebacks.
"""

import argparse
import sys
from pathlib import Path

from agentic_security_eval.adapters.python_workflow import PythonWorkflowAdapter
from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.config.loader import load_target_config
from agentic_security_eval.converters.raw_event_log import load_raw_agent_log, raw_log_to_trace_input
from agentic_security_eval.core.enums import ASICategory
from agentic_security_eval.core.errors import AgenticSecurityEvalError, ReportError
from agentic_security_eval.evaluator.runner import EvaluatorRunner
from agentic_security_eval.evaluator.trace_runner import TraceEvaluationRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter
from agentic_security_eval.trace_io.loader import load_trace_evaluation_input

SUPPORTED_ADAPTER = "python_workflow"
DEFAULT_CATEGORIES = "ASI01,ASI02,ASI06"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    # Config entrypoints (e.g. examples.fake_targets:...) are module paths
    # resolved relative to the current working directory.
    _ensure_cwd_importable()
    handlers = {
        "eval": _run_eval,
        "eval-trace": _run_eval_trace,
        "convert-trace": _run_convert_trace,
        "eval-raw-trace": _run_eval_raw_trace,
    }
    try:
        return handlers[args.command](args)
    except AgenticSecurityEvalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentic-sec-eval", description="Agentic AI security evaluator.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    eval_parser = subparsers.add_parser("eval", help="Evaluate a target described by a YAML TargetConfig.")
    eval_parser.add_argument("--target", required=True, help="Path to a YAML TargetConfig.")
    eval_parser.add_argument("--output", required=True, help="Path to write the JSON report.")
    eval_parser.add_argument(
        "--categories", default=DEFAULT_CATEGORIES,
        help="Comma-separated ASI categories (default: ASI01,ASI02,ASI06).",
    )
    eval_parser.add_argument(
        "--max-cases", type=int, default=None,
        help="Optional cap on the number of attack cases.",
    )

    trace_parser = subparsers.add_parser(
        "eval-trace", help="Evaluate a pre-recorded TraceEvaluationInput JSON bundle."
    )
    trace_parser.add_argument("--input", required=True, help="Path to a trace bundle JSON.")
    trace_parser.add_argument("--output", required=True, help="Path to write the JSON report.")

    convert_parser = subparsers.add_parser(
        "convert-trace", help="Convert a raw agent log into a TraceEvaluationInput bundle."
    )
    convert_parser.add_argument("--input", required=True, help="Path to a raw agent log JSON.")
    convert_parser.add_argument("--output", required=True, help="Path to write the trace bundle JSON.")

    raw_eval_parser = subparsers.add_parser(
        "eval-raw-trace", help="Convert a raw agent log and evaluate it in one step."
    )
    raw_eval_parser.add_argument("--input", required=True, help="Path to a raw agent log JSON.")
    raw_eval_parser.add_argument("--output", required=True, help="Path to write the JSON report.")

    return parser


def _run_eval(args: argparse.Namespace) -> int:
    config = load_target_config(args.target)
    if config.adapter_type != SUPPORTED_ADAPTER:
        print(
            f"error: unsupported adapter_type '{config.adapter_type}'; "
            f"only '{SUPPORTED_ADAPTER}' is supported.",
            file=sys.stderr,
        )
        return 2

    categories = _parse_categories(args.categories)
    if categories is None:
        return 2

    cases = AttackGenerator(config).generate(categories=categories, max_cases=args.max_cases)
    runner = EvaluatorRunner(
        target_id=config.target_id,
        adapter=PythonWorkflowAdapter(config),
        judge_provider=FakeJudgeProvider(),
    )
    report = runner.run(cases)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return 0


def _run_eval_trace(args: argparse.Namespace) -> int:
    trace_input = load_trace_evaluation_input(args.input)
    runner = TraceEvaluationRunner(
        target_id=trace_input.attack_trace.target_id,
        judge_provider=FakeJudgeProvider(),
    )
    report = runner.run(trace_input)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return 0


def _run_convert_trace(args: argparse.Namespace) -> int:
    raw_log = load_raw_agent_log(args.input)
    trace_input = raw_log_to_trace_input(raw_log)

    output_path = Path(args.output)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(trace_input.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Failed to write trace bundle to {output_path}: {exc}") from exc

    print(f"Wrote trace bundle to {output_path} from {len(raw_log.events)} raw events.")
    return 0


def _run_eval_raw_trace(args: argparse.Namespace) -> int:
    raw_log = load_raw_agent_log(args.input)
    trace_input = raw_log_to_trace_input(raw_log)
    runner = TraceEvaluationRunner(
        target_id=trace_input.attack_trace.target_id,
        judge_provider=FakeJudgeProvider(),
    )
    report = runner.run(trace_input)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return 0


def _parse_categories(raw: str) -> list[ASICategory] | None:
    categories: list[ASICategory] = []
    for token in raw.split(","):
        name = token.strip()
        if not name:
            continue
        try:
            categories.append(ASICategory(name))
        except ValueError:
            valid = ", ".join(c.value for c in ASICategory)
            print(f"error: invalid category '{name}'; valid categories: {valid}.", file=sys.stderr)
            return None

    if not categories:
        print("error: no categories provided.", file=sys.stderr)
        return None
    return categories


def _ensure_cwd_importable() -> None:
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)


if __name__ == "__main__":
    raise SystemExit(main())
