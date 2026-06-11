"""Thin argparse CLI: run evaluations and trace conversion.

    agentic-sec-eval eval --target <config.yaml> --output <report.json>

The default judge is the offline ``FakeJudgeProvider``. A real
OpenAI-compatible judge can be selected explicitly for evaluation commands.
Expected failures (bad config/category/adapter, adapter/judge/report errors) are
reported as a short stderr message and a non-zero exit code — no tracebacks.
"""

import argparse
import sys
from pathlib import Path

from agentic_security_eval.adapters.base import TargetAdapter
from agentic_security_eval.adapters.http_target import HttpTargetAdapter
from agentic_security_eval.adapters.python_workflow import PythonWorkflowAdapter
from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.config.loader import load_target_config
from agentic_security_eval.converters.raw_event_log import load_raw_agent_log, raw_log_to_trace_input
from agentic_security_eval.core.enums import ASICategory, Severity
from agentic_security_eval.core.errors import AgenticSecurityEvalError, ConfigError, ReportError
from agentic_security_eval.core.models import EvalReport, TargetConfig
from agentic_security_eval.evaluator.runner import EvaluatorRunner
from agentic_security_eval.evaluator.trace_runner import TraceEvaluationRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.oracle.judge import JudgeProvider
from agentic_security_eval.oracle.openai_compatible_judge import OpenAICompatibleJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter
from agentic_security_eval.trace_io.loader import load_trace_evaluation_input

DEFAULT_CATEGORIES = "ASI01,ASI02,ASI06"
DEFAULT_JUDGE_PROVIDER = "fake"
DEFAULT_JUDGE_BASE_URL = "https://api.openai.com/v1"
DEFAULT_JUDGE_API_KEY_ENV = "OPENAI_API_KEY"
DEFAULT_JUDGE_RESPONSE_FORMAT = "json_object"
FAIL_ON_EXIT_CODE = 3
_FAIL_ON_CHOICES = ("medium", "high", "critical")
# Severity declaration order in the enum is low->high; rank by position.
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


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
    _add_judge_options(eval_parser)
    _add_fail_on(eval_parser)

    trace_parser = subparsers.add_parser(
        "eval-trace", help="Evaluate a pre-recorded TraceEvaluationInput JSON bundle."
    )
    trace_parser.add_argument("--input", required=True, help="Path to a trace bundle JSON.")
    trace_parser.add_argument("--output", required=True, help="Path to write the JSON report.")
    _add_judge_options(trace_parser)
    _add_fail_on(trace_parser)

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
    _add_judge_options(raw_eval_parser)
    _add_fail_on(raw_eval_parser)

    return parser


def _run_eval(args: argparse.Namespace) -> int:
    config = load_target_config(args.target)

    categories = _parse_categories(args.categories)
    if categories is None:
        return 2

    judge_provider = _build_judge_provider(args)
    cases = AttackGenerator(config).generate(categories=categories, max_cases=args.max_cases)
    runner = EvaluatorRunner(
        target_id=config.target_id,
        adapter=_build_target_adapter(config),
        judge_provider=judge_provider,
    )
    report = runner.run(cases)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return _fail_on_exit(report, args.fail_on)


def _run_eval_trace(args: argparse.Namespace) -> int:
    judge_provider = _build_judge_provider(args)
    trace_input = load_trace_evaluation_input(args.input)
    runner = TraceEvaluationRunner(
        target_id=trace_input.attack_trace.target_id,
        judge_provider=judge_provider,
    )
    report = runner.run(trace_input)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return _fail_on_exit(report, args.fail_on)


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
    judge_provider = _build_judge_provider(args)
    raw_log = load_raw_agent_log(args.input)
    trace_input = raw_log_to_trace_input(raw_log)
    runner = TraceEvaluationRunner(
        target_id=trace_input.attack_trace.target_id,
        judge_provider=judge_provider,
    )
    report = runner.run(trace_input)

    output_path = JsonReportWriter().write(report, args.output)
    print(f"Wrote report to {output_path}: {report.total_cases} cases, {report.total_findings} findings.")
    return _fail_on_exit(report, args.fail_on)


def _add_judge_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--judge-provider",
        default=DEFAULT_JUDGE_PROVIDER,
        help="Judge provider: fake or openai-compatible (default: fake).",
    )
    parser.add_argument("--judge-model", default=None, help="Model name for openai-compatible judge.")
    parser.add_argument(
        "--judge-base-url",
        default=DEFAULT_JUDGE_BASE_URL,
        help="Base URL for openai-compatible judge (default: https://api.openai.com/v1).",
    )
    parser.add_argument(
        "--judge-api-key-env",
        default=DEFAULT_JUDGE_API_KEY_ENV,
        help="Environment variable holding the judge API key (default: OPENAI_API_KEY).",
    )
    parser.add_argument(
        "--judge-response-format",
        default=DEFAULT_JUDGE_RESPONSE_FORMAT,
        help="Response format mode: none, json_object, or json_schema (default: json_object).",
    )


def _add_fail_on(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default=None,
        help="Exit with code 3 if any finding is at or above this severity (medium|high|critical).",
    )


def _fail_on_exit(report: EvalReport, fail_on: str | None) -> int:
    """Return 0, or FAIL_ON_EXIT_CODE if a finding meets the --fail-on threshold.

    The report has already been written by the caller; this only decides the exit
    code. Parser/config/runtime errors are handled elsewhere and are unaffected.
    """
    if not fail_on:
        return 0
    threshold = _SEVERITY_RANK[Severity(fail_on)]
    triggering = [f for f in report.findings if _SEVERITY_RANK[f.severity] >= threshold]
    if triggering:
        print(
            f"error: {len(triggering)} finding(s) at or above severity '{fail_on}' (--fail-on).",
            file=sys.stderr,
        )
        return FAIL_ON_EXIT_CODE
    return 0


def _build_judge_provider(args: argparse.Namespace) -> JudgeProvider:
    provider = args.judge_provider
    if provider == "fake":
        return FakeJudgeProvider()
    if provider == "openai-compatible":
        if not args.judge_model or not args.judge_model.strip():
            raise ConfigError("--judge-model is required when --judge-provider openai-compatible is selected.")
        return OpenAICompatibleJudgeProvider(
            model=args.judge_model,
            base_url=args.judge_base_url,
            api_key_env=args.judge_api_key_env,
            response_format_mode=args.judge_response_format,
        )
    raise ConfigError(f"Unsupported judge provider '{provider}'; valid providers: fake, openai-compatible.")


def _build_target_adapter(target_config: TargetConfig) -> TargetAdapter:
    if target_config.adapter_type == "python_workflow":
        return PythonWorkflowAdapter(target_config)
    if target_config.adapter_type == "http":
        return HttpTargetAdapter(target_config)
    raise ConfigError(f"Unsupported adapter_type: {target_config.adapter_type}")


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
