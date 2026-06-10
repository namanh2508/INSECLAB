"""TraceEvaluationRunner — assess one pre-recorded trace bundle offline.

Same hybrid oracle as the live runner (extractor -> judge -> validator ->
finding builder), but it consumes a ``TraceEvaluationInput`` directly: no
adapter, no baseline run, no live target. Exactly one case is evaluated, so the
report has ``total_cases == 1`` and 0 or 1 findings. Findings stay
evidence-grounded. Typed errors propagate (fail fast).
"""

from agentic_security_eval.core.models import EvalReport, JudgeRequest, TraceEvaluationInput
from agentic_security_eval.oracle.evidence import EvidenceExtractor
from agentic_security_eval.oracle.finding_builder import FindingBuilder
from agentic_security_eval.oracle.judge import JudgeProvider
from agentic_security_eval.oracle.validator import DeterministicValidator

from .aggregator import ReportAggregator


class TraceEvaluationRunner:
    """Evaluate a single trace bundle and return an EvalReport."""

    def __init__(self, target_id: str, judge_provider: JudgeProvider) -> None:
        self.target_id = target_id
        self.judge_provider = judge_provider
        self.extractor = EvidenceExtractor()
        self.validator = DeterministicValidator()
        self.finding_builder = FindingBuilder()
        self.aggregator = ReportAggregator()

    def run(self, trace_input: TraceEvaluationInput) -> EvalReport:
        case = trace_input.attack_case
        attack_trace = trace_input.attack_trace
        baseline_trace = trace_input.baseline_trace

        evidence = self.extractor.extract(case, attack_trace, baseline_trace)
        request = JudgeRequest(
            attack_case=case,
            baseline_trace=baseline_trace,
            attack_trace=attack_trace,
            evidence=evidence,
        )
        decision = self.judge_provider.judge(request)
        validated, notes = self.validator.validate(decision, case, evidence)
        finding = self.finding_builder.build(case, validated, evidence, notes)

        findings = [finding] if finding is not None else []
        return self.aggregator.build(self.target_id, [case], findings)
