"""EvaluatorRunner — orchestrate the full evaluation for one target.

Setup once, capture a baseline, then drive each AttackCase through the hybrid
oracle in FIFO order: adapter -> EvidenceExtractor -> JudgeProvider ->
DeterministicValidator -> FindingBuilder. Findings are aggregated into an
EvalReport. Failures (AdapterError / JudgeError) propagate — fail fast, no retry,
no silent continue.
"""

from agentic_security_eval.adapters.base import TargetAdapter
from agentic_security_eval.core.models import AttackCase, EvalReport, JudgeRequest
from agentic_security_eval.oracle.evidence import EvidenceExtractor
from agentic_security_eval.oracle.finding_builder import FindingBuilder
from agentic_security_eval.oracle.judge import JudgeProvider
from agentic_security_eval.oracle.validator import DeterministicValidator
from agentic_security_eval.scheduler.fifo import FifoScheduler

from .aggregator import ReportAggregator
from .baseline import BaselineRunner


class EvaluatorRunner:
    """Run a list of attack cases against a target and produce an EvalReport."""

    def __init__(
        self,
        target_id: str,
        adapter: TargetAdapter,
        judge_provider: JudgeProvider,
    ) -> None:
        self.target_id = target_id
        self.adapter = adapter
        self.judge_provider = judge_provider
        self.extractor = EvidenceExtractor()
        self.validator = DeterministicValidator()
        self.finding_builder = FindingBuilder()
        self.aggregator = ReportAggregator()

    def run(self, cases: list[AttackCase]) -> EvalReport:
        self.adapter.setup()
        baseline_trace = BaselineRunner(self.adapter).run()

        scheduler = FifoScheduler(cases)
        findings = []
        while scheduler.has_next():
            case = scheduler.next()

            self.adapter.reset()
            self.adapter.run_scenario(case)
            attack_trace = self.adapter.get_trace()

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
            if finding is not None:
                findings.append(finding)

        return self.aggregator.build(self.target_id, cases, findings)
