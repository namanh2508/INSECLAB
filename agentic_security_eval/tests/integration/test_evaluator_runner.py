"""Integration: TargetConfig -> AttackGenerator -> EvaluatorRunner -> EvalReport -> JSON.

Drives the full pipeline through the FakeJudgeProvider against the vulnerable and
hardened fake targets, then serializes the report.
"""

import json

from agentic_security_eval.adapters.python_workflow import PythonWorkflowAdapter
from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.core.enums import ASICategory, AttackSurface, Severity
from agentic_security_eval.core.models import Capabilities, TargetConfig
from agentic_security_eval.evaluator.runner import EvaluatorRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter

CATEGORIES = [ASICategory.ASI01, ASICategory.ASI02, ASICategory.ASI06]
ALLOWED = [AttackSurface.USER_PROMPT, AttackSurface.TOOL_OUTPUT, AttackSurface.MEMORY_WRITE]


def _config(entrypoint: str) -> TargetConfig:
    return TargetConfig(
        target_id="t",
        adapter_type="python_workflow",
        entrypoint=entrypoint,
        capabilities=Capabilities(
            tools=True, memory=True, retrieval=False, uploaded_files=False,
            inter_agent_messages=False, plugin_skill_metadata=False,
        ),
        allowed_surfaces=ALLOWED,
    )


def _run(entrypoint: str, target_id: str):
    config = _config(entrypoint)
    cases = AttackGenerator(config).generate(categories=CATEGORIES)
    adapter = PythonWorkflowAdapter(config)
    runner = EvaluatorRunner(target_id=target_id, adapter=adapter, judge_provider=FakeJudgeProvider())
    return runner.run(cases)


def test_vulnerable_target_produces_expected_findings():
    report = _run("examples.fake_targets:create_vulnerable_agent", "vuln")
    assert report.total_cases > 0
    assert report.total_findings > 0

    severities_by_category: dict = {}
    for finding in report.findings:
        severities_by_category.setdefault(finding.category, set()).add(finding.severity)

    assert Severity.MEDIUM in severities_by_category.get(ASICategory.ASI01, set())
    assert Severity.HIGH in severities_by_category.get(ASICategory.ASI02, set())
    assert Severity.CRITICAL in severities_by_category.get(ASICategory.ASI06, set())


def test_hardened_target_produces_no_high_or_critical_findings():
    report = _run("examples.fake_targets:create_hardened_agent", "hard")
    assert report.total_cases > 0
    assert all(f.severity not in (Severity.HIGH, Severity.CRITICAL) for f in report.findings)
    # the hardened fake target is not vulnerable, so it yields no findings at all
    assert report.total_findings == 0


def test_report_serialization_roundtrips(tmp_path):
    report = _run("examples.fake_targets:create_vulnerable_agent", "vuln")
    path = JsonReportWriter().write(report, tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["report_id"] == "report__vuln"
    assert data["total_findings"] == report.total_findings
    assert len(data["findings"]) == report.total_findings
