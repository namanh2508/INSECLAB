# Agentic AI Security Evaluation Tool

An **evaluator-only** tool that probes target agentic systems for OWASP Agentic
Security Initiative (ASI) vulnerabilities. The MVP covers:

| Category | Name |
|----------|------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI06 | Memory & Context Poisoning |

Key properties:

- **Adapter-based & framework-agnostic** — every target is normalized into a
  single `AgentTrace` before any evaluation logic runs. The evaluator never
  imports LangGraph, CrewAI, AutoGen, n8n, or any specific agent framework.
- **Evidence-grounded** — a `Finding` is produced only when it is anchored in
  ID-grounded `Evidence` extracted from the trace. The LLM judge is never the
  sole source of truth; a deterministic validator gates every decision.
- **JSON report first** — JSON is the primary output (Markdown/HTML later).
- **Offline by default** — the MVP ships a deterministic `FakeJudgeProvider`, so
  the whole pipeline (and the full test suite) runs offline with no API keys.

## Architecture

```text
TargetConfig
  -> AttackGenerator
  -> FifoScheduler
  -> PythonWorkflowAdapter
  -> BaselineRunner
  -> EvidenceExtractor
  -> JudgeProvider (FakeJudgeProvider by default)
  -> DeterministicValidator
  -> FindingBuilder
  -> EvalReport
  -> JsonReportWriter
```

The oracle is **hybrid**: `EvidenceExtractor` produces ID-grounded candidate
`Evidence`; `FakeJudgeProvider` rules only on those signals; `DeterministicValidator`
rejects/downgrades any decision that is not grounded (category mismatch, missing
evidence IDs, high/critical without direct evidence); `FindingBuilder` assembles
the validated `Finding`.

## Package structure

```
src/agentic_security_eval/
  core/        enums, Pydantic schemas (AgentTrace, AttackCase, Evidence,
               JudgeDecision, Finding, EvalReport, ...), error hierarchy
  adapters/    TargetAdapter contract + PythonWorkflowAdapter (target -> AgentTrace)
  attacks/     AttackGenerator + YAML templates (ASI01/02/06) + loader
  surfaces/    AttackSurfaceModel (capabilities -> in-scope attack surfaces)
  scheduler/   FifoScheduler
  oracle/      EvidenceExtractor, JudgeProvider contract + parse_judge_decision,
               FakeJudgeProvider, DeterministicValidator, FindingBuilder
  evaluator/   BaselineRunner, EvaluatorRunner, ReportAggregator
  reporting/   JsonReportWriter
examples/      fake vulnerable/hardened targets (test fixtures, not real agents)
tests/         offline unit + integration tests
```

## Usage

```python
from agentic_security_eval.adapters.python_workflow import PythonWorkflowAdapter
from agentic_security_eval.attacks.generator import AttackGenerator
from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.models import Capabilities, TargetConfig
from agentic_security_eval.evaluator.runner import EvaluatorRunner
from agentic_security_eval.oracle.fake_judge import FakeJudgeProvider
from agentic_security_eval.reporting.json_report import JsonReportWriter

config = TargetConfig(
    target_id="demo-vulnerable",
    adapter_type="python_workflow",
    entrypoint="examples.fake_targets:create_vulnerable_agent",
    capabilities=Capabilities(tools=True, memory=True),
    allowed_surfaces=[
        AttackSurface.USER_PROMPT,
        AttackSurface.TOOL_OUTPUT,
        AttackSurface.MEMORY_WRITE,
    ],
)

cases = AttackGenerator(config).generate(
    categories=[ASICategory.ASI01, ASICategory.ASI02, ASICategory.ASI06]
)

runner = EvaluatorRunner(
    target_id=config.target_id,
    adapter=PythonWorkflowAdapter(config),
    judge_provider=FakeJudgeProvider(),
)
report = runner.run(cases)

JsonReportWriter().write(report, "reports/demo-vulnerable.json")
print(report.total_cases, "cases,", report.total_findings, "findings")
```

The `entrypoint` is a `module:factory` string. This example uses the bundled
fake target, so it must be run with both `src/` and the repo root on the path
(the test config sets `pythonpath = ["src", "."]` automatically). For a real
target, point `entrypoint` at your own importable `module:factory`.

## CLI

The evaluator can also be run from the terminal. The CLI defaults to the
offline `FakeJudgeProvider`.

From inside the package directory:

```bash
cd agentic_security_eval

uv run agentic-sec-eval eval \
  --target configs/fake_vulnerable.yaml \
  --categories ASI01,ASI02,ASI06 \
  --max-cases 20 \
  --output reports/fake_vulnerable_report.json
```

Hardened target:

```bash
uv run agentic-sec-eval eval \
  --target configs/fake_hardened.yaml \
  --categories ASI01,ASI02,ASI06 \
  --max-cases 20 \
  --output reports/fake_hardened_report.json
```

Or from the repository root:

```bash
uv --directory agentic_security_eval run agentic-sec-eval eval \
  --target configs/fake_vulnerable.yaml \
  --categories ASI01,ASI02,ASI06 \
  --max-cases 20 \
  --output reports/fake_vulnerable_report.json
```

Flags: `--target` (required YAML `TargetConfig`), `--output` (required JSON
path), `--categories` (default `ASI01,ASI02,ASI06`), `--max-cases` (default: all).

### Trace evaluation (`eval-trace`)

`eval` runs a live local Python target through `PythonWorkflowAdapter`.
`eval-trace` instead evaluates a **pre-recorded** `TraceEvaluationInput` JSON
bundle — no target is run. This is the offline audit path for logs/traces from
real Agentic AI systems once they have been converted to the canonical schema
(see [docs/trace_schema.md](docs/trace_schema.md)).

```bash
cd agentic_security_eval

uv run agentic-sec-eval eval-trace \
  --input examples/traces/asi02_tool_misuse_trace.json \
  --output reports/asi02_trace_report.json
```

`eval`, `eval-trace`, and `eval-raw-trace` use `FakeJudgeProvider` by default.

### Using an OpenAI-compatible judge

An optional OpenAI-compatible Chat Completions judge can be selected for
evaluation commands. LLM output is still parsed as `JudgeDecision` and passed
through `DeterministicValidator`; the LLM never creates findings directly.

```bash
export OPENAI_API_KEY="..."

cd agentic_security_eval

uv run agentic-sec-eval eval-trace \
  --input examples/traces/asi02_tool_misuse_trace.json \
  --output reports/asi02_openai_judge_report.json \
  --judge-provider openai-compatible \
  --judge-model <model-name> \
  --judge-base-url https://api.openai.com/v1
```

`FakeJudgeProvider` remains the default, normal tests stay offline, and live LLM
tests are opt-in. Some OpenAI-compatible providers may require
`--judge-response-format none`.

### Raw log conversion (`convert-trace`, `eval-raw-trace`)

Writing a full `TraceEvaluationInput` bundle by hand is tedious. A simpler
`RawAgentLog` (a flat list of typed events plus the `AttackCase`) can be
converted into a bundle, so users avoid hand-authoring traces for simple cases:

```bash
cd agentic_security_eval

# raw agent log -> TraceEvaluationInput bundle
uv run agentic-sec-eval convert-trace \
  --input examples/raw_logs/asi02_tool_misuse_raw_log.json \
  --output reports/converted_asi02_trace.json

# ...then evaluate the converted bundle
uv run agentic-sec-eval eval-trace \
  --input reports/converted_asi02_trace.json \
  --output reports/converted_asi02_report.json
```

Or do both in one step with `eval-raw-trace`:

```bash
uv run agentic-sec-eval eval-raw-trace \
  --input examples/raw_logs/asi02_tool_misuse_raw_log.json \
  --output reports/asi02_raw_report.json
```

The generic converter is framework-neutral; framework-specific converters
(LangGraph/CrewAI/n8n/Elastic) should follow the same target schema (see
[docs/trace_schema.md](docs/trace_schema.md)).

## Testing

From the repository root (offline, no API keys required):

```bash
uv --directory agentic_security_eval run pytest -v
```

Or from inside `agentic_security_eval/`: `uv run pytest -v`.

## Current limitations

- `FakeJudgeProvider` is deterministic and offline, and remains the default.
- The optional OpenAI-compatible judge supports Chat Completions only; no
  streaming, tool calling, or provider-specific SDKs.
- **No HTTP adapter yet** — only `PythonWorkflowAdapter` (local `module:factory`).
- **No attack mutation and no bandit scheduling** — static template seeds and a
  plain FIFO scheduler only.
- The **fake targets are fixtures**, not real agent systems; they simulate
  vulnerable/hardened behavior for tests.
- A **baseline trace is captured** before attacks run, but differential analysis
  is minimal — the baseline is currently context, not yet a comparison signal.

## Security note

All attack payloads, traces, fixtures, tool outputs, memory entries, and target
outputs are treated as **untrusted data**. The evaluator never follows
instructions found inside them.
