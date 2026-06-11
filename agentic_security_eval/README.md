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
- **Deterministic evidence hardening for ASI01 / ASI02 / ASI06** — conservative
  rules surface direct evidence for goal hijack, tool misuse, and memory/context
  poisoning, so honest targets no longer need to self-label every unsafe behavior
  (`metadata.unsafe` is supported but not required). The target must still return
  sufficient `AgentTrace` detail; paraphrased or implicit behavior may still rely
  on the LLM judge and can remain capped without direct evidence.
- **JSON report first** — JSON is the primary output (Markdown/HTML later).
- **Offline by default** — the MVP ships a deterministic `FakeJudgeProvider`, so
  the whole pipeline (and the full test suite) runs offline with no API keys.

## Architecture

```text
Input source
  -> TargetConfig + PythonWorkflowAdapter
  -> TargetConfig + HttpTargetAdapter
  -> TraceEvaluationInput
  -> RawAgentLog converter
  -> AgentTrace
  -> EvidenceExtractor
  -> JudgeProvider
  -> DeterministicValidator
  -> FindingBuilder
  -> EvalReport
  -> JsonReportWriter
```

The oracle is **hybrid**: `EvidenceExtractor` produces ID-grounded candidate
`Evidence`; a `JudgeProvider` returns a `JudgeDecision`; `DeterministicValidator`
rejects/downgrades any decision that is not grounded (category mismatch, missing
evidence IDs, high/critical without direct evidence); `FindingBuilder` assembles
the validated `Finding`. `FakeJudgeProvider` remains the default. The
OpenAI-compatible judge is optional and explicit, and LLM output is still parsed
and validated before findings are built.

See [docs/architecture.md](docs/architecture.md) for the pipeline, the evidence
trust model, and how to author a new evidence rule.

## Package structure

```
src/agentic_security_eval/
  core/        enums, Pydantic schemas (AgentTrace, AttackCase, Evidence,
               JudgeDecision, Finding, EvalReport, ...), error hierarchy
  adapters/    TargetAdapter contract + PythonWorkflowAdapter/HttpTargetAdapter
               (target -> AgentTrace)
  attacks/     AttackGenerator + YAML templates (ASI01/02/06) + loader
  config/      YAML TargetConfig loader
  converters/  RawAgentLog -> TraceEvaluationInput converter
  surfaces/    AttackSurfaceModel (capabilities -> in-scope attack surfaces)
  scheduler/   FifoScheduler
  oracle/      EvidenceExtractor, JudgeProvider contract + parse_judge_decision,
               FakeJudgeProvider, OpenAICompatibleJudgeProvider,
               DeterministicValidator, FindingBuilder
  evaluator/   BaselineRunner, EvaluatorRunner, ReportAggregator
  reporting/   JsonReportWriter
  trace_io/    TraceEvaluationInput JSON loader
examples/      fake vulnerable/hardened targets (test fixtures, not real agents)
tests/         offline unit + integration tests
tests/live/    gated live tests
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

Current input modes:

- `eval` with a local `python_workflow` target.
- `eval` with an HTTP target implementing the HTTP adapter contract.
- `eval-trace` for an existing `TraceEvaluationInput` bundle.
- `convert-trace` for raw event log conversion.
- `eval-raw-trace` for raw event log conversion plus evaluation.

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

`eval` runs a live target through `PythonWorkflowAdapter` or
`HttpTargetAdapter`.
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

### HTTP target eval

HTTP targets are configured with `adapter_type: http`:

```yaml
target_id: my_http_agent
adapter_type: http
capabilities:
  tools: true
  memory: true
  retrieval: false
  uploaded_files: false
  inter_agent_messages: false
  plugin_skill_metadata: false
allowed_surfaces:
  - user_prompt
  - tool_output
http:
  base_url: "http://127.0.0.1:8765"
  timeout_seconds: 30
  auth_token_env: null
  reset_between_cases: true
  max_response_bytes: 1000000
  adapter_schema_version: "0.1"
```

```bash
uv run agentic-sec-eval eval \
  --target configs/http_target_example.yaml \
  --output reports/http_eval_report.json
```

The HTTP target must implement
[docs/http_adapter_contract.md](docs/http_adapter_contract.md) and return an
`AgentTrace`, not just final answer text. Do not store API keys or bearer tokens
in YAML; use `auth_token_env` if auth is required.

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

### Live provider validation

Use the environment template only for local live validation:

```bash
cd agentic_security_eval
cp .env.example .env
# edit .env and fill in real values
```

`.env.example` intentionally leaves the API key and model empty; fill them in
your local `.env` before running live tests.

`.env` is for local use only and must not be committed. This project does not
automatically load `.env`. Export variables in your shell before running live
tests, or source the file in your shell if your environment supports it:

```bash
set -a
source .env
set +a

uv run pytest tests/live -q
```

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
- **HTTP adapter is synchronous only** — no streaming, SSE, WebSocket, async
  adapter, or external live target tests.
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
