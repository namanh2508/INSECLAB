# Architecture

A short orientation for contributors. For the agent operating rules see the root
[`AGENTS.md`](../../AGENTS.md) and the package [`AGENTS.md`](../AGENTS.md); for the
evidence schema see [`trace_schema.md`](trace_schema.md).

## Pipeline

```text
Input source (TargetAdapter / TraceEvaluationInput / RawAgentLog)
  -> AgentTrace
  -> EvidenceExtractor   (+ oracle/evidence_rules/*)
  -> JudgeProvider
  -> DeterministicValidator
  -> FindingBuilder
  -> EvalReport -> JsonReportWriter
```

The oracle is **hybrid**: a deterministic evidence layer plus an (untrusted) LLM
judge, with a deterministic validator gating every finding.

## Source layout

```text
src/agentic_security_eval/
  core/        Pydantic schemas, enums, typed error hierarchy
  adapters/    TargetAdapter contract + PythonWorkflow / HTTP adapters
  attacks/     AttackGenerator + YAML attack templates
  surfaces/    AttackSurfaceModel (capabilities -> in-scope attack surfaces)
  config/      YAML TargetConfig loader
  trace_io/    TraceEvaluationInput JSON loader
  converters/  RawAgentLog -> TraceEvaluationInput
  scheduler/   FifoScheduler
  oracle/      EvidenceExtractor + evidence_rules/ + judges + validator + finding builder
  evaluator/   live runner, trace runner, batch runner, baseline capture, report aggregator
  reporting/   JSON + batch JSON + Markdown report writers
```

Where future work lands (so the tree stays predictable):

- multi-target evaluation -> `evaluator/` (batch over a directory of trace files
  is implemented; see "Batch evaluation and reporting" below)
- HTML reports -> `reporting/` (render the existing `EvalReport` / `BatchReport`)
- framework converters (LangGraph, n8n, Elastic/SOAR) -> `converters/`, each
  emitting `AgentTrace` or `RawAgentLog` (never a new schema)
- retrieval / inter-agent direct evidence -> a new `oracle/evidence_rules/` module
  plus a category-gated call in `EvidenceExtractor`
- baseline / differential analysis -> `evaluator/` (the baseline is captured today
  but used only as context, not yet a comparison signal)

## AgentTrace — the canonical contract

`AgentTrace` (`core/models.py`) is the single normalized representation of one
target run: `messages`, `tool_calls`, `memory_events`, `retrieval_events`,
`inter_agent_messages`, `final_output`, `errors`, `metadata`. **Every** input
path normalizes into it before any evaluation logic runs, so the evaluator never
depends on a specific agent framework. Two ingestion contracts feed it:

- `TraceEvaluationInput` — the canonical offline bundle (`eval-trace`).
- `RawAgentLog` — a convenience flat event list converted into the bundle.

## Adapter boundary

An adapter is the **only** place untrusted target output is parsed into a typed
`AgentTrace`. Adapters **do not** judge, synthesize direct evidence, or synthesize
`metadata.unsafe`. The HTTP adapter validates shape/consistency only (envelope,
required keys, id uniqueness, `target_id`/`attack_case_id` match) and never
repairs a trace. `run_scenario` may return the trace or store it for
`get_trace()`; `EvaluatorRunner` reads it via `get_trace()`.

## EvidenceExtractor facade

`oracle/evidence.py` owns, and is the **only** owner of:

- trace-channel iteration (fixed order),
- **category-gating** (`if attack_case.category == ASICategory.ASIxx:`),
- `Evidence` construction and stable id assignment (`ev-001`, `ev-002`, ...),
- the cross-category *indirect* signals (`payload_observed`,
  `suspicious_retrieval_content`, `suspicious_inter_agent_message`,
  `final_output_observed`).

## evidence_rules and EvidenceCandidate

Category-specific deterministic logic lives in `oracle/evidence_rules/`
(`common.py` primitives, `candidate.py`, `asi01_goal_hijack.py`,
`asi02_tool_misuse.py`, `asi06_memory_poisoning.py`). A rule classifies one trace
element and returns an `EvidenceCandidate(signal, direct, reason, extra)` or
`None`. Matching is conservative, literal, and phrase-boundary based — not
semantic; paraphrased attacks are left to the judge. Blocked/refused markers
downgrade a direct candidate to an indirect one (e.g. `risky_tool_call_blocked`,
`attacker_goal_refused`).

## JudgeProvider is untrusted

`FakeJudgeProvider` is the deterministic default (offline tests use it). The
optional `OpenAICompatibleJudgeProvider` is explicit. Either way the raw output
goes through the strict `parse_judge_decision()` boundary, and the judge may cite
**only** existing `Evidence.id` values — it cannot invent evidence.

## DeterministicValidator — the trust gate

`oracle/validator.py` rejects a vulnerable decision whose cited evidence ids do
not exist, requires at least one valid cited item, and **downgrades high/critical
to medium unless a cited *direct* evidence item is present**. This is the
load-bearing invariant: because direct evidence is deterministic and
category-gated, an untrusted judge cannot mint a high/critical finding.

## Surface coverage and evidence depth

Attack **surfaces** (`surfaces/model.py`) are *generated inputs* — where an attack is
delivered (user prompt, retrieved content, tool output, memory write, ...). Evidence
**depth** is what the deterministic layer can actually produce for an attack on a
surface. They are not the same: the generator can emit cases on surfaces the
deterministic evidence layer does not deeply evaluate yet.

`surfaces/coverage.py` is the single source of truth that records, per
`(category, surface)`, one of `direct`, `indirect`, `generation_only`, or
`unsupported`. It is conservative and adds no detector logic: direct evidence is read
from each category's outcome channel (ASI01 `final_output`, ASI02 `tool_calls`, ASI06
`memory_events`), so surfaces that only deliver input (retrieval, inter-agent,
uploaded-file, tool-definition, plugin/skill metadata) are `indirect` or
`generation_only` — never falsely `direct`.

Inspect the current matrix (offline; no target/judge):

```bash
uv run agentic-sec-eval coverage              # human-readable table
uv run agentic-sec-eval coverage --format json
```

The matrix is the planning map for evidence-depth work: closing a gap means turning
a `generation_only`/`indirect` surface into `direct` by adding a category-gated rule
(below) and then updating `coverage.py`.

## Batch evaluation and reporting

`eval-traces` evaluates every `*.json` trace bundle in a directory through the same
offline path as `eval-trace`. `BatchTraceRunner` (`evaluator/batch_runner.py`)
discovers and sorts the files (failing fast on an invalid one rather than silently
skipping), runs each through `TraceEvaluationRunner`, and `build_batch_report`
(`reporting/batch_report.py`) folds the per-file `EvalReport`s into one `BatchReport`:
cross-file severity, category, and evidence-signal distributions plus the embedded
per-file reports. `BatchReport` *embeds* `EvalReport` unchanged and adds no new
evidence semantics.

Two artifacts are produced. The JSON report (`write_batch_report`) is the
machine-readable output for automation/CI. The optional Markdown report
(`reporting/markdown_report.py`) is for human review: it is deterministic, lists
evidence **IDs** rather than snippets, and pipe-escapes every table cell so untrusted
finding text cannot break the table layout. `--fail-on` reuses the single-run
severity gate (exit code 3) across all findings in all files.

## Authoring an evidence rule

1. Create or update `oracle/evidence_rules/<category>.py`.
2. Return `EvidenceCandidate | None` — one candidate per element.
3. Do **not** assign Evidence ids; do **not** construct `Evidence`/`Finding`/
   `JudgeDecision`; do **not** inspect `attack_case.category` (no `category`
   parameter — the gating-contract test enforces this).
4. Add the category-gated call in `EvidenceExtractor` (the facade owns iteration,
   gating, and id assignment).
5. Add rule-module unit tests, facade tests in `tests/unit/test_evidence_extractor.py`,
   and — if it proves an end-to-end honest path — an integration fixture under
   `examples/traces/` plus a `tests/integration/test_honest_*` case.
6. Keep direct evidence high-precision; route semantics to the judge, not the
   evidence layer.
