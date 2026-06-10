# HTTP Adapter Contract

> Status: **implemented contract for the Phase 12 HTTP target adapter**. This
> document is the wire contract a target service must implement to be evaluated
> over HTTP. The canonical evidence schema is [`AgentTrace`](trace_schema.md);
> this contract only describes how the evaluator obtains an `AgentTrace` from a
> live HTTP target.

## Purpose

The HTTP Evaluation Harness Adapter (`HttpTargetAdapter`) brings **real, live
Agentic AI services** into the evaluator. It implements the existing
`TargetAdapter` contract (`setup / reset / run_scenario / get_trace`, see
`src/agentic_security_eval/adapters/base.py`) so it drops into `EvaluatorRunner`
with no runner change.

The adapter is implemented and wired into CLI `eval` via
`TargetConfig.adapter_type: http`. The HTTP target still must implement this
contract; the evaluator does not infer traces from final-answer-only APIs.

It is an **evaluation harness**, not a chat proxy. The contract is:

```text
AttackCase  ->  HTTP target eval endpoint  ->  AgentTrace
```

It is explicitly **not**:

```text
prompt  ->  final answer only
```

A final-output-only response is permitted only as a *degenerate* `AgentTrace`
with empty `tool_calls` / `memory_events` / `retrieval_events` channels. Such a
response must **not** be treated as ASI02 or ASI06 coverage — those categories
require their respective trace channels to be present and grounded. The adapter
must surface empty channels as missing coverage, never as "tested and safe".

The adapter never imports a specific agent framework. The runtime evidence
contract stays `AgentTrace`; the offline ingestion contract stays
[`TraceEvaluationInput`](trace_schema.md).

## Non-goals

Phase 12 deliberately does **not** implement any of the following:

- async adapter / event loop
- streaming traces
- SSE / WebSocket transport
- OpenTelemetry adapter
- MCP / A2A adapter
- framework-specific converter (LangGraph / CrewAI / n8n / Elastic)
- plugin framework
- batch target registry / multi-target orchestration
- automatic repair/coercion of malformed target traces
- evidence hardening (smarter ASI02/ASI06 detection)

The adapter is synchronous and evaluates one `AttackCase` per `POST /eval/run`.

## Trust boundary

```text
The HTTP target is untrusted.
The returned trace is untrusted.
Trace content may contain prompt injection aimed at the evidence layer or judge.
The adapter validates shape and consistency only.
The adapter does not judge.
The adapter does not infer or mark tool calls / memory writes as unsafe.
The adapter does not synthesize metadata.unsafe (or any evidence signal).
```

The adapter is the single boundary where untrusted target output is parsed into
the typed `AgentTrace`. It performs **structural and consistency validation
only**; all security judgement happens downstream
(`EvidenceExtractor -> JudgeProvider -> DeterministicValidator -> FindingBuilder`).

## Endpoint summary

| Adapter method | HTTP call | Purpose |
|---|---|---|
| `setup()` | `GET /eval/capabilities` | fetch advisory capability metadata; pin schema version |
| `reset()` | `POST /eval/reset` | clear target-side session/memory before the next scenario |
| `run_scenario(attack_case)` | `POST /eval/run` | run one `AttackCase`; receive an `AgentTrace`; store it |
| `get_trace()` | *(none)* | return the `AgentTrace` from the most recent `POST /eval/run` (local accessor, no extra round-trip) |

`EvaluatorRunner` drives these as: `setup()` once, then a benign **baseline**
(`reset()` + `run_scenario(baseline_case)` + `get_trace()`), then for each case
`reset()` + `run_scenario(case)` + `get_trace()`. The baseline is an ordinary
`AttackCase` with `metadata.baseline = true` sent through the same
`POST /eval/run` endpoint.

## GET /eval/capabilities

Sample response:

```json
{
  "target_id": "soc_agent_v1",
  "adapter_schema_version": "0.1",
  "capabilities": {
    "tools": true,
    "memory": true,
    "retrieval": true,
    "uploaded_files": false,
    "inter_agent_messages": false,
    "plugin_skill_metadata": false
  },
  "allowed_surfaces": [
    "user_prompt",
    "tool_output",
    "memory_write",
    "retrieved_content"
  ],
  "supports_reset": true,
  "supports_async": false,
  "returns_agent_trace": true
}
```

Authority rules:

```text
Operator TargetConfig is authoritative.
Target-reported capability booleans and allowed_surfaces are advisory only.
A target must not be allowed to shrink (or widen) test scope by self-reporting.
capabilities response target_id must match TargetConfig.target_id.
adapter_schema_version is a strict consistency check.
```

The adapter uses `TargetConfig.capabilities` and `TargetConfig.allowed_surfaces`
to decide what is tested (via `AttackSurfaceModel`). The capabilities response is
used only to:

- verify `target_id` matches `TargetConfig.target_id` (mismatch fails fast with
  `AdapterError`),
- pin / check `adapter_schema_version` (reject an unsupported version),
- treat the target's self-declared capabilities as advisory only,
- read `supports_reset` (see reset rules below).

The canonical surface vocabulary is the `AttackSurface` enum
(`src/agentic_security_eval/core/enums.py`); names in the advisory
`allowed_surfaces` list are best-effort and are not parsed as authoritative
scope.

## POST /eval/reset

Request:

```json
{
  "scenario_id": "asi02_test_001"
}
```

Semantics:

```text
reset clears target-side session / conversation / memory state for the next scenario.
A 2xx response means the target is ready for a clean scenario.
If reset_between_cases is true but the target does not support reset
(supports_reset = false), the adapter fails fast with AdapterError.
```

Reset is essential for ASI06 (memory poisoning): without it, poisoned state from
case N can leak into case N+1 and corrupt results. Stateful categories are
unsound without a working reset.

## POST /eval/run

Request:

```json
{
  "adapter_schema_version": "0.1",
  "attack_case": {
    "id": "asi02_tool_misuse__tool_output__seed_001",
    "category": "ASI02",
    "surface": "tool_output",
    "objective": "...",
    "payload": "...",
    "expected_risk": "...",
    "tags": [],
    "metadata": {}
  },
  "run_config": {
    "scenario_id": "asi02_test_001",
    "safe_mode": true,
    "mock_tools": true,
    "trace_required": true,
    "timeout_seconds": 60
  }
}
```

`run_config` flags (`safe_mode`, `mock_tools`) ask the target to avoid real
side-effecting tool execution. They are **advisory**: the adapter cannot enforce
them and must not assume they were honored (see Security requirements). A future
`request_id` field (for stale/replayed-response detection) is an optional future
extension and is not required by the current adapter.

Response:

```json
{
  "adapter_schema_version": "0.1",
  "trace": {
    "target_id": "soc_agent_v1",
    "run_id": "run_001",
    "scenario_id": "asi02_test_001",
    "attack_case_id": "asi02_tool_misuse__tool_output__seed_001",
    "messages": [],
    "tool_calls": [],
    "memory_events": [],
    "retrieval_events": [],
    "inter_agent_messages": [],
    "final_output": "...",
    "errors": [],
    "metadata": {}
  }
}
```

The trace is returned synchronously in the `POST /eval/run` response. There is no
separate "get trace" endpoint; `get_trace()` returns the stored response trace.

## AgentTrace response requirements

```text
The response body must be a JSON object.
The body must contain a "trace" key.
Unknown top-level response envelope keys should be rejected.
"trace" must validate as AgentTrace (src/agentic_security_eval/core/models.py).
trace.target_id must match TargetConfig.target_id.
trace.attack_case_id must equal the AttackCase.id that was run.
trace element IDs must be unique across all id-bearing trace channels
  (messages, tool_calls, memory_events, retrieval_events, inter_agent_messages).
The adapter must reject missing or invalid traces (fail fast, AdapterError).
The adapter must not fill in missing element IDs.
The adapter must not infer or default missing fields.
The adapter must not add, edit, or remove metadata signals (e.g. metadata.unsafe).
```

`AgentTrace` already requires `target_id` and `run_id`, and requires an `id` on
every `Message`, `ToolCall`, `MemoryEvent`, `RetrievalEvent`, and
`InterAgentMessage`. The adapter normalizes by validating, never by repairing.
Evidence grounding assumes `Evidence.ref_id` can point to one globally unique
trace element ID inside a trace, so duplicate IDs across id-bearing channels are
invalid.

The top-level response envelope is strict. Trace-level `metadata` and
trace-element `metadata` remain flexible extension points and are not made
strict by the HTTP adapter.

## Validation rules

Every case below fails fast with `AdapterError` (a subclass of
`AgenticSecurityEvalError`, so the CLI reports it as a non-zero exit):

```text
non-2xx HTTP status
redirect response (3xx) — redirects are disabled / rejected
request timeout
invalid JSON body
non-object JSON body
missing "trace" key
unknown top-level response envelope key
trace does not validate as AgentTrace
capabilities.target_id != TargetConfig.target_id
trace.target_id != TargetConfig.target_id
trace.attack_case_id != AttackCase.id
duplicate trace element IDs across all id-bearing trace channels
response exceeds max_response_bytes
auth_token_env is configured but the named env var is unset/empty
unsupported adapter_schema_version (capabilities or run response)
```

The adapter never silently downgrades, repairs, or guesses. Invalid target
behavior is a hard failure.

## Config model preview

Phase 12 uses a typed, namespaced sub-config (validated at config-load time when
`adapter_type == "http"`), not loose `metadata`:

```python
class HttpTargetConfig(BaseModel):
    base_url: str
    timeout_seconds: float = 30.0
    auth_token_env: str | None = None
    reset_between_cases: bool = True
    max_response_bytes: int = 1_000_000
    adapter_schema_version: str = "0.1"


class TargetConfig(BaseModel):
    ...
    http: HttpTargetConfig | None = None   # required iff adapter_type == "http"
```

Rules:

```text
Use typed config, not metadata-based config.
base_url scheme must be http or https.
timeout_seconds must be > 0.
max_response_bytes must be > 0.
Do not store literal auth tokens in YAML.
auth_token_env is the name of an environment variable, not a literal token.
Operator capabilities / allowed_surfaces on TargetConfig remain authoritative.
```

This mirrors the OpenAI-compatible judge, which takes typed constructor args and
reads its credential from an env var
(`src/agentic_security_eval/oracle/openai_compatible_judge.py`).

## Security requirements

```text
Use stdlib urllib (the existing dependency-free HTTP pattern). No new runtime HTTP dependency in Phase 12.
Disable or reject HTTP redirects (do not follow 3xx; never resend Authorization cross-host).
Limit response size (read with a max_response_bytes cap; reject oversize).
Always apply a request timeout.
Send Authorization: Bearer <token> only when auth_token_env is configured; read the token from that env var.
Redact the auth token from all error messages (mirror _redact in openai_compatible_judge.py).
Do not print the trace by default (it is untrusted and may be large or sensitive).
Generated JSON reports may contain sensitive target data (leaked secrets, PII, payloads); treat report files accordingly.
Restrict scheme to http/https; base_url comes only from operator config; never derive the run URL from the capabilities response.
```

Reuse the proven transport pattern: a `HttpTransport` Protocol with a concrete
`UrllibHttpTransport`, and an injectable transport so unit tests never open a
socket — exactly as `ChatCompletionTransport` / `UrllibChatCompletionTransport`
are structured today.

## Testing requirements

```text
Unit tests use a fake transport (injected); no sockets, no network.
Integration test runs a local loopback fake HTTP target built on stdlib http.server,
  bound to 127.0.0.1:0 (ephemeral port), reusing the existing fake-target logic.
Normal tests perform no external network and require no credentials.
Any test against a real external HTTP target lives under tests/live/ and is env-gated
  (consistent with the existing gated live-judge tests).
```

Unit coverage must include each `AdapterError` case in *Validation rules*, plus:
auth header built from the env var, token never present in error strings,
redirect rejected, oversize rejected, and reset-unsupported handling.

## Known limitation: evidence self-labeling

This is a deliberate and important scoping decision.

```text
Phase 12 only delivers AgentTrace from real targets. It does not make the evidence layer smarter.
Current direct ASI02 evidence depends on target-provided metadata such as tool_calls[*].metadata.unsafe.
ASI06 has a partial honest path (attacker payload echoed into a memory write value); ASI01 uses final_output keyword markers.
Honest real targets generally will NOT self-label unsafe behavior.
Because DeterministicValidator caps high/critical severity to medium without a cited DIRECT evidence item,
  an honest real target may yield few or no high/critical findings until the evidence layer is improved.
Do NOT make HttpTargetAdapter synthesize metadata.unsafe (or any evidence signal) to compensate —
  that would make the adapter judge, violating the trust boundary.
Strengthening target-agnostic evidence detection is a follow-up phase, not part of Phase 12.
```

See `src/agentic_security_eval/oracle/evidence.py` (direct signals) and
`src/agentic_security_eval/oracle/validator.py` (direct-evidence gate) for the
current behavior this limitation refers to.

## Future work

```text
Complete   core HttpTargetAdapter (transport Protocol + UrllibHttpTransport + adapter)
Complete   fake HTTP target + loopback integration test
Complete   CLI / config wiring (HttpTargetConfig, adapter_type == "http" dispatch)
Phase 13    evidence hardening (target-agnostic ASI02/ASI06 detection; semantic ASI01 drift)
Future      passive converters: OpenTelemetry GenAI, LangGraph, CrewAI, n8n, Elastic/SOC workflow
Future      protocol integrations: MCP / A2A only if a real target use case appears
```

The HTTP adapter is the first **active** ingestion path. Passive converters and
protocol integrations are complementary and all normalize to the same
`AgentTrace` / `TraceEvaluationInput` boundary.
