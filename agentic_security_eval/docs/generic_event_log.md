# Generic Agent Event Log (`RawAgentLog`)

## 1. Purpose

The **Generic Agent Event Log** (`RawAgentLog`) is the framework-neutral **passive
ingestion bridge**: a flat list of typed events plus the `AttackCase` under test,
which the tool normalizes into the canonical
[`TraceEvaluationInput`](trace_schema.md) so a recorded run can be audited offline —
no live target, no hand-written bundle.

```text
Generic Agent Event Log (RawAgentLog) JSON
  -> convert-trace
  -> TraceEvaluationInput
  -> eval-trace / eval-raw-trace / eval-traces
```

It is the single shape that real framework logs (LangGraph, CrewAI, n8n,
Elastic/SOAR, custom agents) should be mapped into. It is *not* a framework-specific
converter; framework converters are separate and target this shape (see §10).

## 2. Top-level shape

```json
{
  "schema_version": "0.1",
  "target_id": "recorded-agent",
  "run_id": "raw-run-1",
  "scenario_id": "scenario-a",
  "attack_case": { "...": "AttackCase" },
  "events": [ { "type": "..." } ],
  "metadata": {}
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | optional | Log format version. Defaults to `"0.1"`; only supported versions are accepted (currently `"0.1"`). An unsupported value fails fast. |
| `target_id` | **required** | Identifier of the system that produced the run. |
| `run_id` | **required** | Identifier of this run. |
| `scenario_id` | optional | Free-form scenario label, copied to the trace. |
| `attack_case` | **required** | The `AttackCase` the trace is evaluated against (`id`, `category`, `surface`, `objective`, `payload`, `expected_risk`, ...). Offline evaluation needs this pairing. |
| `events` | **required** (≥1) | Ordered list of typed events (§3). |
| `metadata` | optional | Free-form log metadata. |

## 3. Event types

The log uses a fixed, closed set of event types. Each maps 1:1 onto an `AgentTrace`
channel; only the fields for an event's `type` are used.

| `type` | Required fields | Maps to `AgentTrace` channel |
|---|---|---|
| `message` | `role`, `content` | `messages` |
| `tool_call` | `tool_name` | `tool_calls` |
| `memory_event` | `operation`, `key` | `memory_events` |
| `retrieval_event` | `source`, `content` | `retrieval_events` |
| `inter_agent_message` | `from_agent`, `to_agent`, `content` | `inter_agent_messages` |
| `final_output` | `content` | `final_output` (string) |
| `error` | `content` | `errors` |

Optional per-type fields are passed through where present: `tool_call` also takes
`arguments` and `result`; `memory_event` also takes `value`; `retrieval_event` also
takes `query`; any event may carry `metadata` and (for the id-bearing types) an
explicit `id`.

**`memory_event.operation` vocabulary.** Use the canonical values `write` and
`read`. Memory **writes** are what ASI06 memory-poisoning evidence is read from;
framework-specific synonyms (`store`, `set`, `update`, ...) must be normalized to
`write`/`read` **upstream** by the framework converter. The generic converter does
**not** remap operation names — that would be a semantic repair (§8).

## 4. Tool-call policy

The Generic Agent Event Log uses **combined** `tool_call` events only:

```json
{ "type": "tool_call", "tool_name": "send_email",
  "arguments": {"to": "x@example.com"}, "result": "sent" }
```

This matches the combined `AgentTrace.ToolCall` shape (`arguments` + `result` in one
object). Frameworks that emit a `tool_call_start` / `tool_call_result` pair must
**merge them upstream** into one combined event before emitting the log. Split
tool-call correlation (`correlation_id`) is **deferred** until a real source requires
it; it is intentionally not supported in this version.

## 5. Ordering policy

- **Input order is authoritative.** Elements appear in each channel in the order
  their events appear in `events`.
- The converter **does not sort by timestamp.** Timestamps are often missing, equal,
  or unreliable across frameworks, and sorting would make output nondeterministic on
  ties and diverge "what the log says" from "what was evaluated."
- If a source has timestamps, keep them only as event `metadata` (passthrough
  context); they must not drive ordering.

## 6. ID policy

- Explicit element `id`s are **preserved**.
- Missing `id`s are **generated deterministically** per channel (`msg-1`, `tool-1`,
  `mem-1`, `retrieval-1`, `inter-agent-1`), skipping any id already taken.
- **Duplicate explicit ids fail fast** (`ConfigError`) — the converter never silently
  normalizes ambiguous provenance.
- Ids are **unique across all id-bearing channels** within a trace.
- `final_output` and `error` events carry no element id.

## 7. Error policy

- A **malformed input event** (unknown `type`, missing required field, bad JSON,
  duplicate id, unsupported `schema_version`) is a **hard failure** — loading fails
  fast with `ConfigError`. Malformed events are never silently skipped, and there is
  no continue-on-error mode.
- An event of **`type: "error"`** is a *legitimate* record of the agent's own runtime
  error and is mapped into `trace.errors`. Do not confuse the two: one is bad input,
  the other is valid data describing the run.

## 8. Trust boundary

The converter **normalizes only**. It:

- maps events 1:1 into `AgentTrace` channels,
- assigns deterministic element ids,
- copies event `metadata` **verbatim**.

It **never**:

- judges or assigns verdicts/severity,
- synthesizes `metadata.unsafe` or any evidence signal,
- assigns `Evidence` ids (those are minted centrally by `EvidenceExtractor`),
- interprets content as instructions,
- executes tools, imports agent frameworks, or fetches URLs.

Target-provided `metadata.unsafe` on an input event **is** preserved (it is part of
the recorded trace), but the converter must never add it. All event content —
payloads, tool arguments/results, memory values, retrieved content — is **untrusted
data**; the evaluator never follows instructions found inside it. The only derived
field is a structural `trace.metadata["multiple_final_outputs"]` note when more than
one `final_output` event is present; it is not an evidence channel.

## 9. Example

A combined log exercising several channels lives at
[`examples/raw_logs/generic_event_log_combined_raw_log.json`](../examples/raw_logs/generic_event_log_combined_raw_log.json).
Convert and evaluate it offline:

```bash
cd agentic_security_eval

# convert to a TraceEvaluationInput bundle
uv run agentic-sec-eval convert-trace \
  --input examples/raw_logs/generic_event_log_combined_raw_log.json \
  --output reports/generic_combined_trace.json

# ...or convert and evaluate in one step
uv run agentic-sec-eval eval-raw-trace \
  --input examples/raw_logs/asi02_tool_misuse_raw_log.json \
  --output reports/asi02_raw_report.json
```

Converted bundles can be batch-evaluated together with `eval-traces`.

## 10. How framework converters should target this contract

Framework-specific converters (future work) **emit `RawAgentLog` or
`TraceEvaluationInput` — never a new schema, and never `AgentTrace` alone** (which
lacks the `AttackCase` pairing offline evaluation needs; `AgentTrace`-only is for
live in-process adapters).

- Prefer emitting **`RawAgentLog`** when the framework's events map cleanly to the
  flat typed list — you inherit deterministic ids, fail-fast loading, and
  normalization for free.
- Emit **`TraceEvaluationInput`** directly only when the source is already richly
  structured and the flat list would lose fidelity.

```text
LangGraph callbacks/events  -> message / tool_call / retrieval_event
CrewAI task logs            -> message / tool_call / inter_agent_message
n8n execution logs          -> tool_call / message / final_output
Elastic/SOAR workflow logs  -> tool_call / retrieval_event / final_output
custom agent telemetry      -> any of the above
```
