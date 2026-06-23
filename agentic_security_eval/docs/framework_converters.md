# Framework converters — input policy

This document defines how real Agentic AI framework traces enter the evaluator. It
is the **policy gate** for framework-specific converters; it is written *before* any
converter exists so the first implementation (LangGraph) is built against a real,
versioned export rather than a guessed schema.

> **Status (Phase 14.4.0):** No real LangGraph export has been collected yet. No
> converter exists. Phase 14.4.1 (the `langgraph-messages` converter) is **blocked**
> until at least two real samples are provided — see
> [Sample / version policy](#sample--version-policy) and
> [Collecting a real sample](#collecting-a-real-sample).

## Ingestion model

```text
Framework trace/log (exported JSON)
  -> framework converter (JSON-shape parser)   <-- this document governs it
  -> RawAgentLog
  -> convert-trace / eval-raw-trace
  -> TraceEvaluationInput
  -> EvidenceExtractor -> JudgeProvider -> DeterministicValidator
  -> JSON / Markdown report
```

A framework converter's **only** job is to map one framework's exported events into
the flat [`RawAgentLog`](generic_event_log.md) event list. Everything downstream
already exists and is trust-gated.

## Trust boundary

A framework converter **normalizes only**. It:

- parses already-**exported JSON** and maps fields 1:1 into `RawAgentLog` events,
- copies content into typed fields verbatim.

It **must never**:

- judge, or produce `Evidence`, `Finding`, or `JudgeDecision`,
- synthesize `metadata.unsafe` or any evidence signal,
- **infer the vulnerability category, surface, payload, or expected risk from trace
  content** — those come only from the paired `AttackCase` (see
  [AttackCase pairing](#attackcase-pairing)),
- **import a framework SDK** (`langgraph`, `langchain`, `crewai`, `autogen`, ...) at
  evaluator runtime — converters parse exported JSON, they do not run the framework,
- execute tools, fetch URLs, or call an LLM.

These mirror the rules already enforced for the Generic Agent Event Log and the
adapter boundary. The category is supplied by the `AttackCase`, carried into the
judge request, and enforced by `DeterministicValidator`; a converter that guessed it
would corrupt every verdict.

## Supported input-format naming

Framework input is selected by an explicit, **narrow** format name — naming the
*specific artifact*, not the framework as a whole:

| `--input-format` | Artifact | Status |
|---|---|---|
| `generic` (default) | Generic Agent Event Log (`RawAgentLog`) | implemented |
| `langgraph-messages` | a serialized LangGraph message list / `state["messages"]` | **planned (14.4.1, blocked on samples)** |

The MVP format is **`langgraph-messages`**, *not* the broad name `langgraph`. The
narrow name leaves room for other LangGraph artifacts later (e.g. a future
`langgraph-runtree`) without overloading one name or implying coverage that does not
exist.

## MVP source artifact

The `langgraph-messages` MVP consumes a **serialized LangGraph message
list** — the contents of `state["messages"]` (a list of LangChain `BaseMessage`s
serialized to JSON). It does **not** consume a LangSmith run tree, streaming chunks,
or live API responses.

### Expected shape — UNVERIFIED

The exact serialization is an **open question to be resolved from a real export**.
LangChain has at least two conventions, and the converter must be built against
whichever the recorded version actually emits:

```text
A. messages_to_dict():  [ {"type": "human",     "data": {"content": "...", ...}},
                          {"type": "ai",        "data": {"content": "...",
                                                          "tool_calls": [...]}},
                          {"type": "tool",      "data": {"content": "...",
                                                          "tool_call_id": "..."}} ]

B. model_dump() (flat): [ {"type": "human", "content": "..."},
                          {"type": "ai",    "content": "...", "tool_calls": [...]},
                          {"type": "tool",  "content": "...", "tool_call_id": "..."} ]
```

Do **not** implement against this section. Confirm the real key layout, the
`tool_calls` structure, and the human/ai/tool/system `type` tokens from the collected
sample before writing `converters/langgraph_messages.py`.

## Event mapping plan (for 14.4.1)

Exact MVP mapping once a real shape is confirmed:

| LangGraph artifact | → `RawAgentLog` event | Notes |
|---|---|---|
| `HumanMessage` / `SystemMessage` / `AIMessage` (text) | `message` (`role`, `content`) | role from the message type |
| `AIMessage.tool_calls[*]` + matching `ToolMessage` | **combined** `tool_call` (`tool_name`, `arguments`, `result`) | correlate by `tool_call_id`; one combined event per call |
| last `AIMessage` (or an explicit result field) | `final_output` | benign-or-not, copied verbatim |
| an explicit runtime error in the export | `error` | maps to `trace.errors` |

Everything else is **deferred** (see below). Tool-call correlation is by
`tool_call_id`; an `AIMessage.tool_calls` entry with no matching `ToolMessage` (or
vice-versa) is a shape the converter must handle explicitly (fail-fast or record
without a result) — to be decided against the real sample.

## Explicitly deferred

Not in the `langgraph-messages` MVP:

- LangSmith **run-tree** parsing
- **streaming** chunks / partial-token events
- graph **state** updates as `memory_event` (graph state is execution scratchpad,
  not persistent memory — mapping it would fabricate an ASI06 surface)
- **retriever node** results → `retrieval_event`
- **supervisor / subgraph handoffs** → `inter_agent_message`
- **live LangSmith API** calls
- any **SDK import** inside evaluator runtime

## AttackCase pairing

A framework export does not carry the `AttackCase` it should be evaluated against, so
the converter requires one **explicitly**:

- **Strict default:** an embedded `attack_case`, or a separate
  `--attack-case-file <AttackCase JSON>`.
- **No inference:** category, surface, payload, objective, and expected risk are
  never derived from trace content.
- A reference AttackCase fixture lives at
  [`examples/attack_cases/langgraph_tool_case.json`](../examples/attack_cases/langgraph_tool_case.json)
  (ASI02 / `tool_output`).
- An **audit mode** with no `AttackCase` is deferred: `TraceEvaluationInput` requires
  an `attack_case`, so audit mode needs a schema/validator change and is out of scope.

## Source provenance

Every collected framework fixture must record its provenance, either in a sibling
`README`/`provenance.json` under the version directory or in the fixture's own
`metadata`:

- **framework** (e.g. `langgraph`)
- **framework version** (the recorded, pinned version)
- **export format** (e.g. `langchain messages_to_dict v0.x`)
- **export method** (how it was produced — script, notebook, LangSmith export)
- **run id** if available
- **status** — `real-exported` or `provisional-synthetic`

## Sample / version policy

Before `langgraph-messages` is implemented, provide **at least two real exported
samples from the same recorded LangGraph version**:

1. a **basic** message-only run, and
2. a **tool-calling** run with `AIMessage.tool_calls` and a matching `ToolMessage`.

Layout:

```text
examples/framework_logs/langgraph/<version>/basic_messages.json
examples/framework_logs/langgraph/<version>/tool_call_messages.json
```

Rules:

- Each fixture is clearly labeled **real-exported** or **provisional-synthetic**.
- Real fixtures are **sanitized** (secrets, tokens, PII, internal hostnames replaced
  with placeholders / reserved `example.com`) while **preserving structure** — keep
  keys, message `type` tokens, and `tool_call_id`s intact so the shape stays faithful.
- A **provisional-synthetic** fixture may exist only as an explicitly-labeled
  strawman and must never be presented as real. (None is shipped in 14.4.0 — see the
  rationale in [Status](#framework-converters--input-policy).)

## Collecting a real sample

Run this **in your own environment** (it is operator tooling, *not* part of the
evaluator and not run by this repo). It imports the framework SDK on purpose — that is
allowed here because it is a one-off collection script, not evaluator runtime.

```python
# collect_langgraph_sample.py  — run locally, then sanitize the output
import json
from langchain_core.messages import messages_to_dict

# ... build and invoke your LangGraph app, capturing the final state ...
final_state = app.invoke({"messages": [("user", "…your probe…")]})

with open("tool_call_messages.raw.json", "w", encoding="utf-8") as f:
    json.dump(messages_to_dict(final_state["messages"]), f, indent=2)

# Then: record the langchain/langgraph versions, sanitize secrets/PII (preserve keys,
# message `type` tokens, and tool_call_id values), and drop the file under
# examples/framework_logs/langgraph/<version>/.
```

Capture **two** runs (basic + tool-calling) from the **same** version, sanitize, and
record provenance. Only then is Phase 14.4.1 unblocked.

## Why converters parse exported JSON (not SDK objects)

The evaluator is framework-agnostic and must not depend on any agent framework. A
converter that imported `langgraph`/`langchain` would (a) couple the evaluator to a
specific framework and version, (b) add a heavy runtime dependency, and (c) risk
executing framework code on untrusted input. Converters therefore consume the
framework's **already-serialized JSON** only. SDK use is confined to the operator's
separate, local collection script above.
