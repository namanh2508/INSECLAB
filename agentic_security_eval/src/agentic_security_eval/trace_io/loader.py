"""Load a TraceEvaluationInput bundle from a JSON file.

Trace ingestion is a system boundary: the JSON is read with the stdlib ``json``
module and validated into ``TraceEvaluationInput`` (which also enforces the
attack-case-id consistency rule). Any problem — missing file, malformed JSON, a
non-object top level, schema violation, or id mismatch — fails fast with
``ConfigError``. Trace content is untrusted data and is never executed.
"""

import json
from pathlib import Path

from pydantic import ValidationError

from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import TraceEvaluationInput


def load_trace_evaluation_input(path: str | Path) -> TraceEvaluationInput:
    input_path = Path(path)
    if not input_path.is_file():
        raise ConfigError(f"Trace bundle not found: {input_path}")

    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in trace bundle '{input_path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Trace bundle '{input_path}' must be a JSON object at the top level.")

    try:
        return TraceEvaluationInput.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid trace bundle '{input_path}': {exc}") from exc
