"""The LLM judge contract and strict judge-output parsing.

Phase 1 defined the ``JudgeProvider`` Protocol (interface only). Phase 4 adds
``parse_judge_decision`` — the strict boundary that turns raw judge output into a
typed ``JudgeDecision``. Core models stay permissive internally; strictness
(malformed JSON, non-object payloads, unknown keys, missing fields, out-of-range
scores) is enforced here, at the untrusted LLM-output boundary, with a fail-fast
``JudgeError``. Nothing is silently dropped or defaulted.

The offline ``FakeJudgeProvider`` lives in ``oracle/fake_judge.py``; real
OpenAI/Anthropic providers still arrive in a later phase.
"""

import json
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from agentic_security_eval.core.errors import JudgeError
from agentic_security_eval.core.models import JudgeDecision, JudgeRequest


@runtime_checkable
class JudgeProvider(Protocol):
    """Contract for any LLM-as-judge backend."""

    name: str

    def judge(self, request: JudgeRequest) -> JudgeDecision:
        """Return a (still-untrusted) verdict for a single attack."""
        ...


def parse_judge_decision(raw: str | dict[str, Any]) -> JudgeDecision:
    """Strictly parse raw judge output into a JudgeDecision.

    Raises ``JudgeError`` on malformed JSON, a non-object payload, unknown
    top-level fields, missing required fields, or out-of-range scores.
    """
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JudgeError(f"Judge output is not valid JSON: {exc}") from exc
    elif isinstance(raw, dict):
        data = raw
    else:
        raise JudgeError(
            f"Judge output must be a JSON string or dict, got {type(raw).__name__}."
        )

    if not isinstance(data, dict):
        raise JudgeError("Judge output must be a JSON object.")

    unknown = set(data) - set(JudgeDecision.model_fields)
    if unknown:
        raise JudgeError(f"Judge output has unknown field(s): {', '.join(sorted(unknown))}.")

    try:
        return JudgeDecision.model_validate(data)
    except ValidationError as exc:
        raise JudgeError(f"Judge output does not match the JudgeDecision schema: {exc}") from exc
