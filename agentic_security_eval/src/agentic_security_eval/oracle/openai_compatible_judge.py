"""OpenAI-compatible chat-completions judge provider.

This provider is optional and only runs when explicitly selected. It returns a
raw ``JudgeDecision`` through the existing parser; runners still pass that
decision through the deterministic validator before any finding is built.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol

from agentic_security_eval.core.enums import ASICategory, Severity
from agentic_security_eval.core.errors import JudgeError
from agentic_security_eval.core.models import JudgeDecision, JudgeRequest
from agentic_security_eval.oracle.judge import parse_judge_decision
from agentic_security_eval.oracle.judge_prompts import build_judge_messages

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_RESPONSE_FORMAT_MODE = "json_object"
_RESPONSE_FORMAT_MODES = {"none", "json_object", "json_schema"}


class ChatCompletionTransport(Protocol):
    """Transport boundary for chat completion requests."""

    def complete(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Return a decoded JSON object from the chat-completions endpoint."""
        ...


class UrllibChatCompletionTransport:
    """Standard-library HTTP transport for OpenAI-compatible providers."""

    def complete(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise JudgeError(f"Chat completion request failed with HTTP {status}.")
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise JudgeError(f"Chat completion request failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise JudgeError(f"Chat completion request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise JudgeError("Chat completion request timed out.") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JudgeError(f"Chat completion response is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise JudgeError("Chat completion response must be a JSON object.")
        return data


class OpenAICompatibleJudgeProvider:
    """JudgeProvider implementation for OpenAI-compatible Chat Completions APIs."""

    name = "openai-compatible"

    def __init__(
        self,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        api_key_env: str = DEFAULT_API_KEY_ENV,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: ChatCompletionTransport | None = None,
        response_format_mode: str = DEFAULT_RESPONSE_FORMAT_MODE,
    ) -> None:
        self.model = model.strip()
        if not self.model:
            raise JudgeError("openai-compatible judge requires a non-empty model.")
        self.base_url = base_url.rstrip("/")
        if not self.base_url:
            raise JudgeError("openai-compatible judge requires a non-empty base_url.")
        if response_format_mode not in _RESPONSE_FORMAT_MODES:
            valid = ", ".join(sorted(_RESPONSE_FORMAT_MODES))
            raise JudgeError(f"Invalid response_format_mode '{response_format_mode}'; valid: {valid}.")

        self.api_key_env = api_key_env
        self.api_key = api_key if api_key is not None else os.environ.get(api_key_env)
        if not self.api_key:
            raise JudgeError(f"Missing API key for openai-compatible judge; set {api_key_env}.")

        self.timeout_seconds = timeout_seconds
        self.transport = transport or UrllibChatCompletionTransport()
        self.response_format_mode = response_format_mode

    def judge(self, request: JudgeRequest) -> JudgeDecision:
        """Call the chat-completions endpoint and parse a JudgeDecision."""
        url = f"{self.base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": build_judge_messages(request),
            "temperature": 0,
        }
        response_format = _response_format(self.response_format_mode)
        if response_format is not None:
            payload["response_format"] = response_format

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = self.transport.complete(url, payload, headers, self.timeout_seconds)
            content = _extract_message_content(response)
            return parse_judge_decision(content)
        except JudgeError as exc:
            raise JudgeError(_redact(str(exc), self.api_key)) from exc


def _response_format(mode: str) -> dict[str, Any] | None:
    if mode == "none":
        return None
    if mode == "json_object":
        return {"type": "json_object"}
    if mode == "json_schema":
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "judge_decision",
                "strict": True,
                "schema": _judge_decision_schema(),
            },
        }
    valid = ", ".join(sorted(_RESPONSE_FORMAT_MODES))
    raise JudgeError(f"Invalid response_format_mode '{mode}'; valid: {valid}.")


def _judge_decision_schema() -> dict[str, Any]:
    required = [
        "is_vulnerable",
        "category",
        "severity",
        "confidence",
        "exploitability_score",
        "evidence_ids",
        "explanation",
        "recommendation",
    ]
    return {
        "type": "object",
        "properties": {
            "is_vulnerable": {"type": "boolean"},
            "category": {"type": "string", "enum": [category.value for category in ASICategory]},
            "severity": {"type": "string", "enum": [severity.value for severity in Severity]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "exploitability_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
            "explanation": {"type": "string"},
            "recommendation": {"type": "string"},
        },
        "required": required,
        "additionalProperties": False,
    }


def _extract_message_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise JudgeError("Chat completion response is missing choices.")
    first = choices[0]
    if not isinstance(first, dict):
        raise JudgeError("Chat completion response choice must be an object.")
    message = first.get("message")
    if not isinstance(message, dict):
        raise JudgeError("Chat completion response choice is missing message.")
    content = message.get("content")
    if not isinstance(content, str):
        raise JudgeError("Chat completion response message.content must be a string.")
    return content


def _redact(message: str, secret: str | None) -> str:
    if not secret:
        return message
    return message.replace(secret, "[redacted]")
