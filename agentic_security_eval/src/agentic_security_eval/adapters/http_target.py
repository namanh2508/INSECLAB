"""HTTP target adapter for live evaluation harness targets.

The adapter is intentionally narrow: drive one AttackCase over the HTTP eval
contract, validate the returned AgentTrace, and store it. It does not judge,
repair traces, or synthesize evidence metadata.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol

from pydantic import ValidationError

from agentic_security_eval.core.errors import AdapterError
from agentic_security_eval.core.models import AgentTrace, AttackCase, TargetConfig


class HttpTransport(Protocol):
    """Transport boundary for HTTP target requests."""

    def request_json(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None,
        headers: dict[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        """Return a decoded JSON object from the target."""
        ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibHttpTransport:
    """Standard-library HTTP transport with redirects disabled."""

    def request_json(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None,
        headers: dict[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise AdapterError(f"HTTP target request failed with HTTP {status}.")
                raw = response.read(max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise AdapterError(f"HTTP target request failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise AdapterError(f"HTTP target request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise AdapterError("HTTP target request timed out.") from exc

        if len(raw) > max_response_bytes:
            raise AdapterError("HTTP target response exceeds max_response_bytes.")

        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"HTTP target response is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise AdapterError("HTTP target response must be a JSON object.")
        return data


class HttpTargetAdapter:
    """Drive a live HTTP target through the evaluator harness contract."""

    def __init__(self, target_config: TargetConfig, transport: HttpTransport | None = None) -> None:
        if target_config.adapter_type != "http":
            raise AdapterError("HttpTargetAdapter requires TargetConfig.adapter_type == 'http'.")
        if target_config.http is None:
            raise AdapterError("HttpTargetAdapter requires TargetConfig.http.")

        self.config = target_config
        self.http = target_config.http
        self.base_url = self.http.base_url.rstrip("/")
        self.transport = transport or UrllibHttpTransport()
        self._auth_token = self._read_auth_token()
        self._supports_reset: bool | None = None
        self._capabilities_response: dict[str, Any] | None = None
        self._latest_trace: AgentTrace | None = None
        self._reset_counter = 0

    def setup(self) -> None:
        data = self._request_json("GET", "/eval/capabilities", None)
        self._validate_capabilities_response(data)
        self._capabilities_response = data
        self._supports_reset = data["supports_reset"]

    def reset(self) -> None:
        if not self.http.reset_between_cases:
            return
        if self._supports_reset is None:
            raise AdapterError("HttpTargetAdapter.setup() must be called before reset().")
        if self._supports_reset is not True:
            raise AdapterError("HTTP target does not support reset.")

        self._reset_counter += 1
        self._request_json("POST", "/eval/reset", {"scenario_id": f"reset-{self._reset_counter}"})

    def run_scenario(self, attack_case: AttackCase) -> AgentTrace:
        payload = {
            "adapter_schema_version": self.http.adapter_schema_version,
            "attack_case": attack_case.model_dump(mode="json"),
            "run_config": {
                "scenario_id": attack_case.id,
                "safe_mode": True,
                "mock_tools": True,
                "trace_required": True,
                "timeout_seconds": self.http.timeout_seconds,
            },
        }
        data = self._request_json("POST", "/eval/run", payload)
        trace = self._normalize_run_response(data, attack_case)
        self._latest_trace = trace
        return trace

    def get_trace(self) -> AgentTrace:
        if self._latest_trace is None:
            raise AdapterError("No HTTP target trace is available; run_scenario() has not completed.")
        return self._latest_trace

    def _read_auth_token(self) -> str | None:
        env_name = self.http.auth_token_env
        if env_name is None:
            return None
        token = os.environ.get(env_name)
        if not token:
            raise AdapterError(f"Authentication token env var '{env_name}' is unset or empty.")
        return token

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        try:
            return self.transport.request_json(
                method=method,
                url=_join_url(self.base_url, path),
                payload=payload,
                headers=_build_headers(self._auth_token),
                timeout_seconds=self.http.timeout_seconds,
                max_response_bytes=self.http.max_response_bytes,
            )
        except AdapterError as exc:
            raise AdapterError(_redact(str(exc), self._auth_token)) from exc

    def _validate_capabilities_response(self, data: dict[str, Any]) -> None:
        if data.get("target_id") != self.config.target_id:
            raise AdapterError("HTTP target capabilities target_id does not match TargetConfig.target_id.")
        if data.get("adapter_schema_version") != self.http.adapter_schema_version:
            raise AdapterError("HTTP target capabilities adapter_schema_version is unsupported.")
        if data.get("returns_agent_trace") is not True:
            raise AdapterError("HTTP target must declare returns_agent_trace=true.")
        if not isinstance(data.get("supports_reset"), bool):
            raise AdapterError("HTTP target capabilities supports_reset must be a boolean.")

    def _normalize_run_response(self, data: dict[str, Any], attack_case: AttackCase) -> AgentTrace:
        _validate_response_envelope(data, self.http.adapter_schema_version)
        _validate_trace_payload_has_required_keys(data["trace"])
        try:
            trace = AgentTrace.model_validate(data["trace"])
        except ValidationError as exc:
            raise AdapterError(f"HTTP target returned an invalid AgentTrace: {exc}") from exc

        if trace.target_id != self.config.target_id:
            raise AdapterError("HTTP target trace.target_id does not match TargetConfig.target_id.")
        if trace.attack_case_id != attack_case.id:
            raise AdapterError("HTTP target trace.attack_case_id does not match AttackCase.id.")
        _validate_trace_ids_are_unique(trace)
        return trace


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url}/{path.lstrip('/')}"


def _build_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _validate_response_envelope(data: dict[str, Any], expected_version: str) -> None:
    allowed = {"adapter_schema_version", "trace"}
    unknown = set(data) - allowed
    if unknown:
        raise AdapterError(f"HTTP target response has unknown top-level key(s): {', '.join(sorted(unknown))}.")
    if data.get("adapter_schema_version") != expected_version:
        raise AdapterError("HTTP target response adapter_schema_version is unsupported.")
    if "trace" not in data:
        raise AdapterError("HTTP target response is missing trace.")


def _validate_trace_payload_has_required_keys(raw_trace: Any) -> None:
    if not isinstance(raw_trace, dict):
        raise AdapterError("HTTP target response trace must be a JSON object.")

    required = {
        "target_id",
        "run_id",
        "attack_case_id",
        "messages",
        "tool_calls",
        "memory_events",
        "retrieval_events",
        "inter_agent_messages",
        "final_output",
        "errors",
        "metadata",
    }
    missing = required - set(raw_trace)
    if missing:
        raise AdapterError(f"HTTP target trace is missing required key(s): {', '.join(sorted(missing))}.")


def _validate_trace_ids_are_unique(trace: AgentTrace) -> None:
    ids: list[str] = []
    ids.extend(message.id for message in trace.messages)
    ids.extend(call.id for call in trace.tool_calls)
    ids.extend(event.id for event in trace.memory_events)
    ids.extend(event.id for event in trace.retrieval_events)
    ids.extend(message.id for message in trace.inter_agent_messages)

    seen: set[str] = set()
    duplicates: set[str] = set()
    for item_id in ids:
        if item_id in seen:
            duplicates.add(item_id)
        seen.add(item_id)
    if duplicates:
        raise AdapterError(f"Duplicate trace element id(s): {', '.join(sorted(duplicates))}.")


def _redact(message: str, secret: str | None) -> str:
    if not secret:
        return message
    return message.replace(secret, "[redacted]")
