"""CLI integration tests for HTTP TargetConfig over loopback HTTP."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from agentic_security_eval.cli import main
from agentic_security_eval.core.models import AttackCase
from examples.fake_targets import HardenedAgent, VulnerableAgent


class FakeHttpCliTargetState:
    def __init__(self, profile: str) -> None:
        agent_cls = VulnerableAgent if profile == "vulnerable" else HardenedAgent
        self.agent = agent_cls()
        self.agent.setup()
        self.target_id = self.agent.target_id
        self.base_url = ""
        self.seen_requests: list[tuple[str, str]] = []

    def reset(self) -> None:
        self.agent.reset()

    def run(self, raw_case: dict[str, Any]) -> dict[str, Any]:
        attack_case = AttackCase.model_validate(raw_case)
        self.agent.run_scenario(attack_case)
        return self.agent.get_trace().model_dump(mode="json")


class FakeHttpCliServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, request_handler_class, state: FakeHttpCliTargetState):
        super().__init__(server_address, request_handler_class)
        self.state = state


class FakeHttpCliHandler(BaseHTTPRequestHandler):
    server: FakeHttpCliServer

    def do_GET(self) -> None:
        self.server.state.seen_requests.append(("GET", self.path))
        if self.path != "/eval/capabilities":
            self._send_json(404, {"error": "not found"})
            return
        self._send_json(
            200,
            {
                "target_id": self.server.state.target_id,
                "adapter_schema_version": "0.1",
                "capabilities": {
                    "tools": True,
                    "memory": True,
                    "retrieval": False,
                    "uploaded_files": False,
                    "inter_agent_messages": False,
                    "plugin_skill_metadata": False,
                },
                "allowed_surfaces": ["user_prompt", "tool_output", "memory_write"],
                "supports_reset": True,
                "supports_async": False,
                "returns_agent_trace": True,
            },
        )

    def do_POST(self) -> None:
        self.server.state.seen_requests.append(("POST", self.path))
        if self.path == "/eval/reset":
            self.server.state.reset()
            self._send_json(200, {"ok": True})
            return
        if self.path != "/eval/run":
            self._send_json(404, {"error": "not found"})
            return

        payload = self._read_json_body()
        if payload.get("adapter_schema_version") != "0.1":
            self._send_json(400, {"error": "unsupported schema"})
            return
        raw_case = payload.get("attack_case")
        if not isinstance(raw_case, dict) or not raw_case.get("id"):
            self._send_json(400, {"error": "missing attack_case"})
            return
        self._send_json(200, {"adapter_schema_version": "0.1", "trace": self.server.state.run(raw_case)})

    def log_message(self, format: str, *args) -> None:
        return

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_http_cli_target():
    servers: list[tuple[FakeHttpCliServer, threading.Thread]] = []

    def start(profile: str) -> FakeHttpCliTargetState:
        state = FakeHttpCliTargetState(profile)
        server = FakeHttpCliServer(("127.0.0.1", 0), FakeHttpCliHandler, state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        state.base_url = f"http://{host}:{port}"
        servers.append((server, thread))
        return state

    yield start

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        if thread.is_alive():
            raise AssertionError("fake HTTP CLI target thread did not stop")


def _write_http_target_config(path, state: FakeHttpCliTargetState) -> None:
    path.write_text(
        f"""
target_id: {state.target_id}
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
  - memory_write
http:
  base_url: "{state.base_url}"
  timeout_seconds: 2
  auth_token_env: null
  reset_between_cases: true
  max_response_bytes: 1000000
  adapter_schema_version: "0.1"
""",
        encoding="utf-8",
    )


def test_cli_eval_http_vulnerable_target_produces_findings(tmp_path, fake_http_cli_target):
    state = fake_http_cli_target("vulnerable")
    target = tmp_path / "http-vulnerable.yaml"
    output = tmp_path / "http-report.json"
    _write_http_target_config(target, state)

    rc = main([
        "eval",
        "--target", str(target),
        "--categories", "ASI02,ASI06",
        "--output", str(output),
    ])

    assert rc == 0
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["total_cases"] > 0
    assert data["total_findings"] > 0
    assert ("GET", "/eval/capabilities") in state.seen_requests
    assert ("POST", "/eval/reset") in state.seen_requests
    assert ("POST", "/eval/run") in state.seen_requests


def test_cli_eval_http_hardened_target_produces_no_findings(tmp_path, fake_http_cli_target):
    state = fake_http_cli_target("hardened")
    target = tmp_path / "http-hardened.yaml"
    output = tmp_path / "http-report.json"
    _write_http_target_config(target, state)

    rc = main([
        "eval",
        "--target", str(target),
        "--categories", "ASI02,ASI06",
        "--output", str(output),
    ])

    assert rc == 0
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["total_cases"] > 0
    assert data["total_findings"] == 0
