"""PythonWorkflowAdapter — load a local Python target and normalize its output.

This adapter is the single boundary where untrusted target output is parsed into
the typed ``AgentTrace``. It loads a target object from
``TargetConfig.entrypoint`` (``"module.path:factory"``), drives it with one
``AttackCase``, and returns a normalized trace. It never imports a specific
agent framework.

The loaded target must implement the workflow contract::

    setup() -> None
    reset() -> None
    run_scenario(attack_case: AttackCase) -> None
    get_trace() -> AgentTrace | dict
"""

import importlib

from pydantic import ValidationError

from agentic_security_eval.core.errors import AdapterError, ConfigError
from agentic_security_eval.core.models import AgentTrace, AttackCase, TargetConfig

REQUIRED_TARGET_METHODS = ("setup", "reset", "run_scenario", "get_trace")


class PythonWorkflowAdapter:
    """Drive a locally-importable Python target workflow.

    The target is loaded and validated at construction time (fail-fast). The
    four delegating methods satisfy the ``TargetAdapter`` contract.
    """

    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self._target = _load_target(config)

    def setup(self) -> None:
        self._target.setup()

    def reset(self) -> None:
        self._target.reset()

    def run_scenario(self, attack_case: AttackCase) -> None:
        self._target.run_scenario(attack_case)

    def get_trace(self) -> AgentTrace:
        return _normalize_trace(self._target.get_trace())


def _load_target(config: TargetConfig):
    entrypoint = config.entrypoint
    if not entrypoint:
        raise ConfigError("python_workflow adapter requires TargetConfig.entrypoint.")

    if entrypoint.count(":") != 1:
        raise AdapterError(
            f"Invalid entrypoint '{entrypoint}'. Expected 'module.path:factory'."
        )
    module_name, attr_name = entrypoint.split(":")
    if not module_name or not attr_name:
        raise AdapterError(
            f"Invalid entrypoint '{entrypoint}'. Expected 'module.path:factory'."
        )

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise AdapterError(f"Could not import target module '{module_name}': {exc}") from exc

    try:
        factory = getattr(module, attr_name)
    except AttributeError as exc:
        raise AdapterError(
            f"Target factory '{attr_name}' not found in module '{module_name}'."
        ) from exc

    target = factory()
    _validate_target(target)
    return target


def _validate_target(target) -> None:
    missing = [name for name in REQUIRED_TARGET_METHODS if not callable(getattr(target, name, None))]
    if missing:
        raise AdapterError("Target is missing required method(s): " + ", ".join(missing) + ".")


def _normalize_trace(raw) -> AgentTrace:
    if isinstance(raw, AgentTrace):
        return raw
    if isinstance(raw, dict):
        try:
            return AgentTrace.model_validate(raw)
        except ValidationError as exc:
            raise AdapterError(f"Target returned an invalid trace dict: {exc}") from exc
    raise AdapterError(
        f"Target get_trace() must return AgentTrace or dict, got {type(raw).__name__}."
    )
