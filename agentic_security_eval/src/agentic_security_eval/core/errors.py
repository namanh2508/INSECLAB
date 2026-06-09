"""Typed error hierarchy for the evaluator.

Fail fast with one of these instead of returning ``None`` or silently
recovering. ``AgenticSecurityEvalError`` is the single root so callers can
catch the whole family when they genuinely need to.
"""


class AgenticSecurityEvalError(Exception):
    """Base class for all errors raised by the evaluator."""


class ConfigError(AgenticSecurityEvalError):
    """Invalid or missing configuration (e.g. TargetConfig loading)."""


class AdapterError(AgenticSecurityEvalError):
    """A target adapter could not be set up, driven, or normalized."""


class JudgeError(AgenticSecurityEvalError):
    """An LLM judge failed or returned output that could not be parsed."""


class ReportError(AgenticSecurityEvalError):
    """A report could not be built or serialized."""
