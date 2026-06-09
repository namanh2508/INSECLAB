"""Closed enumerations shared across the evaluator core.

These are the only valid values for category, severity, attack surface, and
evidence source. Keeping them closed lets the deterministic validator reject
out-of-vocabulary judge output at a later phase.
"""

from enum import Enum


class ASICategory(str, Enum):
    """OWASP Agentic Security Initiative categories covered by the MVP."""

    ASI01 = "ASI01"  # Agent Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI06 = "ASI06"  # Memory & Context Poisoning


class Severity(str, Enum):
    """Finding severity, ordered from lowest to highest impact."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackSurface(str, Enum):
    """Channels through which untrusted content can reach the target agent."""

    USER_PROMPT = "user_prompt"
    RETRIEVED_WEB_CONTENT = "retrieved_web_content"
    UPLOADED_FILE_DOCUMENT = "uploaded_file_document"
    TOOL_OUTPUT = "tool_output"
    TOOL_DEFINITION = "tool_definition"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    PLUGIN_SKILL_METADATA = "plugin_skill_metadata"
    INTER_AGENT_MESSAGE = "inter_agent_message"
    SYSTEM_PROMPT = "system_prompt"
    CONTEXT_EXTENSION = "context_extension"


class EvidenceSource(str, Enum):
    """Which trace channel a piece of evidence was grounded in."""

    MESSAGE = "message"
    TOOL_CALL = "tool_call"
    MEMORY_EVENT = "memory_event"
    RETRIEVAL_EVENT = "retrieval_event"
    INTER_AGENT_MESSAGE = "inter_agent_message"
    FINAL_OUTPUT = "final_output"
