"""Built-in attack template loading.

Templates are YAML data — loaded with ``yaml.safe_load`` (never ``load``) and
parsed into typed Pydantic models. Loading is a system boundary: invalid YAML or
a template that violates the schema fails fast with ``ConfigError``. Payloads
inside templates are treated as untrusted data and are never executed here.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from agentic_security_eval.core.enums import ASICategory, AttackSurface
from agentic_security_eval.core.errors import ConfigError

TEMPLATE_DIR = Path(__file__).parent / "templates"


class AttackSeed(BaseModel):
    """One attacker payload within a template."""

    id: str
    payload: str
    tags: list[str] = Field(default_factory=list)


class AttackTemplate(BaseModel):
    """A category's attack template: shared metadata plus a list of seeds."""

    category: ASICategory
    id_prefix: str
    objective: str
    expected_risk: str
    surfaces: list[AttackSurface] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    seeds: list[AttackSeed] = Field(min_length=1)


def load_builtin_templates() -> list[AttackTemplate]:
    """Load and validate every built-in template, in deterministic filename order."""
    templates = [_load_template_file(path) for path in sorted(TEMPLATE_DIR.glob("*.yaml"))]
    if not templates:
        raise ConfigError(f"No attack templates found in {TEMPLATE_DIR}.")
    return templates


def _load_template_file(path: Path) -> AttackTemplate:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in template '{path.name}': {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Template '{path.name}' must be a YAML mapping at the top level.")

    try:
        return AttackTemplate.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid attack template '{path.name}': {exc}") from exc
