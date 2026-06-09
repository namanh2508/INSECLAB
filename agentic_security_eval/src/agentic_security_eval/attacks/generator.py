"""AttackGenerator — expand templates into concrete AttackCases for a target.

For each requested category it intersects the template's surfaces with the
surfaces the target actually exposes (via ``AttackSurfaceModel``) and emits one
``AttackCase`` per (surface, seed). Output is fully deterministic: category
order, then the surface order from the surface model, then seed order. No
randomization and no mutation in this phase.
"""

from agentic_security_eval.core.enums import ASICategory
from agentic_security_eval.core.errors import ConfigError
from agentic_security_eval.core.models import AttackCase, TargetConfig
from agentic_security_eval.surfaces.model import AttackSurfaceModel

from .templates import AttackSeed, AttackTemplate, load_builtin_templates


class AttackGenerator:
    """Builds AttackCases from built-in templates filtered by target capabilities."""

    def __init__(
        self,
        config: TargetConfig,
        templates: list[AttackTemplate] | None = None,
    ) -> None:
        self.config = config
        self.surface_model = AttackSurfaceModel(config)
        templates = templates if templates is not None else load_builtin_templates()
        self._by_category: dict[ASICategory, AttackTemplate] = {t.category: t for t in templates}

    def generate(
        self,
        categories: list[ASICategory] | None = None,
        max_cases: int | None = None,
    ) -> list[AttackCase]:
        if categories is None:
            categories = [c for c in ASICategory if c in self._by_category]

        cases: list[AttackCase] = []
        for category in categories:
            template = self._by_category.get(category)
            if template is None:
                raise ConfigError(f"No attack template for category {category.value}.")

            template_surfaces = set(template.surfaces)
            for surface in self.surface_model.surfaces_for(category):
                if surface not in template_surfaces:
                    continue
                for seed in template.seeds:
                    cases.append(_build_case(template, surface, seed))
                    if max_cases is not None and len(cases) >= max_cases:
                        return cases
        return cases


def _build_case(template: AttackTemplate, surface, seed: AttackSeed) -> AttackCase:
    return AttackCase(
        id=f"{template.id_prefix}__{surface.value}__{seed.id}",
        category=template.category,
        surface=surface,
        objective=template.objective,
        payload=seed.payload,
        expected_risk=template.expected_risk,
        surface_policy=None,
        tags=list(template.tags) + list(seed.tags),
        mutation_parent_id=None,
        metadata={"template_id": template.id_prefix, "seed_id": seed.id},
    )
