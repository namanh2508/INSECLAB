"""JsonReportWriter — serialize an EvalReport to pretty JSON.

JSON is the primary MVP output. Serialization goes through Pydantic so the
report schema stays the single source of truth. Traces are not written here.
"""

from pathlib import Path

from agentic_security_eval.core.models import EvalReport


class JsonReportWriter:
    """Render and persist an EvalReport as JSON."""

    def to_json(self, report: EvalReport) -> str:
        return report.model_dump_json(indent=2)

    def write(self, report: EvalReport, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(report) + "\n", encoding="utf-8")
        return path
