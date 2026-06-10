"""Convert simpler raw agent logs into the canonical TraceEvaluationInput.

Generic and framework-neutral: framework-specific converters (LangGraph, CrewAI,
n8n, Elastic, ...) should follow the same shape rather than special-case here.
"""
