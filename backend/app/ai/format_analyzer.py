"""
ULPF AI Format Analyzer.

Uses the local Qwen model through Ollama to identify
the structural format of an unknown log.
"""

from __future__ import annotations

from typing import Any, Dict

from app.ai.ollama_client import generate_json


FORMAT_ANALYSIS_PROMPT = """You are the format analysis component of a local air-gapped log processing framework called ULPF.

Analyze the supplied log samples.
Your task is to identify the STRUCTURAL FORMAT of these logs.

IMPORTANT RULES:
1. Do NOT write Python code.
2. Do NOT create a parser.
3. Do NOT normalize to OCSF.
4. Do NOT use actual IP addresses or actual port numbers as part of the format identity.
5. Focus on the structure shared by all samples.
6. The format identity must remain the same when field values change.
7. Do not simply call the format "Custom".
8. Return ONLY valid JSON.

Return exactly these top-level fields:
format_name
format_family
confidence
delimiter
timestamp_pattern
structure_pattern
fields
optional_fields
stable_format_features

"structure_pattern" must be a single string.
"fields" must be a list of objects with "name" and "pattern".
"optional_fields" must be a list.
"stable_format_features" must be a list.

LOG SAMPLES:
{log_samples}
"""


def _normalize_analysis(result: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure response has the schema required by ULPF."""
    structure = result.get("structure_pattern", "")

    if isinstance(structure, dict):
        structure = " ".join(str(value) for value in structure.values())

    fields = result.get("fields", [])
    if not fields and isinstance(structure, str):
        fields = []
        for part in structure.split():
            clean_name = part.split("=")[0]
            if clean_name in {"YYYY-MM-DD", "HH:MM:SS"}:
                continue
            if clean_name:
                fields.append({"name": clean_name, "pattern": "string"})

    return {
        "format_name": result.get("format_name", "unknown"),
        "format_family": result.get("format_family", "unknown"),
        "confidence": result.get("confidence", 0),
        "delimiter": result.get("delimiter", " "),
        "timestamp_pattern": result.get("timestamp_pattern", "unknown"),
        "structure_pattern": structure,
        "fields": fields,
        "optional_fields": result.get("optional_fields", []),
        "stable_format_features": result.get("stable_format_features", []),
    }


def analyze_format(log_samples: str) -> Dict[str, Any]:
    """Analyze unknown log samples using the local Qwen model."""
    prompt = FORMAT_ANALYSIS_PROMPT.format(log_samples=log_samples)
    result = generate_json(prompt)
    return _normalize_analysis(result)
