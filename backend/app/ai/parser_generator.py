"""
ULPF AI Parser Generator.

Uses local Qwen through Ollama to generate a controlled
parser specification for an unknown log format.

Qwen does NOT generate Python code.
The LLM is an assistant, NOT the authority.
Never trust raw LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.ai.ollama_client import DEFAULT_SAMPLE_SIZE, generate_json


PARSER_GENERATION_PROMPT = """You are the parser-generation component of ULPF, a local air-gapped log processing framework.

The log format is unknown to ULPF.
Based on the supplied log samples and deterministic observations, generate a CONTROLLED parser specification.

STRICT BEHAVIORAL RULES:
1. Analyze STRUCTURE, not individual literal values.
2. Identify delimiters and positional fields.
3. Identify key/value fields.
4. Identify optional fields.
5. Identify timestamp field.
6. Identify semantic fields and custom fields.
7. NEVER invent fields not present in the logs.
8. NEVER invent values.
9. NEVER infer semantics without concrete evidence in the log text.
10. Return null or empty when uncertain.
11. Preserve unknown fields; do not discard information.
12. Do NOT write Python code.
13. Do NOT generate executable code.
14. Do NOT normalize the logs to OCSF.
15. Do NOT decide arbitrary OCSF IDs (ULPF's deterministic normalization layer assigns them).
16. Return ONLY valid JSON.

==================================================
DETERMINISTIC STRUCTURAL OBSERVATIONS
==================================================
{observations}

==================================================
ULPF CANONICAL FIELD NAMES
==================================================

When a field has a clear semantic meaning, prefer the following ULPF canonical field names:

Timestamp:
- timestamp

Identity:
- user, user_uid, user_domain, user_type

Network:
- src_ip, src_port, src_hostname, src_endpoint_name
- dst_ip, dst_port, dst_hostname, dst_endpoint_name
- protocol, direction, traffic_bytes, traffic_packets

Classification:
- activity_name, severity, status, status_code, status_detail, message

Metadata:
- vendor, product, product_version, service_name, log_name

If a field is vendor-specific or custom, preserve its original descriptive key name.

==================================================
FIELD TYPES
==================================================

Allowed field types:
- datetime
- ip
- port
- protocol
- action
- number
- string

==================================================
EXAMPLE OUTPUT FORMAT
==================================================
{{
  "format_name": "custom_inventory",
  "parser_type": "delimited",
  "delimiter": "|",
  "fields": [
    {{"name": "timestamp", "type": "datetime"}},
    {{"name": "service_name", "type": "string"}},
    {{"name": "user", "type": "string"}},
    {{"name": "action", "type": "string"}},
    {{"name": "src_ip", "type": "ip"}}
  ],
  "optional_fields": [],
  "confidence": 0.96
}}

Allowed parser types:
key_value, delimited, regex, json, syslog, csv, xml

Return exactly these fields:
format_name, parser_type, delimiter, fields, timestamp_field, key_value_separator, optional_fields, confidence

LOG SAMPLES:
{log_samples}
"""


def extract_deterministic_observations(log_samples: str) -> Dict[str, Any]:
    """
    Extract deterministic structural observations from raw sample lines
    to ground the LLM and eliminate hallucinations.
    """
    lines = [line.strip() for line in log_samples.splitlines() if line.strip()]
    if not lines:
        return {"line_count": 0}

    candidate_delims = ["|", ",", "\t", ";", " ", ":", "="]
    delim_counts: Dict[str, List[int]] = {d: [] for d in candidate_delims}

    kv_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_\-\.]*)(?:[=:])')
    detected_keys = set()
    has_kv = False

    for line in lines:
        for d in candidate_delims:
            delim_counts[d].append(line.count(d))
        keys = kv_pattern.findall(line)
        if len(keys) >= 2:
            has_kv = True
            detected_keys.update(keys)

    consistent_delims = []
    for d, counts in delim_counts.items():
        if counts and all(c == counts[0] for c in counts) and counts[0] > 0:
            consistent_delims.append((d, counts[0]))

    return {
        "line_count": len(lines),
        "consistent_delimiters": consistent_delims,
        "has_key_value": has_kv,
        "detected_keys": sorted(list(detected_keys)),
    }


def format_observations(obs: Dict[str, Any]) -> str:
    """Format structural observations into prompt text."""
    parts = []
    if obs.get("consistent_delimiters"):
        delims_str = ", ".join(f"'{d}' (count: {c} per line)" for d, c in obs["consistent_delimiters"])
        parts.append(f"- Consistent delimiters observed across all lines: {delims_str}")
    if obs.get("has_key_value"):
        keys_sample = ", ".join(obs.get("detected_keys", [])[:15])
        parts.append(f"- Key=value patterns detected with keys: {keys_sample}")
    if not parts:
        parts.append("- Heterogeneous or positional spacing detected; analyze token structure carefully.")
    return "\n".join(parts)


def generate_parser_spec(
    log_samples: str,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    model: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Ask local Qwen to generate a controlled parser
    specification for the supplied log samples.
    """
    sample_lines = [s for s in log_samples.splitlines() if s.strip()][:sample_size]
    bounded_samples = "\n".join(sample_lines)

    observations = extract_deterministic_observations(bounded_samples)
    obs_text = format_observations(observations)

    prompt = PARSER_GENERATION_PROMPT.format(
        observations=obs_text,
        log_samples=bounded_samples,
    )

    result = generate_json(prompt, model=model, timeout=timeout)
    return _normalize_parser_spec(result)


def _normalize_parser_spec(
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """Normalize response into a predictable structure."""
    fields = result.get("fields", [])
    normalized_fields = []

    if isinstance(fields, list):
        for field in fields:
            if not isinstance(field, dict):
                continue

            name = str(field.get("name", "")).strip()
            field_type = str(field.get("type", "string")).strip().lower()

            if not name:
                continue

            # Strip any arbitrary model-invented OCSF numeric IDs
            normalized_fields.append(
                {
                    "name": name.lower(),
                    "type": field_type,
                }
            )

    parser_type = str(result.get("parser_type", "")).strip().lower()

    conf = result.get("confidence", 0.90)
    try:
        conf_float = max(0.0, min(1.0, float(conf)))
    except (ValueError, TypeError):
        conf_float = 0.90

    return {
        "format_name": str(result.get("format_name", "unknown")).strip(),
        "parser_type": parser_type,
        "delimiter": str(result.get("delimiter", "")),
        "fields": normalized_fields,
        "timestamp_field": str(result.get("timestamp_field", "")).strip().lower(),
        "key_value_separator": str(result.get("key_value_separator", "")),
        "optional_fields": [
            str(field).strip().lower()
            for field in result.get("optional_fields", [])
        ],
        "confidence": conf_float,
    }
