"""
Ollama LLM Parser for unknown / novel log formats in ULPF.
"""

from __future__ import annotations

from typing import Any, Dict

from app.ai.ollama_detector import query_ollama_for_log
from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification, normalize_event
from app.normalization.field_mapping import coerce_int, parse_timestamp
from app.parsers.base import BaseParser
from app.parsers.generic_parser import parse_generic_log


class OllamaParser(BaseParser):
    format_name = "ollama"

    def parse(self, raw: str) -> UnifiedEvent:
        return parse_with_ollama(raw)


def parse_with_ollama(raw_text: str, model: str = "llama3.2") -> UnifiedEvent:
    """Parse an unknown log format using the local Ollama LLM."""
    llm_result = query_ollama_for_log(raw_text, model=model)

    if not llm_result:
        # Graceful fallback to GenericParser
        return parse_generic_log(raw_text)

    mapped: Dict[str, Any] = {
        "raw_event": raw_text,
        "log_format": f"llm_{llm_result.get('format_name', 'custom').lower().replace(' ', '_')}",
        "vendor": llm_result.get("vendor"),
        "product": llm_result.get("product"),
        "message": llm_result.get("message") or raw_text,
        "src_ip": llm_result.get("src_ip"),
        "dst_ip": llm_result.get("dst_ip"),
        "user": llm_result.get("user"),
        "activity_name": llm_result.get("action"),
        "status": llm_result.get("status"),
        "severity": llm_result.get("severity", "Informational"),
        "category_name": llm_result.get("category_name"),
    }

    if llm_result.get("timestamp"):
        ts = parse_timestamp(llm_result["timestamp"])
        if ts:
            mapped["timestamp"] = ts

    if llm_result.get("src_port"):
        mapped["src_port"] = coerce_int(llm_result["src_port"])
    if llm_result.get("dst_port"):
        mapped["dst_port"] = coerce_int(llm_result["dst_port"])

    # Clean None values
    mapped = {k: v for k, v in mapped.items() if v is not None}
    enrich_classification(mapped)

    ev = UnifiedEvent(**mapped)
    return normalize_event(ev)
