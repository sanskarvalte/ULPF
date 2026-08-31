"""
Automated AI Schema Mapper.
Infers schema mapping suggestions and taxonomy classifications from sample log entries.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from app.ai.confidence import calculate_field_confidence
from app.normalization.field_mapping import COMMON_FIELD_MAP


def suggest_schema_mapping(sample_keys: List[str], sample_values: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze sample keys and propose an automated mapping to OCSF schema with confidence ratings."""
    suggestions: List[Dict[str, Any]] = []

    for key in sample_keys:
        sample_val = sample_values.get(key)
        target_ocsf = COMMON_FIELD_MAP.get(key.lower(), "unmapped")
        confidence = calculate_field_confidence(key, target_ocsf, sample_val) if target_ocsf != "unmapped" else 0.2

        suggestions.append({
            "source_field": key,
            "suggested_ocsf_field": target_ocsf,
            "confidence": confidence,
            "sample_value": str(sample_val)[:50] if sample_val is not None else None,
        })

    avg_conf = sum(s["confidence"] for s in suggestions) / len(suggestions) if suggestions else 0.0

    return {
        "total_fields": len(sample_keys),
        "overall_confidence": round(avg_conf, 2),
        "mappings": suggestions,
    }
