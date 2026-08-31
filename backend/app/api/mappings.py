"""
Schema mappings and review API endpoints.
Provides OCSF schema reference, active vendor rules, and AI automated mapping suggestion.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ai.schema_mapper import suggest_schema_mapping
from app.mapping.existing import BUILTIN_MAPPINGS

router = APIRouter(prefix="/mappings", tags=["Schema Mappings"])


class MappingSuggestRequest(BaseModel):
    sample_keys: List[str] = Field(..., description="List of raw extracted keys to map.")
    sample_values: Dict[str, Any] = Field(default_factory=dict, description="Example key-value pairs.")


@router.get("", summary="Get all active and built-in schema mappings")
def get_mappings() -> Dict[str, Any]:
    return {
        "count": len(BUILTIN_MAPPINGS),
        "mappings": BUILTIN_MAPPINGS,
    }


@router.post("/suggest", summary="AI Automated Schema Mapping Suggestion")
def suggest_mapping(payload: MappingSuggestRequest) -> Dict[str, Any]:
    return suggest_schema_mapping(payload.sample_keys, payload.sample_values)
