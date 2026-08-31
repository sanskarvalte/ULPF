"""
Sources management API endpoints.
Enables plug-and-play onboarding of new perimeter and host log sources.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.storage.mappings import list_registered_sources, register_source

router = APIRouter(prefix="/sources", tags=["Source Onboarding"])


class RegisterSourceRequest(BaseModel):
    source_name: str = Field(..., description="Name of the log source (e.g. Cisco_ASA_FW_01).")
    format: str = Field(..., description="Format (syslog, json, cef, leef, csv, xml, generic).")
    vendor: Optional[str] = Field(None, description="Device/Software vendor.")
    product: Optional[str] = Field(None, description="Device/Software product name.")
    mapping_rules: Optional[Dict[str, Any]] = Field(None, description="Custom field mapping dictionary.")


@router.post("", summary="Register a new log source")
def register_new_source(payload: RegisterSourceRequest) -> Dict[str, Any]:
    source_id = register_source(
        source_name=payload.source_name,
        format=payload.format,
        vendor=payload.vendor,
        product=payload.product,
        mapping_rules=payload.mapping_rules,
    )
    return {
        "status": "success",
        "source_id": source_id,
        "message": f"Successfully registered log source '{payload.source_name}'.",
    }


@router.get("", summary="List all registered log sources")
def get_sources() -> Dict[str, Any]:
    sources = list_registered_sources()
    return {
        "count": len(sources),
        "sources": sources,
    }
