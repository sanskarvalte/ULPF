"""
Ground-truth dataset loader for ULPF conversion and normalization accuracy benchmark.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

_GROUND_TRUTH_FILE = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "datasets"
    / "ground_truth"
    / "ground_truth.json"
)


def load_ground_truth_dataset(custom_path: str | Path | None = None) -> List[Dict[str, Any]]:
    """Load benchmark ground truth dataset from JSON file."""
    p = Path(custom_path) if custom_path else _GROUND_TRUTH_FILE
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)
