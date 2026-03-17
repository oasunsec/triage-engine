"""Graph JSON export helpers."""

from __future__ import annotations

import json
from typing import Dict

from triage_engine.export_sanitizer import sanitize_export_data


def export(graph_data: Dict, filepath: str) -> Dict:
    graph_data = sanitize_export_data(graph_data)
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(graph_data, handle, indent=2)
    return graph_data
