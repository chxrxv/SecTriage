"""Machine-readable JSON export of a triage run."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import TriagedFinding


def render_json_report(triaged: list[TriagedFinding], metrics: dict, generated_by: str = "sectriage") -> dict:
    return {
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "total_findings": len(triaged),
        "findings": [tf.to_dict() for tf in triaged],
    }


def write_json_report(triaged: list[TriagedFinding], metrics: dict, path: str) -> None:
    payload = render_json_report(triaged, metrics)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
