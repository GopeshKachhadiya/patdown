from __future__ import annotations

import json
from collections import Counter

from patdown import __version__
from patdown.findings import Finding


def render_json(findings: list[Finding], stats: dict[str, object]) -> str:
    counts = Counter(f.severity.name for f in findings)
    payload = {
        "tool": "patdown",
        "version": __version__,
        "stats": stats,
        "summary": {name: counts.get(name, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
