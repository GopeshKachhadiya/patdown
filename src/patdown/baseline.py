"""Baseline files: accept the findings you have reviewed, fail only on new ones."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from patdown import __version__
from patdown.findings import Finding

BASELINE_FILENAME = ".patdown-baseline.json"


def load_baseline(path: str) -> set[str]:
    if not os.path.isfile(path):
        return set()
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError:
            return set()
    items = data.get("findings", []) if isinstance(data, dict) else []
    return {str(i.get("fingerprint")) for i in items if isinstance(i, dict) and i.get("fingerprint")}


def write_baseline(path: str, findings: list[Finding]) -> None:
    payload = {
        "tool": "patdown",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "findings": [
            {"fingerprint": f.fingerprint, "rule": f.rule, "path": f.path, "line": f.line, "message": f.message}
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def apply_baseline(findings: list[Finding], baseline: set[str]) -> tuple[list[Finding], int]:
    if not baseline:
        return findings, 0
    kept = [f for f in findings if f.fingerprint not in baseline]
    return kept, len(findings) - len(kept)
