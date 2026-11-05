"""SARIF 2.1.0 output so findings show up in GitHub code scanning."""
from __future__ import annotations

import json

from patdown import __version__
from patdown.findings import Finding, Severity
from patdown.rules import ALL_RULES

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SCORES = {Severity.CRITICAL: 9.5, Severity.HIGH: 8.0, Severity.MEDIUM: 5.0, Severity.LOW: 2.5, Severity.INFO: 1.0}


def render_sarif(findings: list[Finding], stats: dict[str, object]) -> str:
    rule_ids = {r.id: r for r in ALL_RULES}
    seen_rules: dict[str, dict[str, object]] = {}
    results = []
    for f in findings:
        if f.rule not in seen_rules:
            base = rule_ids.get(f.rule)
            seen_rules[f.rule] = {
                "id": f.rule,
                "name": f.name,
                "shortDescription": {"text": (base.description if base else f.name)[:200]},
                "fullDescription": {"text": base.description if base else f.message},
                "helpUri": f"https://github.com/GopeshKachhadiya/patdown/blob/main/docs/rules.md#{f.rule.lower()}",
                "properties": {"security-severity": str(SCORES[f.severity]), "tags": ["security", "ai-agent", "supply-chain"]},
            }
        uri = f.path if not f.path.startswith("mcp://") else f.path
        location: dict[str, object] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if f.line:
            region: dict[str, object] = {"startLine": f.line}
            if f.col:
                region["startColumn"] = f.col
            if f.snippet:
                region["snippet"] = {"text": f.snippet}
            location["physicalLocation"]["region"] = region  # type: ignore[index]
        message = f.message if not f.detail else f.message + "\n" + f.detail
        results.append({
            "ruleId": f.rule,
            "level": LEVELS[f.severity],
            "message": {"text": message},
            "locations": [location],
            "partialFingerprints": {"patdown/v1": f.fingerprint},
            "properties": {"severity": f.severity.name, "kind": f.kind},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "patdown",
                "version": __version__,
                "informationUri": "https://github.com/GopeshKachhadiya/patdown",
                "rules": list(seen_rules.values()),
            }},
            "results": results,
            "properties": {"stats": stats},
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
