"""Leaked credentials: well-known token shapes anywhere, and plain-text values
under secret-looking keys in agent config files."""
from __future__ import annotations

import re
from typing import Any

from patdown.findings import Finding, Severity
from patdown.patterns import SECRET_PATTERNS, SECRETISH_KEY, WEAK_SECRET_NAMES, looks_like_placeholder, redact
from patdown.rules.base import KIND_CONFIG, KIND_MCP_CONFIG, KIND_PLUGIN, KIND_SETTINGS, Context, Document, Rule
from patdown.textutil import line_at


class HardcodedSecretRule(Rule):
    id = "PD030"
    name = "hardcoded-secret"
    description = "API keys, tokens and private keys in files an agent reads; anything the agent can read it can also leak."
    severity = Severity.HIGH

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        seen: set[int] = set()
        for label, rx in SECRET_PATTERNS:
            for m in rx.finditer(doc.text):
                if m.start() in seen:
                    continue
                seen.add(m.start())
                sev = Severity.MEDIUM if label in WEAK_SECRET_NAMES else self.severity_for(doc)
                snippet = redact(line_at(doc.text, m.start()))
                out.append(self.finding(doc, f"{label} found", m.start(), severity=sev, snippet=snippet))
        return out


class SecretInConfigRule(Rule):
    id = "PD031"
    name = "secret-in-config"
    description = "Plain-text credential stored under a key like API_KEY/TOKEN/PASSWORD in an MCP or agent config file."
    severity = Severity.MEDIUM
    kinds = {KIND_MCP_CONFIG, KIND_SETTINGS, KIND_PLUGIN, KIND_CONFIG}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        if not isinstance(doc.data, (dict, list)):
            return []
        out: list[Finding] = []
        for key, value in _walk_strings(doc.data):
            if not SECRETISH_KEY.search(key):
                continue
            if len(value) < 12 or looks_like_placeholder(value):
                continue
            if any(rx.search(value) for _, rx in SECRET_PATTERNS):
                continue  # already reported with its exact type by PD030
            offset = _locate_key(doc.text, key, value)
            masked = value[:3] + "*" * min(len(value) - 3, 20)
            out.append(self.finding(
                doc, f"Plain-text credential stored under {key!r}", offset,
                snippet=f"{key}: {masked}",
            ))
        return out


def _walk_strings(node: Any, key: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                out.append((str(k), v))
            else:
                out.extend(_walk_strings(v, str(k)))
    elif isinstance(node, list):
        for item in node:
            out.extend(_walk_strings(item, key))
    return out


def _locate_key(text: str, key: str, value: str) -> int | None:
    m = re.search(r"[\"']?" + re.escape(key) + r"[\"']?\s*[:=]", text)
    if m:
        return m.start()
    idx = text.find(value)
    return idx if idx >= 0 else None
