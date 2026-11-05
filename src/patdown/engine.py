from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from patdown.findings import Finding, Severity
from patdown.rules import ALL_RULES, NESTED_RULE_IDS
from patdown.rules.base import Context, Document, Rule, apply_ignores

MAX_PER_RULE_PER_FILE = 40


class Scanner:
    """Runs every enabled rule over documents and handles nested re-scans."""

    def __init__(
        self,
        ignore_rules: Iterable[str] = (),
        only_rules: Iterable[str] | None = None,
        strict: bool = False,
        known_tools: dict[str, str] | None = None,
    ) -> None:
        ignore = {r.upper() for r in ignore_rules}
        only = {r.upper() for r in only_rules} if only_rules else None
        self.rules: list[Rule] = [
            r for r in ALL_RULES
            if r.id not in ignore and (only is None or r.id in only)
        ]
        self.nested_rules: list[Rule] = [r for r in self.rules if r.id in NESTED_RULE_IDS]
        self.strict = strict
        self.known_tools = known_tools or {}

    def _context(self, depth: int = 0) -> Context:
        return Context(scan_text=self.scan_text, depth=depth, strict=self.strict, known_tools=self.known_tools)

    def scan_text(self, text: str, kind: str, path: str, depth: int) -> list[Finding]:
        """Scan decoded or embedded content with the data-flow rules only."""
        doc = Document(path=path, text=text, kind=kind)
        ctx = self._context(depth)
        out: list[Finding] = []
        for rule in self.nested_rules:
            if rule.applies(doc):
                out.extend(rule.check(doc, ctx))
        return out

    def scan_document(self, doc: Document) -> list[Finding]:
        ctx = self._context(0)
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.applies(doc):
                continue
            try:
                found = rule.check(doc, ctx)
            except Exception as exc:  # a broken rule must never kill the scan
                found = [Finding(
                    rule="PD000", name="rule-error", severity=Severity.INFO,
                    message=f"rule {rule.id} failed on this file: {exc.__class__.__name__}: {exc}",
                    path=doc.path, kind=doc.kind,
                )]
            findings.extend(found)
        findings = apply_ignores(doc, findings)
        return dedupe(_cap(findings, doc))


def _cap(findings: list[Finding], doc: Document) -> list[Finding]:
    per_rule: dict[str, int] = defaultdict(int)
    out: list[Finding] = []
    overflow: dict[str, int] = defaultdict(int)
    for f in findings:
        per_rule[f.rule] += 1
        if per_rule[f.rule] <= MAX_PER_RULE_PER_FILE:
            out.append(f)
        else:
            overflow[f.rule] += 1
    for rule_id, n in overflow.items():
        name = next((f.name for f in out if f.rule == rule_id), rule_id)
        out.append(Finding(
            rule=rule_id, name=name, severity=Severity.INFO,
            message=f"{n} more {name} finding(s) in this file not shown",
            path=doc.path, kind=doc.kind, snippet=f"overflow:{rule_id}",
        ))
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule, f.path, f.line, (f.snippet or "")[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: (-int(f.severity), f.path, f.line or 0, f.rule))
    return out
