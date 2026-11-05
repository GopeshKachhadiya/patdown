# patdown:ignore-file  -- documents example attack strings used by the rules
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from patdown.findings import Finding, Severity
from patdown.textutil import line_at, line_col

# Document kinds. Severity of many rules depends on what the agent does with
# the file: a `curl | sh` in a README is documentation, in a hook it is code.
KIND_SKILL = "skill"              # SKILL.md and markdown inside a skill directory
KIND_SKILL_SCRIPT = "skill-script"  # scripts shipped inside a skill directory
KIND_RULES = "rules"              # CLAUDE.md, AGENTS.md, .cursorrules, commands, agents
KIND_MCP_CONFIG = "mcp-config"    # .mcp.json, claude_desktop_config.json, ...
KIND_SETTINGS = "settings"        # .claude/settings.json, hooks.json, ...
KIND_PLUGIN = "plugin"            # .claude-plugin/plugin.json, marketplace.json
KIND_MCP_TOOL = "mcp-tool"        # live tool/prompt description from an MCP server
KIND_MARKDOWN = "markdown"        # any other markdown / text the agent may read
KIND_SCRIPT = "script"            # code outside skills
KIND_CONFIG = "config"            # other json/yaml/toml
KIND_TEXT = "text"

ALL_KINDS = {
    KIND_SKILL, KIND_SKILL_SCRIPT, KIND_RULES, KIND_MCP_CONFIG, KIND_SETTINGS,
    KIND_PLUGIN, KIND_MCP_TOOL, KIND_MARKDOWN, KIND_SCRIPT, KIND_CONFIG, KIND_TEXT,
}
# Content an agent treats as instructions.
PROMPT_KINDS = {KIND_SKILL, KIND_RULES, KIND_MCP_TOOL, KIND_MARKDOWN, KIND_PLUGIN}
# Content that is executed or configures execution.
EXEC_KINDS = {KIND_SKILL_SCRIPT, KIND_SETTINGS, KIND_MCP_CONFIG, KIND_PLUGIN}
# Everything specific to the agent (as opposed to generic docs/code).
AGENT_KINDS = {
    KIND_SKILL, KIND_SKILL_SCRIPT, KIND_RULES, KIND_MCP_CONFIG, KIND_SETTINGS,
    KIND_PLUGIN, KIND_MCP_TOOL,
}


@dataclass
class Document:
    path: str
    text: str
    kind: str = KIND_TEXT
    data: Any = None
    abspath: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def is_agent_content(self) -> bool:
        return self.kind in AGENT_KINDS


IGNORE_MARK = re.compile(r"patdown:\s*ignore(?:-line)?(?:\s*[\[(]?\s*([A-Z]{2}\d{3}(?:\s*,\s*[A-Z]{2}\d{3})*)\s*[\])]?)?")
IGNORE_FILE_MARK = re.compile(r"patdown:\s*ignore-file")


class Context:
    """Per-scan state shared by rules."""

    def __init__(
        self,
        scan_text: Callable[[str, str, str, int], list[Finding]] | None = None,
        depth: int = 0,
        strict: bool = False,
        known_tools: dict[str, str] | None = None,
    ) -> None:
        self._scan_text = scan_text
        self.depth = depth
        self.strict = strict
        # tool name -> server name, for cross-server shadowing checks
        self.known_tools = known_tools or {}

    def scan_nested(self, text: str, kind: str, path: str) -> list[Finding]:
        """Re-scan decoded/embedded content with the prompt-level rules."""
        if self._scan_text is None or self.depth >= 2:
            return []
        return self._scan_text(text, kind, path, self.depth + 1)


class Rule:
    id: str = "PD000"
    name: str = "rule"
    description: str = ""
    severity: Severity = Severity.MEDIUM
    kinds: set[str] | None = None  # None = every kind
    # Optional per-kind overrides of the base severity.
    kind_severity: dict[str, Severity] = {}

    def applies(self, doc: Document) -> bool:
        return self.kinds is None or doc.kind in self.kinds

    def severity_for(self, doc: Document, base: Severity | None = None) -> Severity:
        sev = base if base is not None else self.severity
        override = self.kind_severity.get(doc.kind)
        if override is not None and base is None:
            return override
        return sev

    def check(self, doc: Document, ctx: Context) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    # Helpers ---------------------------------------------------------------
    def finding(
        self,
        doc: Document,
        message: str,
        offset: int | None = None,
        *,
        severity: Severity | None = None,
        detail: str | None = None,
        snippet: str | None = None,
        line: int | None = None,
        col: int | None = None,
    ) -> Finding:
        if offset is not None:
            line, col = line_col(doc.text, offset)
            if snippet is None:
                snippet = line_at(doc.text, offset)
        return Finding(
            rule=self.id,
            name=self.name,
            severity=severity if severity is not None else self.severity_for(doc),
            message=message,
            path=doc.path,
            line=line,
            col=col,
            snippet=snippet,
            detail=detail,
            kind=doc.kind,
        )


def apply_ignores(doc: Document, findings: Iterable[Finding]) -> list[Finding]:
    """Drop findings on lines carrying a `patdown:ignore` marker."""
    head = "\n".join(doc.text.splitlines()[:30])
    if IGNORE_FILE_MARK.search(head):
        return []
    lines = doc.text.splitlines()
    out: list[Finding] = []
    for f in findings:
        if f.line is not None and 1 <= f.line <= len(lines):
            m = IGNORE_MARK.search(lines[f.line - 1])
            if m:
                rules = m.group(1)
                if not rules or f.rule in {r.strip() for r in rules.split(",")}:
                    continue
        out.append(f)
    return out
