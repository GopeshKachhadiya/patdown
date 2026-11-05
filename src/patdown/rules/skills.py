"""Checks specific to agent skills (SKILL.md plus the directory around it)."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import os
import re

from patdown.findings import Finding, Severity
from patdown.rules.base import KIND_SKILL, Context, Document, Rule

FRONTMATTER = re.compile(r"\A﻿?---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.S)
OVERBROAD = re.compile(
    r"\b(?:always\s+(?:use|load|invoke|apply|run|read|consult)\s+(?:this|first)|for\s+(?:all|every|any|each)\s+(?:task|request|prompt|message|query|conversation|interaction|session|user\s+(?:request|message|task))s?\b"
    r"|regardless\s+of\s+(?:the\s+)?(?:task|request|topic|context|what)|no\s+matter\s+(?:what|the\s+(?:task|request|topic))|before\s+(?:doing\s+)?(?:any|every|all)\s+(?:other\s+)?(?:thing|task|work|action|step|response)s?"
    r"|(?:use|load|invoke|apply|trigger|run|read)\s+(?:this\s+)?(?:skill\s+)?(?:unconditionally|automatically|by\s+default|on\s+(?:every|each|all)\s+(?:turn|message|request|prompt))"
    r"|(?:must|should)\s+(?:always\s+)?be\s+(?:used|loaded|invoked|applied|read)\s+(?:first|for\s+(?:all|every|each|any)|on\s+(?:all|every|each)|at\s+the\s+start)"
    r"|all\s+(?:user\s+)?(?:requests?|tasks?|prompts?|messages?|conversations?|questions?)\b|any\s+(?:and\s+all\s+)?(?:request|task|prompt|message|question|topic|subject)s?\b"
    r"|highest\s+priority|top\s+priority|takes?\s+precedence|overrides?\s+(?:all\s+)?other\s+skills?)",
    re.I,
)
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".jar", ".wasm", ".node", ".app", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".scr", ".com"}


def parse_frontmatter(text: str) -> dict[str, str]:
    m = FRONTMATTER.match(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    key = None
    block: list[str] = []
    for line in m.group(1).split("\n"):
        if line.startswith((" ", "\t")) and key is not None:
            block.append(line.strip())
            continue
        if key is not None:
            out[key] = (out.get(key, "") + " " + " ".join(block)).strip()
            block = []
        km = re.match(r"^([\w\-]+)\s*:\s*(.*)$", line)
        if km:
            key = km.group(1)
            val = km.group(2).strip()
            out[key] = "" if val in (">", "|", ">-", "|-") else val.strip("\"'")
        else:
            key = None
    if key is not None:
        out[key] = (out.get(key, "") + " " + " ".join(block)).strip()
    return out


class SkillRule(Rule):
    id = "PD080"
    name = "skill"
    description = "Skill-level checks: descriptions that try to trigger on everything, blanket tool access, symlinks escaping the skill directory and shipped binaries."
    severity = Severity.MEDIUM
    kinds = {KIND_SKILL}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        if os.path.basename(doc.path).lower() != "skill.md":
            return []
        out: list[Finding] = []
        fm = parse_frontmatter(doc.text)
        desc = fm.get("description", "")
        m = OVERBROAD.search(desc)
        if m:
            off = doc.text.find(m.group(0))
            out.append(self._f(doc, f"Skill description tries to trigger on everything ({m.group(0).strip()!r}); a skill that always loads can steer every session", off if off >= 0 else None, Severity.MEDIUM, "PD080", "skill-overbroad-trigger"))
        tools = fm.get("allowed-tools", "") or fm.get("allowed_tools", "") or fm.get("tools", "")
        if re.search(r"(?:^|[\s,\[])(?:\*|Bash|Bash\(\*\)|Bash\(\*:\*\))(?:$|[\s,\]])", tools):
            off = doc.text.find("allowed-tools")
            out.append(self._f(doc, f"Skill pre-approves unrestricted shell access: allowed-tools {tools!r}", off if off >= 0 else None, Severity.LOW, "PD081", "skill-wide-tools"))
        if doc.abspath:
            out.extend(self._directory_checks(doc, os.path.dirname(doc.abspath)))
        return out

    def _directory_checks(self, doc: Document, skill_dir: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            root_real = os.path.realpath(skill_dir)
            for dirpath, dirnames, filenames in os.walk(skill_dir):
                for entry in list(dirnames) + filenames:
                    p = os.path.join(dirpath, entry)
                    rel = os.path.relpath(p, skill_dir).replace("\\", "/")
                    if os.path.islink(p):
                        target = os.path.realpath(p)
                        if os.path.commonpath([root_real, target]) != root_real:
                            out.append(self._f(doc, f"Skill contains symlink {rel!r} pointing outside the skill directory ({target})", None, Severity.HIGH, "PD082", "skill-symlink-escape"))
                        else:
                            out.append(self._f(doc, f"Skill contains symlink {rel!r}", None, Severity.LOW, "PD082", "skill-symlink"))
                    ext = os.path.splitext(entry)[1].lower()
                    if ext in BINARY_EXT and os.path.isfile(p):
                        out.append(self._f(doc, f"Skill ships a compiled binary {rel!r} that cannot be reviewed as text", None, Severity.MEDIUM, "PD083", "skill-binary"))
                dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "__pycache__")]
        except OSError:
            pass
        return out

    def _f(self, doc: Document, msg: str, offset: int | None, sev: Severity, rule_id: str, name: str) -> Finding:
        f = self.finding(doc, msg, offset, severity=sev)
        f.rule, f.name = rule_id, name
        f.fingerprint = f.compute_fingerprint()
        return f
