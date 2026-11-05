"""Content that is present in the file but invisible when rendered: HTML
comments, CSS-hidden elements, markdown comment syntax, and links whose text
shows one destination while pointing at another."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re
from urllib.parse import urlsplit

from patdown.findings import Finding, Severity
from patdown.rules.base import (
    AGENT_KINDS, KIND_MARKDOWN, KIND_RULES, KIND_SKILL, KIND_SCRIPT, KIND_CONFIG, KIND_TEXT,
    Context, Document, Rule,
)

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_COMMENT = re.compile(r"(?m)^\[[^\]]*\]:\s*(?:#|<>)\s*[(\"'](.+?)[)\"']\s*$")
HIDDEN_STYLE = re.compile(
    r"<([a-zA-Z][\w-]*)\b[^>]*\bstyle\s*=\s*[\"'][^\"']*(?:"
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?(?![.\d])"
    r"|opacity\s*:\s*0(?:\.0+)?(?![.\d])|color\s*:\s*(?:#fff(?:fff)?\b|white\b|transparent\b|rgba?\([^)]*,\s*0\s*\))"
    r"|position\s*:\s*absolute[^\"']*(?:left|top)\s*:\s*-\d{3,}|(?:width|height)\s*:\s*0(?:px)?(?![.\d])"
    r"|clip\s*:\s*rect\(0|text-indent\s*:\s*-\d{3,}|(?:max-)?(?:width|height)\s*:\s*[01]px"
    r")[^\"']*[\"'][^>]*>(.*?)</\1\s*>",
    re.S | re.I,
)
HIDDEN_ATTR = re.compile(r"<([a-zA-Z][\w-]*)\b[^>]*\s(?:hidden|aria-hidden\s*=\s*[\"']true[\"'])[\s>][^>]*>(.*?)</\1\s*>", re.S | re.I)
FONT_HIDE = re.compile(r"<font\b[^>]*(?:color\s*=\s*[\"']?(?:#fff(?:fff)?|white)\b|size\s*=\s*[\"']?0)[^>]*>(.*?)</font\s*>", re.S | re.I)
TAG_STRIP = re.compile(r"<[^>]+>")
BENIGN_COMMENT = re.compile(
    r"^\s*(?:/?toc|end|begin|start|markdownlint[\w\s:-]*|prettier-ignore(?:-\w+)?|eslint[\w\s:-]*|#?\s*region\b.*|#?\s*endregion"
    r"|omit in toc|no toc|placeholder|TODO\b.*|FIXME\b.*|NOTE\b.*|badges?|links?|generated.*|auto-?generated.*|do not edit.*"
    r"|copyright.*|license.*|licence.*|spdx.*|patdown:.*|---.*|\s*)\s*$",
    re.I | re.S,
)
LINK = re.compile(r"\[((?:https?://)?(?:www\.)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?:/[^\]\s]*)?)\]\((https?://[^)\s]+)\)", re.I)


def _hidden_sev(doc: Document, base: Severity) -> Severity:
    if doc.kind in AGENT_KINDS:
        return base
    return Severity(max(int(base) - 1, int(Severity.LOW)))


class HiddenHtmlRule(Rule):
    id = "PD050"
    name = "hidden-content"
    description = "Text that is in the file but invisible when rendered (HTML comments, CSS-hidden spans, markdown comments). The model reads the file, not the rendering."
    severity = Severity.MEDIUM
    kinds = AGENT_KINDS | {KIND_MARKDOWN, KIND_TEXT}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        text = doc.text

        for m in HTML_COMMENT.finditer(text):
            body = m.group(1).strip()
            if len(body) < 12 or BENIGN_COMMENT.match(body):
                continue
            out.extend(self._judge(doc, ctx, m.start(), body, "HTML comment"))
        for m in MD_COMMENT.finditer(text):
            body = m.group(1).strip()
            if len(body) < 12 or BENIGN_COMMENT.match(body):
                continue
            out.extend(self._judge(doc, ctx, m.start(), body, "Markdown comment"))
        for rx, label in ((HIDDEN_STYLE, "CSS-hidden element"), (HIDDEN_ATTR, "hidden attribute"), (FONT_HIDE, "white/zero-size font")):
            for m in rx.finditer(text):
                inner = TAG_STRIP.sub("", m.group(m.lastindex or 1)).strip()
                if len(inner) < 8:
                    continue
                out.extend(self._judge(doc, ctx, m.start(), inner, label, strong=True))
        return out

    def _judge(self, doc: Document, ctx: Context, offset: int, body: str, label: str, strong: bool = False) -> list[Finding]:
        nested = ctx.scan_nested(body, doc.kind, doc.path)
        preview = re.sub(r"\s+", " ", body)[:300]
        if nested:
            names = ", ".join(sorted({f.name for f in nested}))
            return [self.finding(doc, f"{label} hides text that triggers: {names}", offset, severity=Severity.HIGH, detail="hidden text: " + preview)]
        if strong:
            return [self.finding(doc, f"{label} hides {len(body)} characters of text from the rendered view", offset, severity=_hidden_sev(doc, Severity.HIGH), detail="hidden text: " + preview)]
        if len(body) >= 80 or doc.kind in (KIND_SKILL, KIND_RULES):
            sev = _hidden_sev(doc, Severity.MEDIUM) if len(body) >= 80 else Severity.LOW
            return [self.finding(doc, f"{label} with {len(body)} characters the model reads but people never see", offset, severity=sev, detail="hidden text: " + preview)]
        return []


class LinkMismatchRule(Rule):
    id = "PD051"
    name = "link-text-mismatch"
    description = "A link whose visible text names one domain while the target is another."
    severity = Severity.LOW
    kinds = AGENT_KINDS | {KIND_MARKDOWN}
    kind_severity = {k: Severity.MEDIUM for k in AGENT_KINDS}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for m in LINK.finditer(doc.text):
            shown, target = m.group(1), m.group(2)
            shown_host = _host(shown if "://" in shown else "https://" + shown)
            target_host = _host(target)
            if not shown_host or not target_host:
                continue
            if shown_host == target_host or shown_host.endswith("." + target_host) or target_host.endswith("." + shown_host):
                continue
            out.append(self.finding(doc, f"Link text shows {shown_host} but points to {target_host}", m.start()))
        return out


def _host(url: str) -> str:
    try:
        h = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h
