"""Encoded payloads: base64 / hex / entity / percent / \\u-escaped blobs that
decode to readable text. The decoded text is re-scanned with the data-flow
rules, so an exfil URL hidden in base64 is still caught."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import unquote

from patdown.findings import Finding, Severity
from patdown.rules.base import (
    KIND_CONFIG, KIND_MARKDOWN, KIND_SCRIPT, KIND_TEXT, Context, Document, Rule,
)
from patdown.textutil import printable_ratio

B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
B64URL = re.compile(r"(?<![A-Za-z0-9_\-=])[A-Za-z0-9_\-]{40,}={0,2}(?![A-Za-z0-9_\-=])")
HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{2}){24,}(?![0-9A-Za-z])")
ENTITIES = re.compile(r"(?:&#x?[0-9a-fA-F]{1,6};\s*){8,}")
PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){8,}")
UESC = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}|(?:\\x[0-9a-fA-F]{2}){8,}")
SKIP_BEFORE = ("data:image", "sha256-", "sha384-", "sha512-", "ssh-rsa ", "ssh-ed25519 ", "integrity=", "AAAAB3NzaC")
WORDISH = re.compile(r"[A-Za-z]{3,}(?:\s+[A-Za-z]{2,}){2,}")


class EncodedPayloadRule(Rule):
    id = "PD040"
    name = "encoded-payload"
    description = "Base64/hex/entity-encoded blobs that decode to readable text. Encoding is how instructions and URLs get past a quick human skim."
    severity = Severity.MEDIUM
    kind_severity = {KIND_MARKDOWN: Severity.LOW, KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        text = doc.text
        seen: set[int] = set()

        def report(start: int, label: str, decoded: str) -> None:
            if start in seen:
                return
            seen.add(start)
            nested = ctx.scan_nested(decoded, doc.kind, doc.path)
            preview = decoded.replace("\n", " ")[:300]
            if nested:
                names = ", ".join(sorted({f.name for f in nested}))
                out.append(self.finding(
                    doc, f"{label} decodes to text that triggers: {names}", start,
                    severity=Severity.HIGH, detail="decoded: " + preview,
                ))
            else:
                out.append(self.finding(doc, f"{label} decodes to readable text", start, detail="decoded: " + preview))

        for m in B64.finditer(text):
            ctx_before = text[max(0, m.start() - 24) : m.start()]
            if any(s in ctx_before for s in SKIP_BEFORE):
                continue
            decoded = _b64(m.group(0))
            if decoded is not None and _looks_like_text(decoded):
                report(m.start(), f"Base64 blob ({len(m.group(0))} chars)", decoded)
        for m in B64URL.finditer(text):
            if m.start() in seen or "-" not in m.group(0) and "_" not in m.group(0):
                continue
            decoded = _b64(m.group(0), urlsafe=True)
            if decoded is not None and _looks_like_text(decoded):
                report(m.start(), f"URL-safe base64 blob ({len(m.group(0))} chars)", decoded)
        for m in HEX.finditer(text):
            raw = m.group(0)[2:] if m.group(0).startswith("0x") else m.group(0)
            try:
                data = bytes.fromhex(raw)
            except ValueError:
                continue
            if printable_ratio(data) >= 0.95:
                decoded = data.decode("utf-8", "replace")
                if _looks_like_text(decoded):
                    report(m.start(), f"Hex blob ({len(raw)} chars)", decoded)
        for m in ENTITIES.finditer(text):
            decoded = html.unescape(m.group(0))
            if _looks_like_text(decoded, min_len=8):
                report(m.start(), "HTML-entity-encoded text", decoded)
        for m in PERCENT.finditer(text):
            decoded = unquote(m.group(0))
            if _looks_like_text(decoded, min_len=8):
                report(m.start(), "Percent-encoded text", decoded)
        for m in UESC.finditer(text):
            try:
                decoded = m.group(0).encode("ascii").decode("unicode_escape")
            except (UnicodeDecodeError, UnicodeEncodeError):
                continue
            if _looks_like_text(decoded, min_len=6):
                report(m.start(), "Escape-sequence-encoded text", decoded)
        return out


def _b64(s: str, urlsafe: bool = False) -> str | None:
    pad = "=" * (-len(s) % 4)
    try:
        data = base64.urlsafe_b64decode(s + pad) if urlsafe else base64.b64decode(s + pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) < 16 or printable_ratio(data) < 0.92:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _looks_like_text(s: str, min_len: int = 16) -> bool:
    if len(s) < min_len:
        return False
    if WORDISH.search(s):
        return True
    # URLs / paths / key=value are also "text" worth looking at
    return bool(re.search(r"https?://|[A-Za-z]:\\|/[A-Za-z0-9_.\-]+/|\w+=\w+", s))
