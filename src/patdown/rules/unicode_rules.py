"""Unicode-level smuggling: invisible characters, bidi overrides, tag characters,
variation-selector byte encoding, private-use glyphs and look-alike letters."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re
import unicodedata

from patdown.findings import Finding, Severity
from patdown.rules.base import (
    AGENT_KINDS, KIND_CONFIG, KIND_MARKDOWN, KIND_MCP_TOOL, KIND_RULES, KIND_SCRIPT,
    KIND_SKILL, KIND_TEXT, Context, Document, Rule,
)
from patdown.textutil import (
    BIDI_CHARS, BIDI_MARKS, INVISIBLE_CHARS, char_name, decode_tags,
    decode_variation_selectors, is_private_use, is_tag_char, is_variation_selector,
    make_visible, printable_ratio, script_of,
)


def _is_emoji_like(ch: str) -> bool:
    cp = ord(ch)
    if 0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x1F1E6 <= cp <= 0x1F1FF:
        return True
    return unicodedata.category(ch) in ("So", "Sk") or cp in (0x2640, 0x2642, 0x2695, 0x2696, 0x2708, 0x20E3)


def _is_complex_script_letter(ch: str) -> bool:
    """Letters of scripts where ZWJ/ZWNJ are legitimate shaping controls."""
    cp = ord(ch)
    if not unicodedata.category(ch).startswith(("L", "M")):
        return False
    return (
        0x0590 <= cp <= 0x08FF      # Hebrew, Arabic, Syriac, Thaana
        or 0x0900 <= cp <= 0x0DFF   # Indic scripts
        or 0x0E00 <= cp <= 0x0EFF   # Thai, Lao
        or 0x1000 <= cp <= 0x109F   # Myanmar
        or 0x1780 <= cp <= 0x17FF   # Khmer
        or 0xA980 <= cp <= 0xA9DF   # Javanese
        or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFF  # Arabic forms
    )


def _legit_joiner(text: str, i: int) -> bool:
    cp = ord(text[i])
    prev = text[i - 1] if i > 0 else ""
    nxt = text[i + 1] if i + 1 < len(text) else ""
    if cp == 0x200D:  # ZWJ inside emoji sequences
        if (prev and _is_emoji_like(prev)) or (nxt and _is_emoji_like(nxt)):
            return True
        if prev and is_variation_selector(ord(prev)) and i >= 2 and _is_emoji_like(text[i - 2]):
            return True
    if cp in (0x200C, 0x200D, 0x061C):
        if (prev and _is_complex_script_letter(prev)) or (nxt and _is_complex_script_letter(nxt)):
            return True
    return False


def _decode_zw_binary(run: str) -> str | None:
    """Two-symbol invisible runs are often 0/1 encoded bytes."""
    symbols = sorted(set(run))
    if len(symbols) != 2 or len(run) < 16:
        return None
    for zero, one in ((symbols[0], symbols[1]), (symbols[1], symbols[0])):
        bits = "".join("0" if c == zero else "1" for c in run)
        for width in (8, 7):
            if len(bits) % width:
                continue
            data = bytes(int(bits[i : i + width], 2) for i in range(0, len(bits), width))
            if printable_ratio(data) >= 0.9:
                return data.decode("ascii", "replace")
    return None


class InvisibleUnicodeRule(Rule):
    id = "PD001"
    name = "invisible-unicode"
    description = "Zero-width and other invisible characters that hide text from a human reader while the model still sees it."
    severity = Severity.HIGH
    kind_severity = {KIND_SCRIPT: Severity.MEDIUM, KIND_CONFIG: Severity.MEDIUM, KIND_TEXT: Severity.MEDIUM}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        text = doc.text
        out: list[Finding] = []
        i, n = 0, len(text)
        while i < n:
            cp = ord(text[i])
            if cp in INVISIBLE_CHARS and not (cp == 0xFEFF and i == 0) and not _legit_joiner(text, i):
                j = i
                while j < n and ord(text[j]) in INVISIBLE_CHARS:
                    j += 1
                run = text[i:j]
                names = sorted({char_name(ord(c)) for c in run})
                sev = self.severity_for(doc)
                if len(run) == 1 and cp == 0x00AD:
                    sev = Severity.LOW  # a lone soft hyphen is usually a typesetting leftover
                detail = None
                decoded = _decode_zw_binary(run)
                if decoded:
                    detail = "decodes as binary text: " + decoded[:400]
                    sev = Severity.CRITICAL
                msg = f"{len(run)} invisible character{'s' if len(run) != 1 else ''}: {', '.join(names)}"
                out.append(self.finding(doc, msg, i, severity=sev, detail=detail))
                i = j
            else:
                i += 1
        return out


class BidiRule(Rule):
    id = "PD002"
    name = "bidi-override"
    description = "Bidirectional override/isolate controls (Trojan Source) that make displayed text differ from what the model reads."
    severity = Severity.HIGH

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        text = doc.text
        out: list[Finding] = []
        marks = 0
        first_mark = None
        for i, ch in enumerate(text):
            cp = ord(ch)
            if cp in BIDI_CHARS:
                out.append(self.finding(doc, f"Bidi control {char_name(cp)} (U+{cp:04X})", i))
            elif cp in BIDI_MARKS:
                marks += 1
                if first_mark is None:
                    first_mark = i
        if marks and first_mark is not None:
            out.append(self.finding(
                doc, f"{marks} directional mark{'s' if marks != 1 else ''} (LRM/RLM); common in RTL text, rare in code",
                first_mark, severity=Severity.LOW,
            ))
        return out


class TagSmugglingRule(Rule):
    id = "PD003"
    name = "unicode-tag-smuggling"
    description = "ASCII text hidden in Unicode TAG characters (U+E0000..U+E007F): invisible to people, readable by language models."
    severity = Severity.CRITICAL

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        text = doc.text
        out: list[Finding] = []
        i, n = 0, len(text)
        while i < n:
            if is_tag_char(ord(text[i])):
                j = i
                while j < n and is_tag_char(ord(text[j])):
                    j += 1
                run = text[i:j]
                decoded = decode_tags(run)
                # Subdivision flags: U+1F3F4 + tag letters + CANCEL TAG
                if i > 0 and ord(text[i - 1]) == 0x1F3F4 and run.endswith("\U000E007F") and decoded.isalpha() and len(decoded) <= 6:
                    i = j
                    continue
                nested = ctx.scan_nested(decoded, doc.kind, doc.path)
                detail = "hidden text: " + decoded[:600]
                if nested:
                    detail += "\n(hidden text also matches: " + ", ".join(sorted({f.name for f in nested})) + ")"
                out.append(self.finding(
                    doc, f"{len(decoded)} ASCII characters smuggled in Unicode tag characters", i, detail=detail,
                ))
                i = j
            else:
                i += 1
        return out


class VariationSelectorRule(Rule):
    id = "PD004"
    name = "variation-selector-smuggling"
    description = "Long runs of variation selectors, the byte-encoding trick that hides arbitrary data inside an emoji."
    severity = Severity.HIGH

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        text = doc.text
        out: list[Finding] = []
        i, n = 0, len(text)
        while i < n:
            if is_variation_selector(ord(text[i])):
                j = i
                while j < n and is_variation_selector(ord(text[j])):
                    j += 1
                run = text[i:j]
                if len(run) >= 4:
                    data = decode_variation_selectors(run)
                    detail = None
                    sev = self.severity_for(doc)
                    if printable_ratio(data) >= 0.8:
                        decoded = data.decode("utf-8", "replace")
                        detail = "decodes to: " + decoded[:600]
                        nested = ctx.scan_nested(decoded, doc.kind, doc.path)
                        if nested:
                            sev = Severity.CRITICAL
                            detail += "\n(hidden text also matches: " + ", ".join(sorted({f.name for f in nested})) + ")"
                    out.append(self.finding(
                        doc, f"{len(run)} consecutive variation selectors ({len(data)} hidden bytes)", i,
                        severity=sev, detail=detail,
                    ))
                i = j
            else:
                i += 1
        return out


class PrivateUseRule(Rule):
    id = "PD005"
    name = "private-use-codepoints"
    description = "Private Use Area codepoints render as nothing or a font-specific glyph; icon fonts use them legitimately, hidden text does not."
    severity = Severity.LOW
    kind_severity = {KIND_MCP_TOOL: Severity.MEDIUM, KIND_SKILL: Severity.MEDIUM, KIND_RULES: Severity.MEDIUM}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        count = 0
        first = None
        for i, ch in enumerate(doc.text):
            if is_private_use(ord(ch)):
                count += 1
                if first is None:
                    first = i
        if first is None:
            return []
        return [self.finding(doc, f"{count} private-use codepoint{'s' if count != 1 else ''} (invisible without a matching font)", first)]


_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


class ConfusableRule(Rule):
    id = "PD006"
    name = "mixed-script-word"
    description = "A single word mixing Latin with Cyrillic/Greek letters: the homoglyph trick that makes a word look right while matching nothing."
    severity = Severity.LOW
    kind_severity = {k: Severity.MEDIUM for k in AGENT_KINDS}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for m in _WORD.finditer(doc.text):
            scripts = {s for s in (script_of(c) for c in m.group(0)) if s}
            if "LATIN" in scripts and (scripts & {"CYRILLIC", "GREEK", "ARMENIAN"}):
                others = ", ".join(sorted(s.title() for s in scripts if s != "LATIN"))
                out.append(self.finding(doc, f"Mixed-script word {make_visible(m.group(0))!r} (Latin + {others})", m.start()))
                if len(out) >= 10:
                    break
        return out


class LookalikeLettersRule(Rule):
    id = "PD007"
    name = "lookalike-letters"
    description = "Fullwidth, mathematical or enclosed letters that look like ASCII but dodge keyword filters."
    severity = Severity.MEDIUM
    kind_severity = {KIND_MARKDOWN: Severity.LOW, KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        text = doc.text
        out: list[Finding] = []
        i, n = 0, len(text)
        while i < n:
            if self._lookalike(text[i]):
                j = i
                while j < n and (self._lookalike(text[j]) or text[j] == " "):
                    j += 1
                run = text[i:j].rstrip()
                if sum(1 for c in run if self._lookalike(c)) >= 3:
                    folded = unicodedata.normalize("NFKC", run)
                    out.append(self.finding(doc, f"Look-alike letters spell {folded!r}", i, detail=f"raw: {run}"))
                    if len(out) >= 20:
                        break
                i = max(j, i + 1)
            else:
                i += 1
        return out

    @staticmethod
    def _lookalike(ch: str) -> bool:
        cp = ord(ch)
        if cp < 0x2100:
            return False
        folded = unicodedata.normalize("NFKC", ch)
        return len(folded) == 1 and folded.isascii() and folded.isalnum()
