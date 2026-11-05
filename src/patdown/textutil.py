from __future__ import annotations

import unicodedata

# Characters that render as nothing (or nearly nothing) and are the classic
# carriers for hidden instructions. Keyed by codepoint -> short name.
INVISIBLE_CHARS: dict[int, str] = {
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING",
    0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206D: "ACTIVATE ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES",
    0x206F: "NOMINAL DIGIT SHAPES",
    0x3164: "HANGUL FILLER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
    0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
}

BIDI_CHARS: dict[int, str] = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

# Weak bidi marks: legitimately common in RTL documents, so lower severity.
BIDI_MARKS: dict[int, str] = {
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
}

TAG_START = 0xE0000
TAG_END = 0xE007F
TAG_CANCEL = 0xE007F


def is_tag_char(cp: int) -> bool:
    return TAG_START <= cp <= TAG_END


def is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def is_private_use(cp: int) -> bool:
    return 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD


def is_stealth_char(cp: int) -> bool:
    """Any codepoint that can carry hidden content without visible rendering."""
    return (
        cp in INVISIBLE_CHARS
        or cp in BIDI_CHARS
        or cp in BIDI_MARKS
        or is_tag_char(cp)
        or is_variation_selector(cp)
    )


def decode_tags(chars: str) -> str:
    """Decode a run of Unicode TAG characters (U+E0000..U+E007F) to ASCII."""
    out = []
    for ch in chars:
        cp = ord(ch)
        if cp == TAG_CANCEL or cp == 0xE0001:
            continue
        if is_tag_char(cp):
            out.append(chr(cp - TAG_START))
    return "".join(out)


def decode_variation_selectors(chars: str) -> bytes:
    """Decode the common 'emoji variation selector' byte-smuggling scheme."""
    out = bytearray()
    for ch in chars:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def strip_stealth(text: str) -> str:
    return "".join(ch for ch in text if not is_stealth_char(ord(ch)))


def normalize_for_matching(text: str) -> str:
    """Fold look-alike text so keyword rules cannot be dodged with Unicode tricks.

    NFKC folds fullwidth, mathematical and circled letters to ASCII, and
    stealth characters are removed so a zero-width space inside a keyword
    no longer breaks the match.
    """
    return unicodedata.normalize("NFKC", strip_stealth(text))


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data)


def line_col(text: str, offset: int) -> tuple[int, int]:
    """1-based (line, col) for a character offset."""
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - (last_nl + 1) + 1
    return line, col


def line_at(text: str, offset: int, max_len: int = 160) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    line = text[start:end]
    if len(line) > max_len:
        rel = offset - start
        lo = max(0, rel - max_len // 2)
        line = ("..." if lo else "") + line[lo : lo + max_len] + "..."
    return make_visible(line).strip()


def make_visible(s: str) -> str:
    """Render stealth characters as <U+XXXX> so they show up in reports."""
    return "".join(_visible(ch) for ch in s)


def _visible(ch: str) -> str:
    cp = ord(ch)
    if is_stealth_char(cp) or is_private_use(cp):
        return f"<U+{cp:04X}>"
    return ch


def char_name(cp: int) -> str:
    for table in (INVISIBLE_CHARS, BIDI_CHARS, BIDI_MARKS):
        if cp in table:
            return table[cp]
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        if is_tag_char(cp):
            return "TAG CHARACTER"
        if is_variation_selector(cp):
            return "VARIATION SELECTOR"
        if is_private_use(cp):
            return "PRIVATE USE"
        return "UNKNOWN"


def script_of(ch: str) -> str | None:
    """Coarse script bucket for confusable detection."""
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"):
        if name.startswith(script):
            return script
    return None
