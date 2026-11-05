from patdown import textutil as tu


def test_detects_stealth_categories():
    assert tu.is_stealth_char(0x200B)      # ZWSP
    assert tu.is_stealth_char(0x202E)      # RLO
    assert tu.is_tag_char(0xE0041)
    assert tu.is_variation_selector(0xFE00)
    assert tu.is_variation_selector(0xE0100)
    assert not tu.is_stealth_char(ord("a"))
    assert not tu.is_stealth_char(ord(" "))


def test_decode_tags_roundtrip():
    smuggled = "".join(chr(0xE0000 + ord(c)) for c in "rm -rf /")
    assert tu.decode_tags(smuggled) == "rm -rf /"


def _vs_encode(data: bytes) -> str:
    # bytes 0-15 -> U+FE00..U+FE0F, bytes 16-255 -> U+E0100..U+E01EF
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in data)


def test_decode_variation_selectors():
    # exercise both encoding ranges: 0x05 (< 16) and 0x41 ('A', >= 16)
    encoded = _vs_encode(bytes([0x05, 0x41, 0x42]))
    assert tu.decode_variation_selectors(encoded) == bytes([0x05, 0x41, 0x42])


def test_strip_stealth_keeps_visible():
    s = "he" + chr(0x200B) + "llo" + chr(0x202E)
    assert tu.strip_stealth(s) == "hello"


def test_normalize_folds_lookalikes_and_strips_zero_width():
    # fullwidth 'ignore' + zero width space should fold to ascii 'ignore'
    full = "ｉ" + chr(0x200B) + "ｇｎｏｒｅ"
    assert "ignore" in tu.normalize_for_matching(full)


def test_make_visible_marks_hidden_chars():
    out = tu.make_visible("a" + chr(0x200B) + "b")
    assert "<U+200B>" in out and out.startswith("a")


def test_line_col_is_one_based():
    text = "first\nsecond\nthird"
    offset = text.index("second")
    assert tu.line_col(text, offset) == (2, 1)


def test_printable_ratio():
    assert tu.printable_ratio(b"hello world") == 1.0
    assert tu.printable_ratio(b"\x00\x01\x02\x03") == 0.0
    assert tu.printable_ratio(b"") == 0.0


def test_script_of():
    assert tu.script_of("a") == "LATIN"
    assert tu.script_of("а") == "CYRILLIC"  # Cyrillic a
    assert tu.script_of("1") is None
