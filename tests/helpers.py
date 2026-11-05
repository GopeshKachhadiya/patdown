from patdown.engine import Scanner
from patdown.rules.base import Document


def scan(text, kind="markdown", path="test.md", **scanner_kwargs):
    scanner = Scanner(**scanner_kwargs)
    return scanner.scan_document(Document(path=path, text=text, kind=kind))


def rules_hit(findings):
    return {f.rule for f in findings}


def names_hit(findings):
    return {f.name for f in findings}


def tag_smuggle(ascii_text):
    return "".join(chr(0xE0000 + ord(c)) for c in ascii_text)


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule == rule_id]
