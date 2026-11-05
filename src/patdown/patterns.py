"""Shared regexes for secrets so snippets can be redacted everywhere."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re

# (name, regex, severity-name)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("Stripe key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Groq key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("Replicate token", re.compile(r"\br8_[A-Za-z0-9]{30,}\b")),
    ("Perplexity key", re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Twilio key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{30,}")),
]

# Weak secrets are flagged at MEDIUM rather than HIGH.
WEAK_SECRET_NAMES = {"JWT", "Bearer token"}

SECRETISH_KEY = re.compile(
    r"(?i)(?:api[_\-]?key|secret|token|passw(?:or)?d|passphrase|credential|auth|private[_\-]?key|access[_\-]?key|client[_\-]?secret)"
)

ENV_REF = re.compile(r"^\s*(?:\$\{?[A-Z0-9_]+\}?|%[A-Z0-9_]+%|\$\{env:[^}]+\}|\$\{input:[^}]+\}|<[^>]+>|\{\{[^}]+\}\})\s*$")


def looks_like_placeholder(value: str) -> bool:
    v = value.strip()
    if not v or ENV_REF.match(v):
        return True
    low = v.lower()
    return any(tok in low for tok in ("your_", "your-", "xxxx", "<your", "example", "changeme", "replace", "placeholder", "todo"))


def redact(text: str) -> str:
    """Mask anything secret-looking in a snippet before it reaches a report."""
    for name, rx in SECRET_PATTERNS:
        text = rx.sub(lambda m: _mask(m.group(0)), text)
    return text


def _mask(tok: str) -> str:
    if len(tok) <= 8:
        return "*" * len(tok)
    return tok[:4] + "*" * min(len(tok) - 6, 24) + tok[-2:]
