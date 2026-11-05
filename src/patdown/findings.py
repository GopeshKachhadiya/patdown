from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.name.lower() for s in cls)
            )

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


_WS = re.compile(r"\s+")


@dataclass
class Finding:
    rule: str
    name: str
    severity: Severity
    message: str
    path: str
    line: int | None = None
    col: int | None = None
    snippet: str | None = None
    detail: str | None = None
    kind: str = "text"
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        norm_snippet = _WS.sub(" ", (self.snippet or "")).strip()[:200]
        raw = "\x1f".join([self.rule, self.path.replace("\\", "/"), norm_snippet])
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    def location(self) -> str:
        loc = self.path
        if self.line is not None:
            loc += f":{self.line}"
            if self.col is not None:
                loc += f":{self.col}"
        return loc
