from __future__ import annotations

import os
import sys
from collections import Counter, OrderedDict

from patdown.findings import Finding, Severity

COLORS = {
    Severity.CRITICAL: "\x1b[1;95m",
    Severity.HIGH: "\x1b[1;91m",
    Severity.MEDIUM: "\x1b[1;93m",
    Severity.LOW: "\x1b[1;96m",
    Severity.INFO: "\x1b[2m",
}
RESET = "\x1b[0m"
DIM = "\x1b[2m"
BOLD = "\x1b[1m"


def want_color(flag: bool | None) -> bool:
    if flag is not None:
        return flag
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        _enable_windows_vt()
    return True


def _enable_windows_vt() -> None:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def render_terminal(findings: list[Finding], stats: dict[str, object], color: bool, verbose: bool = False) -> str:
    c = (lambda s, code: f"{code}{s}{RESET}") if color else (lambda s, code: s)
    lines: list[str] = []
    by_path: "OrderedDict[str, list[Finding]]" = OrderedDict()
    for f in findings:
        by_path.setdefault(f.path, []).append(f)

    for path, items in by_path.items():
        worst = max(items, key=lambda f: f.severity).severity
        lines.append(c(path, BOLD) + c(f"  ({len(items)} finding{'s' if len(items) != 1 else ''})", DIM))
        for f in sorted(items, key=lambda f: (-int(f.severity), f.line or 0)):
            tag = c(f"[{f.severity.name}]", COLORS[f.severity])
            loc = f"line {f.line}" + (f":{f.col}" if f.col else "") if f.line else ""
            lines.append(f"  {tag} {c(f.rule, BOLD)} {f.name}  {c(loc, DIM)}")
            lines.append(f"      {f.message}")
            if f.snippet and not f.snippet.startswith("overflow:"):
                lines.append(c(f"      > {f.snippet}", DIM))
            if f.detail:
                for dl in f.detail.splitlines():
                    lines.append(c(f"      | {dl}", DIM))
        lines.append("")
        del worst

    counts = Counter(f.severity for f in findings)
    if findings:
        summary = ", ".join(
            c(f"{counts[s]} {s.name.lower()}", COLORS[s]) for s in sorted(counts, reverse=True)
        )
        lines.append(f"{c('Findings:', BOLD)} {summary}")
    else:
        lines.append(c("No findings.", "\x1b[1;92m") if color else "No findings.")
    scanned = stats.get("files")
    servers = stats.get("servers")
    bits = []
    if scanned is not None:
        bits.append(f"{scanned} file{'s' if scanned != 1 else ''}")
    if servers:
        bits.append(f"{servers} MCP server{'s' if servers != 1 else ''}")
    if bits:
        lines.append(c(f"Scanned {', '.join(bits)} in {stats.get('seconds', 0):.2f}s", DIM))
    suppressed = stats.get("baselined")
    if suppressed:
        lines.append(c(f"{suppressed} finding(s) suppressed by baseline", DIM))
    return "\n".join(lines)
