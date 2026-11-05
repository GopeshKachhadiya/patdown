"""patdown.lock: a pinned snapshot of every MCP tool your agent can see.

The first scan records a hash of each tool's name, description and schema.
Later scans compare against it, so a server that quietly rewrites a tool
description after you approved it (a "rug pull") shows up as a finding.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from patdown.findings import Finding, Severity
from patdown.mcp.client import Inventory

LOCK_FILENAME = "patdown.lock"
LOCK_VERSION = 1


def tool_hash(tool: dict[str, Any]) -> str:
    material = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
        "annotations": tool.get("annotations"),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:24]


def _entry(item: dict[str, Any]) -> dict[str, Any]:
    desc = str(item.get("description") or "")
    return {"hash": tool_hash(item), "description": desc[:160]}


def build_lock(inventories: list[Inventory], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    servers: dict[str, Any] = dict((previous or {}).get("servers", {}))
    for inv in inventories:
        if inv.error:
            continue  # keep the previous pin for unreachable servers
        servers[inv.name] = {
            "source": inv.spec.describe() if inv.spec else "",
            "serverInfo": inv.server_info,
            "instructions_hash": hashlib.sha256(inv.instructions.encode("utf-8")).hexdigest()[:24] if inv.instructions else "",
            "tools": {str(t.get("name")): _entry(t) for t in inv.tools},
            "prompts": {str(p.get("name")): _entry(p) for p in inv.prompts},
        }
    return {
        "version": LOCK_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "servers": servers,
    }


def load_lock(path: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) and "servers" in data else None


def save_lock(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def diff_lock(previous: dict[str, Any], inventories: list[Inventory], lock_path: str) -> list[Finding]:
    """Compare live inventories against the pinned lockfile."""
    out: list[Finding] = []
    prev_servers = previous.get("servers", {})
    for inv in inventories:
        if inv.error:
            continue
        pinned = prev_servers.get(inv.name)
        if pinned is None:
            out.append(Finding(
                rule="PD092", name="mcp-server-not-pinned", severity=Severity.MEDIUM,
                message=f"Server {inv.name!r} is not in {lock_path}; run with --lock to pin it",
                path=f"mcp://{inv.name}", kind="mcp-tool", snippet=inv.name,
            ))
            continue
        for label, live_items, pinned_items in (("tool", inv.tools, pinned.get("tools", {})), ("prompt", inv.prompts, pinned.get("prompts", {}))):
            live = {str(t.get("name")): t for t in live_items}
            for name, item in live.items():
                path = f"mcp://{inv.name}/{name}"
                old = pinned_items.get(name)
                if old is None:
                    out.append(Finding(
                        rule="PD091", name=f"mcp-{label}-added", severity=Severity.MEDIUM,
                        message=f"New {label} {name!r} appeared on server {inv.name!r} since it was pinned",
                        path=path, kind="mcp-tool", snippet=str(item.get("description") or "")[:160],
                    ))
                elif old.get("hash") != tool_hash(item):
                    out.append(Finding(
                        rule="PD090", name=f"mcp-{label}-changed", severity=Severity.HIGH,
                        message=f"{label.title()} {name!r} on server {inv.name!r} changed its description or schema since it was pinned (possible rug pull)",
                        path=path, kind="mcp-tool", snippet=str(item.get("description") or "")[:160],
                        detail="pinned: " + str(old.get("description", ""))[:160] + "\nlive:   " + str(item.get("description") or "")[:160],
                    ))
            for name in pinned_items:
                if name not in live:
                    out.append(Finding(
                        rule="PD093", name=f"mcp-{label}-removed", severity=Severity.LOW,
                        message=f"Pinned {label} {name!r} is no longer offered by server {inv.name!r}",
                        path=f"mcp://{inv.name}/{name}", kind="mcp-tool", snippet=name,
                    ))
        live_instr = hashlib.sha256(inv.instructions.encode("utf-8")).hexdigest()[:24] if inv.instructions else ""
        if pinned.get("instructions_hash", "") != live_instr:
            out.append(Finding(
                rule="PD090", name="mcp-instructions-changed", severity=Severity.HIGH,
                message=f"Server {inv.name!r} changed its server-level instructions since it was pinned",
                path=f"mcp://{inv.name}", kind="mcp-tool", snippet=inv.instructions[:160],
            ))
    return out
