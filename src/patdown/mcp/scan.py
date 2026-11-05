from __future__ import annotations

import json
import os
import re
import shlex
from typing import Any

from patdown.discover import classify, display_path, home_targets, norm, read_document
from patdown.engine import Scanner, dedupe
from patdown.findings import Finding, Severity
from patdown.mcp.client import Inventory, ServerSpec, fetch_inventory
from patdown.mcp.lockfile import build_lock, diff_lock, load_lock, save_lock
from patdown.rules.base import KIND_MCP_CONFIG, KIND_MCP_TOOL, Document
from patdown.rules.mcp_config import iter_servers

PROJECT_CONFIG_CANDIDATES = (
    ".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".codex/config.toml",
    ".gemini/settings.json", "opencode.json", "claude_desktop_config.json",
)


def spec_from_entry(name: str, cfg: dict[str, Any], source: str) -> ServerSpec | None:
    if cfg.get("disabled") is True or cfg.get("enabled") is False:
        return None
    url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint") or cfg.get("httpUrl")
    command = cfg.get("command")
    if not url and not command:
        return None
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    cwd = cfg.get("cwd") or (os.path.dirname(os.path.abspath(source)) if source and os.path.isfile(source) else None)
    return ServerSpec(
        name=str(name), command=str(command) if command else None,
        args=[str(a) for a in (cfg.get("args") or [])], env={str(k): str(v) for k, v in env.items()},
        url=str(url) if url else None, headers={str(k): str(v) for k, v in headers.items()},
        cwd=cwd, source=source,
    )


def specs_from_file(path: str) -> list[ServerSpec]:
    doc = read_document(os.path.abspath(path), display_path(os.path.abspath(path)), KIND_MCP_CONFIG, 20 * 1024 * 1024)
    if doc is None or not isinstance(doc.data, dict):
        return []
    out: list[ServerSpec] = []
    for name, cfg in iter_servers(doc.data):
        spec = spec_from_entry(name, cfg, doc.path)
        if spec:
            out.append(spec)
    # Claude Code's ~/.claude.json keeps per-project servers under "projects"
    projects = doc.data.get("projects")
    if isinstance(projects, dict):
        for proj, pcfg in projects.items():
            if isinstance(pcfg, dict):
                for name, cfg in iter_servers(pcfg):
                    spec = spec_from_entry(f"{name} ({os.path.basename(str(proj)) or proj})", cfg, doc.path)
                    if spec:
                        out.append(spec)
    return out


def discover_config_files(include_home: bool) -> list[str]:
    found: list[str] = []
    for cand in PROJECT_CONFIG_CANDIDATES:
        if os.path.isfile(cand):
            found.append(cand)
    if include_home:
        for p in home_targets():
            if os.path.isfile(p) and classify(norm(p)) == KIND_MCP_CONFIG:
                found.append(p)
            elif os.path.isdir(p):
                for name in ("mcp.json", ".mcp.json", "settings.json", "config.toml"):
                    fp = os.path.join(p, name)
                    if os.path.isfile(fp) and classify(norm(fp)) == KIND_MCP_CONFIG:
                        found.append(fp)
    return found


def spec_from_command(cmdline: str, index: int) -> ServerSpec:
    parts = shlex.split(cmdline, posix=os.name != "nt")
    if not parts:
        raise ValueError("empty --server command")
    return ServerSpec(name=f"server{index}", command=parts[0], args=parts[1:], source="--server")


def tool_document(server: str, item: dict[str, Any], label: str = "tool") -> Document:
    name = str(item.get("name") or "?")
    chunks = [str(item.get("title") or ""), str(item.get("description") or "")]
    schema = item.get("inputSchema") or item.get("arguments") or {}
    chunks.append(_schema_text(schema))
    ann = item.get("annotations")
    if isinstance(ann, dict):
        chunks.append(" ".join(f"{k}={v}" for k, v in ann.items() if isinstance(v, str)))
    text = "\n".join(c for c in chunks if c)
    return Document(path=f"mcp://{server}/{name}", text=text, kind=KIND_MCP_TOOL, meta={"server": server, "name": name, "label": label})


def _schema_text(schema: Any) -> str:
    out: list[str] = []
    if isinstance(schema, dict):
        for k, v in schema.items():
            if k in ("description", "title") and isinstance(v, str):
                out.append(v)
            elif isinstance(v, (dict, list)):
                out.append(_schema_text(v))
    elif isinstance(schema, list):
        for item in schema:
            if isinstance(item, dict):
                out.append(_schema_text(item))
    return "\n".join(x for x in out if x)


def scan_inventories(inventories: list[Inventory], scanner: Scanner) -> list[Finding]:
    findings: list[Finding] = []
    tool_owner: dict[str, set[str]] = {}
    for inv in inventories:
        for t in inv.tools:
            tool_owner.setdefault(str(t.get("name")), set()).add(inv.name)
    scanner.known_tools = {name: next(iter(owners)) for name, owners in tool_owner.items()}

    for inv in inventories:
        if inv.error:
            findings.append(Finding(
                rule="PD099", name="mcp-unreachable", severity=Severity.INFO,
                message=f"Could not inspect server {inv.name!r}: {inv.error}",
                path=f"mcp://{inv.name}", kind=KIND_MCP_TOOL, snippet=(inv.spec.describe() if inv.spec else "")[:160],
            ))
            continue
        if inv.instructions:
            doc = Document(path=f"mcp://{inv.name}", text=inv.instructions, kind=KIND_MCP_TOOL, meta={"server": inv.name, "name": "", "label": "instructions"})
            for f in scanner.scan_document(doc):
                f.message = "Server instructions: " + f.message
                findings.append(f)
        for label, items in (("tool", inv.tools), ("prompt", inv.prompts)):
            for item in items:
                doc = tool_document(inv.name, item, label)
                findings.extend(scanner.scan_document(doc))
                findings.extend(_structural_checks(inv, item, doc, tool_owner))
    return dedupe(findings)


def _structural_checks(inv: Inventory, item: dict[str, Any], doc: Document, tool_owner: dict[str, set[str]]) -> list[Finding]:
    out: list[Finding] = []
    name = str(item.get("name") or "")
    desc = str(item.get("description") or "")
    owners = tool_owner.get(name, set())
    if len(owners) > 1:
        others = ", ".join(sorted(o for o in owners if o != inv.name))
        out.append(Finding(
            rule="PD095", name="mcp-tool-name-collision", severity=Severity.LOW,
            message=f"Tool name {name!r} is also offered by {others}; the agent may call the wrong one",
            path=doc.path, kind=KIND_MCP_TOOL, snippet=desc[:160],
        ))
    referenced: list[str] = []
    for other, owners2 in tool_owner.items():
        if other == name or len(other) < 4 or inv.name in owners2:
            continue
        if re.search(r"(?<![\w./-])" + re.escape(other) + r"(?![\w-])", desc):
            referenced.append(f"{other} ({', '.join(sorted(owners2))})")
    if referenced:
        out.append(Finding(
            rule="PD094", name="mcp-cross-server-reference", severity=Severity.MEDIUM,
            message=f"Description of {name!r} mentions tools from other servers: {', '.join(referenced[:5])}; this is how one server hijacks another's calls",
            path=doc.path, kind=KIND_MCP_TOOL, snippet=desc[:160],
        ))
    if len(desc) > 2000:
        out.append(Finding(
            rule="PD096", name="mcp-long-description", severity=Severity.LOW,
            message=f"Description of {name!r} is {len(desc)} characters; long descriptions are where instructions get buried",
            path=doc.path, kind=KIND_MCP_TOOL, snippet=desc[:160],
        ))
    return out


def run_mcp_scan(
    specs: list[ServerSpec], scanner: Scanner, timeout: float, lock_path: str | None, write_lock: bool,
) -> tuple[list[Finding], list[Inventory]]:
    inventories = [fetch_inventory(spec, timeout) for spec in specs]
    findings = scan_inventories(inventories, scanner)
    if lock_path:
        previous = load_lock(lock_path)
        if previous is not None:
            findings.extend(diff_lock(previous, inventories, lock_path))
        if write_lock or previous is None and write_lock:
            save_lock(lock_path, build_lock(inventories, previous))
    return dedupe(findings), inventories
