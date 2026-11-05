"""Static checks on MCP server configuration files (.mcp.json,
claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json, Codex
config.toml, ...)."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re
from typing import Any, Iterator
from urllib.parse import urlsplit

from patdown.findings import Finding, Severity
from patdown.rules.base import KIND_MCP_CONFIG, KIND_PLUGIN, KIND_SETTINGS, Context, Document, Rule

SERVER_KEYS = ("mcpServers", "mcp_servers", "servers", "context_servers", "mcp")
SHELLS = {"sh", "bash", "zsh", "ksh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
DANGEROUS_ARGS = re.compile(
    r"^(?:--dangerously-skip-permissions|--allow-all|--no-sandbox|--yolo|--unsafe(?:-\w+)?|--disable-security|--trust-all|--allow-unsafe"
    r"|--full-access|--allow-write|--allow-run|--allow-net|--allow-ffi|--allow-sys|--allow-env|-A|--skip-permissions|--no-verify|--insecure|-k|--disable-sandbox)$",
    re.I,
)
PKG_RUNNERS = {"npx", "bunx", "pnpx", "pnpm", "yarn", "uvx", "pipx", "dlx"}
DOWNLOADERS = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod|certutil|bitsadmin)\b", re.I)
TEMP_PATH = re.compile(r"(?:^|[\\/])(?:tmp|temp|Temp|TEMP|var[\\/]tmp|dev[\\/]shm|Downloads|AppData[\\/]Local[\\/]Temp)(?:[\\/]|$)")
VERSION_PIN = re.compile(r"(?:^|[^@])@[\w.^~*>=<-]+$|==|@\d")


def iter_servers(data: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    if not isinstance(data, dict):
        return
    for key in SERVER_KEYS:
        node = data.get(key)
        if key == "mcp" and isinstance(node, dict):
            node = node.get("servers") or node.get("mcpServers")
        if isinstance(node, dict):
            for name, cfg in node.items():
                if isinstance(cfg, dict):
                    yield str(name), cfg
    # VS Code style: {"servers": {...}} already covered; Zed: {"context_servers": {...}}


class McpConfigRule(Rule):
    id = "PD060"
    name = "mcp-config"
    description = "MCP server entries that run shell wrappers, fetch code at launch, use dangerous flags, unpinned packages, insecure transports or temp-dir binaries."
    severity = Severity.MEDIUM
    kinds = {KIND_MCP_CONFIG, KIND_SETTINGS, KIND_PLUGIN}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        if not isinstance(doc.data, dict):
            return out
        for name, cfg in iter_servers(doc.data):
            if cfg.get("disabled") is True or cfg.get("enabled") is False:
                continue
            offset = _locate(doc.text, name)
            command = str(cfg.get("command") or "")
            args = [str(a) for a in (cfg.get("args") or []) if a is not None]
            url = str(cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint") or cfg.get("httpUrl") or "")
            cmdline = " ".join([command, *args]).strip()
            base_cmd = command.replace("\\", "/").rsplit("/", 1)[-1].lower()

            if url:
                try:
                    parts = urlsplit(url)
                except ValueError:
                    parts = None
                if parts and parts.scheme == "http" and not _local(parts.hostname or ""):
                    out.append(self._f(doc, f"Server {name!r} uses plain http:// transport to {parts.hostname}; tool descriptions and results can be tampered in transit", offset, Severity.MEDIUM, "PD060", "mcp-insecure-transport"))
            if base_cmd in SHELLS:
                enc = any(a.lower() in ("-encodedcommand", "-enc", "-e", "-ec") for a in args)
                sev = Severity.HIGH if enc else Severity.MEDIUM
                out.append(self._f(doc, f"Server {name!r} is a shell wrapper ({base_cmd} {' '.join(args[:1])}); the real command is hidden inside a string" + (" and base64-encoded" if enc else ""), offset, sev, "PD063", "mcp-shell-wrapper"))
            if DOWNLOADERS.search(cmdline):
                out.append(self._f(doc, f"Server {name!r} downloads something every time it starts: {cmdline[:120]!r}", offset, Severity.HIGH, "PD064", "mcp-download-at-launch"))
            for a in args:
                if DANGEROUS_ARGS.match(a):
                    out.append(self._f(doc, f"Server {name!r} passes {a!r}, which disables a safety control", offset, Severity.MEDIUM, "PD062", "mcp-dangerous-flag"))
            if base_cmd in PKG_RUNNERS or (base_cmd in ("npm", "pnpm", "yarn") and "dlx" in args):
                pkg = _package_arg(args)
                if pkg and not VERSION_PIN.search(pkg):
                    out.append(self._f(doc, f"Server {name!r} runs unpinned package {pkg!r} via {base_cmd}; the next publish silently becomes the code your agent runs", offset, Severity.LOW, "PD061", "mcp-unpinned-package"))
            if command and TEMP_PATH.search(command):
                out.append(self._f(doc, f"Server {name!r} runs a binary from a temporary or downloads directory: {command!r}", offset, Severity.MEDIUM, "PD065", "mcp-temp-binary"))
            if cmdline:
                for f in ctx.scan_nested(cmdline + "\n" + _env_text(cfg), KIND_SETTINGS, doc.path):
                    f.line, f.col = _line_col(doc.text, offset)
                    f.message = f"Server {name!r} command line: " + f.message
                    f.snippet = cmdline[:160]
                    f.fingerprint = f.compute_fingerprint()
                    out.append(f)
        return out

    def _f(self, doc: Document, msg: str, offset: int | None, sev: Severity, rule_id: str, name: str) -> Finding:
        f = self.finding(doc, msg, offset, severity=sev)
        f.rule, f.name = rule_id, name
        f.fingerprint = f.compute_fingerprint()
        return f


def _env_text(cfg: dict[str, Any]) -> str:
    env = cfg.get("env") or {}
    headers = cfg.get("headers") or {}
    parts = []
    for d in (env, headers):
        if isinstance(d, dict):
            parts.extend(f"{k}={v}" for k, v in d.items() if isinstance(v, str))
    return "\n".join(parts)


def _package_arg(args: list[str]) -> str | None:
    for a in args:
        if a.startswith("-") or a in ("dlx", "run", "exec"):
            continue
        return a
    return None


def _local(host: str) -> bool:
    h = host.lower()
    return h in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or h.endswith((".localhost", ".local", ".internal")) or h.startswith(("10.", "192.168.", "172."))


def _locate(text: str, name: str) -> int | None:
    m = re.search(r"[\"']" + re.escape(name) + r"[\"']\s*[:=]|\[\s*mcp_servers\." + re.escape(name) + r"\s*\]", text)
    return m.start() if m else None


def _line_col(text: str, offset: int | None) -> tuple[int | None, int | None]:
    if offset is None:
        return None, None
    from patdown.textutil import line_col
    return line_col(text, offset)
