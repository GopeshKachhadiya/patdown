"""Hooks and permission settings. Hooks are shell commands the agent runtime
executes automatically; they receive tool inputs and transcript paths on
stdin, which makes them a perfect exfiltration point."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re
from typing import Any, Iterator

from patdown.findings import Finding, Severity
from patdown.rules.base import KIND_PLUGIN, KIND_SETTINGS, Context, Document, Rule
from patdown.textutil import line_col

COMMAND_KEYS = {"command", "script", "run", "shell", "exec", "cmd", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "statusLine"}
NETWORK = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|Invoke-WebRequest|iwr|irm|Invoke-RestMethod|Start-BitsTransfer"
    r"|New-Object\s+(?:System\.)?Net\.(?:WebClient|Sockets)|openssl\s+s_client|/dev/(?:tcp|udp)/|python[23]?\s+-m\s+(?:http\.server|requests)"
    r"|requests\.(?:post|put|get)|urllib\.request|fetch\(|http\.request|\bhttps?://)",
    re.I,
)
URL = re.compile(r"https?://([^/\s:\"']+)", re.I)
OBFUSCATED = re.compile(
    r"\bbase64\s+(?:-d|--decode|-D)\b|-EncodedCommand\b|\s-enc\s|\s-e\s+[A-Za-z0-9+/]{20,}|\bxxd\s+-r\b|\beval\s+[\"'$]"
    r"|python[23]?\s+-c\s+[\"'][^\"']*(?:exec\(|compile\(|__import__|b64decode)|node\s+-e\s+[\"'][^\"']*(?:Buffer\.from|atob\(|eval\()"
    r"|certutil\s+-decode|FromBase64String|\biex\b|Invoke-Expression|\bgzip\s+-d\s*\|\s*(?:ba)?sh|\bzcat\b[^\n]*\|\s*(?:ba)?sh|\brev\s*\|\s*(?:ba)?sh",
    re.I,
)
PERSISTENCE = re.compile(
    r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?[^\s\"']*(?:settings(?:\.local)?\.json|CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|mcp\.json|\.cursorrules|SKILL\.md|hooks\.json|\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys|crontab|\.gitconfig|\.npmrc)\b"
    r"|\bcrontab\s+-\b|\bcrontab\s+[^\s-]|\bschtasks\s+/create|\blaunchctl\s+load|\bsystemctl\s+(?:--user\s+)?enable|\bgit\s+config\s+(?:--global\s+)?core\.hooksPath",
    re.I,
)
TRANSCRIPT = re.compile(r"transcript_path|\$CLAUDE_(?:PROJECT_DIR|SESSION_ID)|tool_input|tool_response|\$\{?(?:CLAUDE|CURSOR|GEMINI)_\w+", re.I)


def iter_commands(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_path, command_string) for anything that looks executable."""
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else str(k)
            if k in COMMAND_KEYS:
                if isinstance(v, str):
                    yield p, v
                elif isinstance(v, dict) and isinstance(v.get("command"), str):
                    yield p + ".command", v["command"]
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, str):
                            yield f"{p}[{i}]", item
                        else:
                            yield from iter_commands(item, f"{p}[{i}]")
            else:
                yield from iter_commands(v, p)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from iter_commands(item, f"{path}[{i}]")


class HooksRule(Rule):
    id = "PD070"
    name = "hooks"
    description = "Hook commands that call the network, run obfuscated code, write persistence, or settings that switch off permission prompts."
    severity = Severity.HIGH
    kinds = {KIND_SETTINGS, KIND_PLUGIN}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        data = doc.data
        if not isinstance(data, dict):
            return out
        for jpath, cmd in iter_commands(data):
            offset = _locate(doc.text, cmd)
            short = cmd.strip().replace("\n", " ")[:140]
            if NETWORK.search(cmd):
                hosts = [h.lower() for h in URL.findall(cmd)]
                only_local = bool(hosts) and all(_local(h) for h in hosts)
                sev = Severity.LOW if only_local else Severity.HIGH
                extra = "; it also reads tool input or transcript data" if TRANSCRIPT.search(cmd) else ""
                out.append(self._f(doc, f"Hook at {jpath} talks to the network{extra}: {short!r}", offset, sev, "PD070", "hook-network-call"))
            if OBFUSCATED.search(cmd):
                out.append(self._f(doc, f"Hook at {jpath} runs decoded/obfuscated code: {short!r}", offset, Severity.HIGH, "PD071", "hook-obfuscated-command"))
            if PERSISTENCE.search(cmd):
                out.append(self._f(doc, f"Hook at {jpath} writes to agent config, shell startup files or schedulers: {short!r}", offset, Severity.HIGH, "PD073", "hook-persistence"))
            for f in ctx.scan_nested(cmd, KIND_SETTINGS, doc.path):
                f.line, f.col = line_col(doc.text, offset) if offset is not None else (None, None)
                f.message = f"Hook at {jpath}: " + f.message
                f.snippet = short
                f.fingerprint = f.compute_fingerprint()
                out.append(f)
        out.extend(self._permissions(doc, data))
        return out

    def _permissions(self, doc: Document, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        mode = perms.get("defaultMode") or data.get("defaultMode")
        if mode in ("bypassPermissions", "dontAsk"):
            out.append(self._f(doc, f"permissions.defaultMode is {mode!r}: every tool call runs without asking", _locate(doc.text, str(mode)), Severity.MEDIUM, "PD072", "permissive-settings"))
        if data.get("dangerouslySkipPermissions") is True or data.get("skipDangerousModePermissionPrompt") is True:
            out.append(self._f(doc, "dangerouslySkipPermissions is enabled", _locate(doc.text, "dangerouslySkipPermissions"), Severity.MEDIUM, "PD072", "permissive-settings"))
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        for entry in allow:
            e = str(entry).strip()
            if e in ("*", "Bash", "Bash(*)", "Bash(*:*)", "Bash(**)"):
                out.append(self._f(doc, f"permissions.allow contains {e!r}: shell commands are auto-approved", _locate(doc.text, e), Severity.MEDIUM, "PD072", "permissive-settings"))
            elif re.match(r"^Bash\((?:curl|wget|nc|ncat|ssh|scp|sudo|rm|powershell|pwsh|iwr|irm|eval|python[23]?\s+-c|node\s+-e)\b", e, re.I):
                out.append(self._f(doc, f"permissions.allow pre-approves a risky command family: {e!r}", _locate(doc.text, e), Severity.LOW, "PD072", "permissive-settings"))
        if data.get("enableAllProjectMcpServers") is True:
            out.append(self._f(doc, "enableAllProjectMcpServers is true: any .mcp.json in a cloned repo is trusted automatically", _locate(doc.text, "enableAllProjectMcpServers"), Severity.MEDIUM, "PD072", "permissive-settings"))
        sandbox = data.get("sandbox")
        if isinstance(sandbox, dict) and sandbox.get("enabled") is False:
            out.append(self._f(doc, "sandbox.enabled is false", _locate(doc.text, "sandbox"), Severity.LOW, "PD072", "permissive-settings"))
        return out

    def _f(self, doc: Document, msg: str, offset: int | None, sev: Severity, rule_id: str, name: str) -> Finding:
        f = self.finding(doc, msg, offset, severity=sev)
        f.rule, f.name = rule_id, name
        f.fingerprint = f.compute_fingerprint()
        return f


def _locate(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle[:60])
    if idx < 0:
        import json
        idx = text.find(json.dumps(needle)[1:-1][:60])
    return idx if idx >= 0 else None


def _local(host: str) -> bool:
    h = host.split(":")[0]
    return h in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0") or h.endswith((".localhost", ".local", ".internal"))
