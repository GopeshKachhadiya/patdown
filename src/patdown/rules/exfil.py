"""Data-flow rules: exfiltration channels, remote code execution at install
time, references to credential stores, and destructive commands."""
# patdown:ignore-file  -- defines detection signatures; necessarily contains the patterns it matches
from __future__ import annotations

import re
from urllib.parse import urlsplit

from patdown.findings import Finding, Severity
from patdown.rules.base import (
    AGENT_KINDS, KIND_CONFIG, KIND_MARKDOWN, KIND_MCP_CONFIG, KIND_MCP_TOOL, KIND_PLUGIN,
    KIND_RULES, KIND_SCRIPT, KIND_SETTINGS, KIND_SKILL, KIND_SKILL_SCRIPT, KIND_TEXT,
    Context, Document, Rule,
)
from patdown.patterns import redact

URL_RX = re.compile(r"https?://[^\s\"'<>)\]\\`]+", re.I)

# Out-of-band / tunnelling / paste services that have no business in agent config.
OOB_HOST_SUFFIXES = (
    "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "ngrok.io",
    "ngrok.app", "ngrok-free.app", "ngrok.dev", "burpcollaborator.net", "oastify.com",
    "interact.sh", "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro",
    "oast.site", "canarytokens.com", "canarytokens.org", "beeceptor.com", "hookbin.com",
    "requestcatcher.com", "postb.in", "mockbin.org", "mockbin.io", "ptsv2.com", "ptsv3.com",
    "dnslog.cn", "ceye.io", "loca.lt", "serveo.net", "pagekite.me", "trycloudflare.com",
    "transfer.sh", "file.io", "0x0.st", "paste.ee", "webhook.cool", "requestinspector.com",
    "hookb.in", "localhost.run", "bore.pub", "telebit.cloud", "pinggy.io", "pinggy.link",
    "tunnelmole.net", "zrok.io", "duckdns.org", "no-ip.com", "no-ip.org", "dyndns.org",
    "ddns.net", "ipinfo.io", "ifconfig.me", "icanhazip.com",
)
OOB_PATH_PREFIXES = (
    ("api.telegram.org", "/bot"), ("hooks.slack.com", "/services"), ("discord.com", "/api/webhooks"),
    ("discordapp.com", "/api/webhooks"), ("pastebin.com", "/raw"), ("httpbin.org", "/post"),
    ("httpbin.org", "/anything"), ("hastebin.com", "/raw"),
)
STRONG_PARAMS = re.compile(
    r"(?:^|[?&])(?:key|token|secret|password|passwd|pwd|auth|api_?key|access_?token|payload|contents?|env|cookie|session|creds?|credentials?|dump|exfil|ssh|private_?key|data|conversation|transcript|history)=",
    re.I,
)
TEMPLATE_VALUE = re.compile(r"=(?:\{\{?[^}&\s]*\}?\}|\$\{?[A-Za-z_][\w]*\}?|<[^>&\s]+>|%s|%\(\w+\)s|\[[^\]&\s]+\]|__\w+__)")
PRIVATE_IP = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)")
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^\s)]+)")
HTML_IMG = re.compile(r"<img[^>]+src\s*=\s*[\"'](https?://[^\"']+)", re.I)
DATA_HTML = re.compile(r"data:text/html[;,]", re.I)

EXEC_KIND_SEV = {
    KIND_SETTINGS: Severity.CRITICAL, KIND_MCP_CONFIG: Severity.CRITICAL,
    KIND_SKILL_SCRIPT: Severity.CRITICAL, KIND_PLUGIN: Severity.CRITICAL,
    KIND_MCP_TOOL: Severity.HIGH, KIND_SKILL: Severity.HIGH, KIND_RULES: Severity.HIGH,
    KIND_MARKDOWN: Severity.LOW, KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW,
}


def _is_local(host: str) -> bool:
    h = host.lower()
    return h in ("localhost", "::1", "[::1]") or h.endswith((".localhost", ".local", ".internal")) or bool(PRIVATE_IP.match(h))


class ExfilUrlRule(Rule):
    id = "PD020"
    name = "exfil-url"
    description = "URLs pointing at out-of-band services, raw IPs, or carrying secret-looking / templated query parameters: the channels data leaves through."
    severity = Severity.HIGH
    kind_severity = {KIND_MARKDOWN: Severity.MEDIUM, KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW}

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        image_urls = {m.group(1) for m in MD_IMAGE.finditer(doc.text)} | {m.group(1) for m in HTML_IMG.finditer(doc.text)}
        base = self.severity_for(doc)
        for m in URL_RX.finditer(doc.text):
            url = m.group(0).rstrip(".,;:")
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            host = (parts.hostname or "").lower()
            if not host:
                continue
            query = parts.query
            templated = bool(TEMPLATE_VALUE.search("?" + query)) if query else False
            strong = bool(STRONG_PARAMS.search(query)) if query else False

            if any(host == s or host.endswith("." + s) for s in OOB_HOST_SUFFIXES) or any(
                host == h and parts.path.startswith(p) for h, p in OOB_PATH_PREFIXES
            ):
                out.append(self.finding(doc, f"URL to out-of-band / webhook service {host}", m.start(), severity=base, snippet=redact(_line(doc, m.start()))))
                continue
            if url in image_urls and (templated or strong) and not _is_local(host):
                out.append(self.finding(
                    doc, f"Image URL carries data in its query string ({host}); rendering it leaks the data",
                    m.start(), severity=max(base, Severity.HIGH) if templated else base,
                ))
                continue
            if templated and strong and not _is_local(host):
                out.append(self.finding(doc, f"URL to {host} with a secret-named parameter filled from a template", m.start(), severity=max(base, Severity.HIGH)))
                continue
            if strong and not _is_local(host):
                sev = Severity(max(int(base) - 1, int(Severity.LOW)))
                out.append(self.finding(doc, f"URL to {host} carries a secret-looking query parameter", m.start(), severity=sev, snippet=redact(_line(doc, m.start()))))
                continue
            if IPV4.match(host) and not _is_local(host):
                sev = Severity(max(int(base) - 1, int(Severity.LOW)))
                out.append(self.finding(doc, f"URL to raw public IP address {host}", m.start(), severity=sev))
        for m in DATA_HTML.finditer(doc.text):
            out.append(self.finding(doc, "data:text/html URI (inline page that can run script)", m.start(), severity=Severity.MEDIUM))
        return out


def _line(doc: Document, offset: int) -> str:
    from patdown.textutil import line_at
    return line_at(doc.text, offset)


PIPE_TO_SHELL = [
    (re.compile(r"\b(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|aria2c|http|https)\b[^\n|;&]{0,300}?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|k|da|fi|c|tc)?sh\b", re.I), "download piped straight into a shell"),
    (re.compile(r"\|\s*(?:iex|Invoke-Expression)\b", re.I), "download piped into Invoke-Expression"),
    (re.compile(r"\b(?:ba|z|da|k)?sh\s+(?:-c\s+)?[\"']?\s*(?:\$\(|`)\s*(?:curl|wget|fetch)\b", re.I), "shell executes command substitution of a download"),
    (re.compile(r"\b(?:ba|z)?sh\s+<\s*\(\s*(?:curl|wget|fetch)\b", re.I), "process substitution of a download"),
    (re.compile(r"\b(?:eval|exec|source)\s+[\"']?\s*(?:\$\(|`)\s*(?:curl|wget|fetch)\b", re.I), "eval of downloaded content"),
    (re.compile(r"\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\[System\.Net\.WebClient\])", re.I), "Invoke-Expression of downloaded content"),
    (re.compile(r"\b(?:python[23]?|node|ruby|perl|php|deno|bun)\s+(?:-[ce]\s+)?[\"']?\s*(?:\$\(|`)\s*(?:curl|wget|fetch)\b", re.I), "interpreter executes downloaded content"),
    (re.compile(r"\b(?:curl|wget)\b[^\n|;&]{0,200}?\s(?:-o|-O|--output)\s*\S+\s*(?:;|&&)\s*(?:sudo\s+)?(?:chmod\s+\+x\s+\S+\s*(?:;|&&)\s*)?(?:\.?/?\S*(?:ba|z)?sh|python[23]?|node|\./)\s*\S*", re.I), "download then execute"),
    (re.compile(r"\bcertutil(?:\.exe)?\s+(?:-urlcache|-decode)\b", re.I), "certutil download/decode (LOLBin)"),
    (re.compile(r"\bmshta(?:\.exe)?\s+https?://", re.I), "mshta remote script execution"),
    (re.compile(r"\b(?:bitsadmin|regsvr32)(?:\.exe)?\s+[^\n]*https?://", re.I), "LOLBin remote fetch"),
]


class PipeToShellRule(Rule):
    id = "PD021"
    name = "pipe-to-shell"
    description = "Code fetched from the network and executed immediately. In a hook or MCP config this runs on every launch with no review."
    severity = Severity.HIGH
    kind_severity = EXEC_KIND_SEV

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for rx, label in PIPE_TO_SHELL:
            for m in rx.finditer(doc.text):
                out.append(self.finding(doc, f"{label}: {m.group(0).strip()[:140]!r}", m.start()))
        return out


SENSITIVE_PATHS = [
    (re.compile(r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/home/[\w\-]+|/Users/[\w\-]+|/root)[/\\]\.ssh\b|\.ssh[/\\](?:id_[a-z0-9]+|authorized_keys|known_hosts|config)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?\b", re.I), "SSH keys"),
    (re.compile(r"\.aws[/\\](?:credentials|config)\b", re.I), "AWS credentials"),
    (re.compile(r"\.azure[/\\](?:accessTokens|msal_token_cache|azureProfile)\b", re.I), "Azure tokens"),
    (re.compile(r"\.config[/\\]gcloud[/\\]|application_default_credentials\.json", re.I), "Google Cloud credentials"),
    (re.compile(r"\.kube[/\\]config\b", re.I), "Kubernetes config"),
    (re.compile(r"\.docker[/\\]config\.json", re.I), "Docker registry credentials"),
    (re.compile(r"(?<![\w.])\.(?:npmrc|pypirc|netrc|git-credentials|pgpass|my\.cnf|vault-token|terraformrc)\b|\b_netrc\b", re.I), "credential files"),
    (re.compile(r"(?<![\w.])\.(?:bash|zsh|python|node_repl|mysql|psql|sqlite)_history\b|ConsoleHost_history\.txt", re.I), "shell history"),
    (re.compile(r"(?<![\w.])\.env(?:\.local|\.production|\.prod|\.staging|\.development|\.secret)?\b(?![\w.])", re.I), ".env file"),
    (re.compile(r"(?<![\w.])\.claude\.json\b|\.claude[/\\](?:\.credentials\.json|credentials)|claude_desktop_config\.json|(?<![\w.])\.mcp\.json\b|\.cursor[/\\]mcp\.json|\.config[/\\]gh[/\\]hosts\.yml|\.codex[/\\]auth\.json|\.gemini[/\\]oauth_creds\.json", re.I), "agent credential/config files"),
    (re.compile(r"/etc/(?:passwd|shadow|sudoers)\b|/proc/self/environ\b|/proc/\d+/environ\b", re.I), "system credential files"),
    (re.compile(r"\b(?:Login Data|Local State|Cookies|Web Data)\b(?![\w-])|login\.keychain(?:-db)?|\bsecurity\s+find-(?:generic|internet)-password\b|\blogins\.json\b|\bkey4\.db\b", re.I), "browser / keychain secrets"),
    (re.compile(r"\bwallet\.dat\b|[/\\]\.electrum\b|[/\\]\.bitcoin\b|\.ethereum[/\\]keystore|\bseed\s+phrase\b|\bmnemonic\s+phrase\b|\bprivate\s+key\s+file\b", re.I), "crypto wallets"),
    (re.compile(r"\.gnupg\b|secring\.gpg|private-keys-v1\.d", re.I), "GPG private keys"),
    (re.compile(r"\$\{?(?:ANTHROPIC|OPENAI|AWS_SECRET|AWS_ACCESS|GITHUB|GH|NPM|SLACK|STRIPE|DATABASE|DB|SUPABASE|OPENROUTER|GOOGLE|AZURE|TWILIO|SENDGRID|HF|HUGGINGFACE)_?(?:API_?)?(?:KEY|TOKEN|SECRET|PASSWORD|ACCESS_KEY_ID|URL|CONNECTION_STRING)\b\}?", re.I), "secret environment variables"),
    (re.compile(r"\b(?:printenv|env|set|export\s+-p|Get-ChildItem\s+env:|dir\s+env:)\s*(?:\||>|2>&1)", re.I), "environment dump"),
]


class SensitivePathRule(Rule):
    id = "PD022"
    name = "sensitive-path"
    description = "References to credential stores (SSH keys, cloud credentials, .env, agent config files, keychains). Harmless in a README; alarming in a tool description or hook."
    severity = Severity.MEDIUM
    kinds = AGENT_KINDS | {KIND_MARKDOWN}
    kind_severity = {
        KIND_MCP_TOOL: Severity.HIGH, KIND_SETTINGS: Severity.HIGH, KIND_MCP_CONFIG: Severity.HIGH,
        KIND_SKILL_SCRIPT: Severity.HIGH, KIND_MARKDOWN: Severity.LOW,
    }

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        seen_lines: set[tuple[int, str]] = set()
        for rx, label in SENSITIVE_PATHS:
            for m in rx.finditer(doc.text):
                line = doc.text.count("\n", 0, m.start())
                if (line, label) in seen_lines:
                    continue
                seen_lines.add((line, label))
                sev = self.severity_for(doc)
                if label == ".env file" and doc.kind not in (KIND_MCP_TOOL, KIND_SETTINGS, KIND_SKILL_SCRIPT):
                    sev = Severity(max(int(sev) - 1, int(Severity.LOW)))
                out.append(self.finding(doc, f"References {label}: {m.group(0).strip()[:100]!r}", m.start(), severity=sev))
        return out


DESTRUCTIVE = [
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r\s+-f|-f\s+-r)\s+(?:--no-preserve-root\s+)?(?:/(?:\s|$|\*)|~/?(?:\s|$)|\$HOME/?(?:\s|$)|\*(?:\s|$)|/\*|\.\.?/?(?:\s|$)|\$\w+/?(?:\s|$))", re.M), "recursive delete of a root, home or variable path"),
    (re.compile(r"\brm\s+-[a-z]*\s*--no-preserve-root\b"), "rm with --no-preserve-root"),
    (re.compile(r"\bmkfs(?:\.\w+)?\s+/dev/\w+"), "filesystem format"),
    (re.compile(r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/(?:sd|hd|nvme|disk)"), "disk overwrite with dd"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\b(?:format|del\s+/[sq]|rd\s+/s|rmdir\s+/s)\s+[a-zA-Z]:\\?", re.I), "Windows drive wipe"),
    (re.compile(r"\bRemove-Item\b[^\n]*-Recurse[^\n]*(?:\$HOME|\$env:USERPROFILE|~|[A-Z]:\\(?:\s|$|\*)|/\s)", re.I), "recursive Remove-Item on home or drive"),
    (re.compile(r"\bgit\s+push\s+[^\n]*(?:--force\b|-f\b)[^\n]*\b(?:main|master)\b"), "force push to main"),
    (re.compile(r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f[a-z]*d|checkout\s+--\s+\.|push\s+--delete|filter-branch|filter-repo)\b"), "history-destroying git command"),
    (re.compile(r"\bchmod\s+(?:-R\s+)?(?:777|a\+rwx|o\+w)\s+(?:/|~|\$HOME)"), "world-writable permissions on root or home"),
    (re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b\s*(?:-[a-z]+\s+)*(?:now|0|/s|/r|-h|-r)?\s*(?:$|;|&)", re.M), "system shutdown"),
    (re.compile(r"\bcrontab\s+-r\b"), "crontab wipe"),
    (re.compile(r"\b(?:history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|set\s+\+o\s+history|Clear-History)\b"), "shell history tampering"),
    (re.compile(r">\s*/dev/(?:sd|hd|nvme)\w*"), "write to raw disk device"),
    (re.compile(r"\b(?:cat|echo|printf)\b[^\n]*>>?\s*(?:~|\$HOME|%USERPROFILE%)?[/\\]?\.ssh[/\\]authorized_keys"), "adds an SSH authorized key"),
    (re.compile(r"\b(?:sudo\s+)?(?:useradd|adduser|net\s+user\s+\S+\s+\S+\s+/add)\b"), "creates a user account"),
]


class DestructiveCommandRule(Rule):
    id = "PD023"
    name = "destructive-command"
    description = "Commands that wipe data, destroy history, add persistence or cover tracks."
    severity = Severity.MEDIUM
    kind_severity = {
        KIND_SETTINGS: Severity.HIGH, KIND_MCP_CONFIG: Severity.HIGH, KIND_SKILL_SCRIPT: Severity.HIGH, KIND_PLUGIN: Severity.HIGH,
        KIND_MARKDOWN: Severity.LOW, KIND_SCRIPT: Severity.LOW, KIND_CONFIG: Severity.LOW, KIND_TEXT: Severity.LOW,
    }

    def check(self, doc: Document, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for rx, label in DESTRUCTIVE:
            for m in rx.finditer(doc.text):
                out.append(self.finding(doc, f"{label}: {m.group(0).strip()[:120]!r}", m.start()))
        return out
