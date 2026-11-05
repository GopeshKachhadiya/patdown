from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterator

from patdown.rules.base import (
    KIND_CONFIG, KIND_MARKDOWN, KIND_MCP_CONFIG, KIND_PLUGIN, KIND_RULES,
    KIND_SCRIPT, KIND_SETTINGS, KIND_SKILL, KIND_SKILL_SCRIPT, KIND_TEXT, Document,
)

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox",
    ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", "target",
    ".next", ".nuxt", ".turbo", "coverage", ".gradle", ".terraform", "site-packages",
    ".eggs", ".cache", ".parcel-cache",
}
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "uv.lock", "Gemfile.lock", "composer.lock", "go.sum", "bun.lockb", "flake.lock",
    ".patdown-baseline.json", "patdown.lock",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".psd", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".zip", ".gz", ".tgz", ".bz2", ".xz",
    ".7z", ".rar", ".tar", ".jar", ".war", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".class", ".o", ".a", ".wasm", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".ogg", ".flac", ".sqlite", ".db", ".parquet", ".npy", ".npz", ".pkl",
    ".min.js", ".map", ".lockb",
}
SCRIPT_EXT = {
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js",
    ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".lua", ".go", ".rs", ".java",
    ".kt", ".swift", ".c", ".cc", ".cpp", ".cs", ".scala", ".exs", ".ex", ".r",
    ".applescript", ".vbs",
}
MARKDOWN_EXT = {".md", ".mdx", ".mdc", ".markdown", ".txt", ".rst", ".adoc"}
CONFIG_EXT = {".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}

RULES_FILENAMES = {
    "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", "codex.md",
    ".cursorrules", ".windsurfrules", ".clinerules", ".roomodes", ".goosehints",
    "copilot-instructions.md", "conventions.md", "llms.txt", "llms-full.txt",
    "instructions.md", "system.md", "prompt.md", "prompts.md",
}
RULES_DIR_PARTS = (
    "/.cursor/rules/", "/.clinerules/", "/.roo/rules", "/.github/instructions/",
    "/.windsurf/rules/", "/.claude/commands/", "/.claude/agents/", "/.codex/prompts/",
    "/.gemini/commands/", "/.continue/rules/", "/.kiro/steering/", "/.amazonq/rules/",
    "/.trae/rules/", "/commands/", "/agents/",
)
MCP_CONFIG_FILENAMES = {
    ".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json",
    "mcp-config.json", "mcp_servers.json", "mcp-servers.json", "opencode.json",
    "opencode.jsonc", ".claude.json",
}
SETTINGS_FILENAMES = {"settings.json", "settings.local.json", "hooks.json"}
SETTINGS_DIR_PARTS = ("/.claude/", "/.cursor/", "/.gemini/", "/hooks/", "/.claude-plugin/", "/.codex/", "/.kiro/", "/.windsurf/", "/.copilot/")
PLUGIN_FILENAMES = {"plugin.json", "marketplace.json"}


@dataclass
class ScanOptions:
    excludes: list[str] = field(default_factory=list)
    default_excludes: bool = True
    max_bytes: int = 2 * 1024 * 1024
    follow_symlinks: bool = False


def norm(path: str) -> str:
    return path.replace("\\", "/")


def classify(path: str, skill_dirs: set[str] | None = None) -> str:
    p = norm(path)
    name = os.path.basename(p)
    low = name.lower()
    ext = os.path.splitext(low)[1]
    parts = "/" + p.strip("/") + "/"

    in_skill = False
    if skill_dirs:
        d = os.path.dirname(p)
        while d:
            if d in skill_dirs:
                in_skill = True
                break
            nd = os.path.dirname(d)
            if nd == d:
                break
            d = nd
    if low == "skill.md":
        return KIND_SKILL
    if in_skill:
        if ext in MARKDOWN_EXT:
            return KIND_SKILL
        if ext in SCRIPT_EXT or ext == "":
            return KIND_SKILL_SCRIPT
        return KIND_SKILL
    if low in MCP_CONFIG_FILENAMES:
        return KIND_MCP_CONFIG
    if low == "config.toml" and "/.codex/" in parts:
        return KIND_MCP_CONFIG
    if low == "hooks.json":
        return KIND_SETTINGS
    if low in SETTINGS_FILENAMES and any(seg in parts for seg in SETTINGS_DIR_PARTS):
        return KIND_SETTINGS
    if low in PLUGIN_FILENAMES and "/.claude-plugin/" in parts:
        return KIND_PLUGIN
    if low in RULES_FILENAMES:
        return KIND_RULES
    if low.endswith((".instructions.md", ".prompt.md", ".agent.md", ".chatmode.md")):
        return KIND_RULES
    if ext in MARKDOWN_EXT and any(seg in parts for seg in RULES_DIR_PARTS):
        return KIND_RULES
    if ext in MARKDOWN_EXT:
        return KIND_MARKDOWN
    if ext in SCRIPT_EXT:
        return KIND_SCRIPT
    if ext in CONFIG_EXT or low.startswith(".env"):
        return KIND_CONFIG
    return KIND_TEXT


_JSONC_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def parse_structured(text: str, path: str) -> Any:
    """Best-effort parse for JSON / JSONC / TOML config files."""
    low = path.lower()
    body = text.lstrip("\ufeff")
    if low.endswith(".toml"):
        try:
            import tomllib  # py3.11+
            return tomllib.loads(body)
        except Exception:
            return None
    if low.endswith((".json", ".jsonc", ".json5")):
        try:
            return json.loads(body)
        except Exception:
            pass
        try:
            stripped = _TRAILING_COMMA.sub(r"\1", _JSONC_COMMENT.sub("", body))
            return json.loads(stripped)
        except Exception:
            return None
    return None


STRUCTURED_KINDS = {KIND_MCP_CONFIG, KIND_SETTINGS, KIND_PLUGIN, KIND_CONFIG}


def read_document(abspath: str, display: str, kind: str, max_bytes: int) -> Document | None:
    try:
        size = os.path.getsize(abspath)
        if size > max_bytes or size == 0:
            return None
        with open(abspath, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            try:
                text = raw.decode("utf-16")
            except UnicodeDecodeError:
                return None
        else:
            return None
    data = parse_structured(text, abspath) if kind in STRUCTURED_KINDS else None
    return Document(path=display, text=text, kind=kind, data=data, abspath=abspath)


def _excluded(rel: str, name: str, opts: ScanOptions) -> bool:
    for pat in opts.excludes:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def display_path(abspath: str) -> str:
    try:
        cwd = os.path.abspath(os.getcwd())
        if os.path.commonpath([cwd, abspath]) == cwd:
            return norm(os.path.relpath(abspath, cwd))
    except ValueError:
        pass
    return norm(abspath)


def iter_documents(roots: list[str], opts: ScanOptions) -> Iterator[Document]:
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            doc = read_document(root, display_path(root), classify(root, _skill_dirs_for_file(root)), opts.max_bytes)
            if doc:
                yield doc
            continue
        if not os.path.isdir(root):
            print(f"patdown: warning: {root} is not a file or directory", file=sys.stderr)
            continue
        skill_dirs = _find_skill_dirs(root, opts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
            rel_dir = norm(os.path.relpath(dirpath, root))
            if rel_dir == ".":
                rel_dir = ""
            dirnames[:] = sorted(
                d for d in dirnames
                if not (opts.default_excludes and _default_excluded_dir(d))
                and not _excluded(norm(os.path.join(rel_dir, d)), d, opts)
            )
            for fn in sorted(filenames):
                if fn in SKIP_FILENAMES:
                    continue
                low = fn.lower()
                if any(low.endswith(e) for e in BINARY_EXT):
                    continue
                abspath = os.path.join(dirpath, fn)
                rel = norm(os.path.join(rel_dir, fn))
                if _excluded(rel, fn, opts):
                    continue
                if not opts.follow_symlinks and os.path.islink(abspath):
                    continue
                kind = classify(norm(abspath), skill_dirs)
                doc = read_document(abspath, display_path(abspath), kind, opts.max_bytes)
                if doc:
                    yield doc


def _default_excluded_dir(name: str) -> bool:
    """Dependency, VCS and build-artifact directories skipped unless --no-default-excludes."""
    return name in DEFAULT_EXCLUDE_DIRS or name.endswith((".egg-info", ".dist-info"))


def _find_skill_dirs(root: str, opts: ScanOptions) -> set[str]:
    out: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
        dirnames[:] = [d for d in dirnames if not (opts.default_excludes and _default_excluded_dir(d))]
        if any(f.lower() == "skill.md" for f in filenames):
            out.add(norm(dirpath))
    return out


def _skill_dirs_for_file(abspath: str) -> set[str]:
    d = os.path.dirname(abspath)
    try:
        if any(f.lower() == "skill.md" for f in os.listdir(d)):
            return {norm(d)}
    except OSError:
        pass
    return set()


def home_targets() -> list[str]:
    """User-level locations where agents keep instructions, hooks and MCP configs."""
    home = os.path.expanduser("~")
    cands = [
        "~/.claude", "~/.claude.json", "~/.cursor", "~/.codex", "~/.gemini",
        "~/.windsurf", "~/.continue", "~/.kiro", "~/.config/opencode",
        "~/.config/Claude/claude_desktop_config.json",
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        "~/.config/github-copilot", "~/.copilot", "~/.aider.conf.yml", "~/.goosehints",
        "~/.config/goose",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        cands.append(os.path.join(appdata, "Claude", "claude_desktop_config.json"))
        cands.append(os.path.join(appdata, "Code", "User", "mcp.json"))
    cands.append(os.path.join(home, ".config", "Code", "User", "mcp.json"))
    cands.append(os.path.join(home, "Library", "Application Support", "Code", "User", "mcp.json"))
    out = []
    for c in cands:
        p = os.path.expanduser(c)
        if os.path.exists(p):
            out.append(p)
    return out
