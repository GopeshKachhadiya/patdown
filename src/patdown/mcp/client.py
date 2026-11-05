"""A deliberately small MCP client: enough JSON-RPC to initialize a server and
list its tools, prompts and resources over stdio or streamable HTTP."""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from patdown import __version__

PROTOCOL_VERSION = "2025-06-18"


class McpError(Exception):
    pass


@dataclass
class ServerSpec:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    source: str = ""

    def describe(self) -> str:
        if self.url:
            return self.url
        return " ".join([self.command or "", *self.args]).strip()


@dataclass
class Inventory:
    name: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    instructions: str = ""
    error: str | None = None
    spec: ServerSpec | None = None


_ENV_REF = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%")


def expand_env(value: str, env: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1) or m.group(2) or m.group(3)
        return env.get(key, m.group(0))
    return _ENV_REF.sub(sub, value)


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "patdown", "version": __version__},
    }


class _Transport:
    def request(self, method: str, params: dict[str, Any] | None, timeout: float) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        pass


class StdioTransport(_Transport):
    def __init__(self, spec: ServerSpec, timeout: float) -> None:
        env = os.environ.copy()
        for k, v in spec.env.items():
            env[k] = expand_env(str(v), env)
        command = expand_env(spec.command or "", env)
        resolved = shutil.which(command) or command
        args = [expand_env(a, env) for a in spec.args]
        try:
            self.proc = subprocess.Popen(
                [resolved, *args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=spec.cwd or None, env=env, text=False,
            )
        except (OSError, ValueError) as exc:
            raise McpError(f"cannot start {command!r}: {exc}") from exc
        self._next_id = 1
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._stderr: list[bytes] = []
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line.decode("utf-8", "replace")))
            except json.JSONDecodeError:
                continue
        self._q.put(None)

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            if len(self._stderr) < 50:
                self._stderr.append(raw)

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise McpError(f"server closed stdin: {exc}; stderr: {self.stderr_tail()}") from exc

    def request(self, method: str, params: dict[str, Any] | None, timeout: float) -> dict[str, Any]:
        rid = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpError(f"timeout waiting for {method} response; stderr: {self.stderr_tail()}")
            try:
                msg = self._q.get(timeout=remaining)
            except queue.Empty:
                continue
            if msg is None:
                raise McpError(f"server exited before answering {method}; stderr: {self.stderr_tail()}")
            if msg.get("id") == rid:
                if "error" in msg:
                    raise McpError(f"{method} error: {msg['error']}")
                return msg.get("result") or {}
            # server-initiated requests (ping, sampling) get a benign reply
            if "method" in msg and "id" in msg:
                self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def stderr_tail(self) -> str:
        return b"".join(self._stderr[-5:]).decode("utf-8", "replace").strip()[:300]

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except OSError:
            pass


class HttpTransport(_Transport):
    """Streamable HTTP transport (POST JSON-RPC, JSON or SSE responses)."""

    def __init__(self, spec: ServerSpec, timeout: float) -> None:
        env = os.environ.copy()
        self.url = expand_env(spec.url or "", env)
        self.headers = {k: expand_env(str(v), env) for k, v in spec.headers.items()}
        self.session_id: str | None = None
        self._next_id = 1

    def _post(self, body: dict[str, Any], timeout: float) -> tuple[int, dict[str, str], bytes]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "User-Agent": f"patdown/{__version__}",
            **self.headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise McpError(f"HTTP transport error: {exc}") from exc

    def request(self, method: str, params: dict[str, Any] | None, timeout: float) -> dict[str, Any]:
        rid = self._next_id
        self._next_id += 1
        status, headers, raw = self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}, timeout)
        if status >= 400:
            raise McpError(f"{method} returned HTTP {status}: {raw[:200]!r}")
        if headers.get("mcp-session-id"):
            self.session_id = headers["mcp-session-id"]
        text = raw.decode("utf-8", "replace")
        messages: list[dict[str, Any]] = []
        if "text/event-stream" in headers.get("content-type", ""):
            for line in text.splitlines():
                if line.startswith("data:"):
                    try:
                        messages.append(json.loads(line[5:].strip()))
                    except json.JSONDecodeError:
                        pass
        else:
            try:
                parsed = json.loads(text) if text.strip() else {}
                messages = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError as exc:
                raise McpError(f"{method}: non-JSON response: {text[:200]!r}") from exc
        for msg in messages:
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    raise McpError(f"{method} error: {msg['error']}")
                return msg.get("result") or {}
        raise McpError(f"{method}: no response with id {rid}")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        try:
            self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, 10)
        except McpError:
            pass


def _list_all(t: _Transport, method: str, key: str, timeout: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):
        params: dict[str, Any] = {"cursor": cursor} if cursor else {}
        try:
            result = t.request(method, params, timeout)
        except McpError as exc:
            if items or "error" in str(exc).lower():
                break
            raise
        items.extend(x for x in result.get(key, []) if isinstance(x, dict))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return items


def fetch_inventory(spec: ServerSpec, timeout: float = 20.0) -> Inventory:
    inv = Inventory(name=spec.name, spec=spec)
    transport: _Transport | None = None
    try:
        if spec.url:
            transport = HttpTransport(spec, timeout)
        elif spec.command:
            transport = StdioTransport(spec, timeout)
        else:
            raise McpError("server has neither command nor url")
        init = transport.request("initialize", _initialize_params(), timeout)
        inv.server_info = init.get("serverInfo") or {}
        inv.instructions = str(init.get("instructions") or "")
        transport.notify("notifications/initialized")
        caps = init.get("capabilities") or {}
        inv.tools = _list_all(transport, "tools/list", "tools", timeout) if caps.get("tools") is not None or True else []
        if caps.get("prompts") is not None:
            try:
                inv.prompts = _list_all(transport, "prompts/list", "prompts", timeout)
            except McpError:
                pass
        if caps.get("resources") is not None:
            try:
                inv.resources = _list_all(transport, "resources/list", "resources", timeout)
            except McpError:
                pass
    except McpError as exc:
        inv.error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        inv.error = f"{exc.__class__.__name__}: {exc}"
    finally:
        if transport is not None:
            transport.close()
    return inv
