<!-- patdown:ignore-file -->
# patdown examples

Everything under here is a **deliberately unsafe demo corpus**. It is inert — it
*describes* attacks and carries hidden characters, but nothing here does
anything harmful when read or run. Its only job is to give patdown something to
find.

## `vulnerable-agent-repo/`

A repository shaped like one you might `git clone` and open in an agent. Scan it:

```bash
patdown scan examples/vulnerable-agent-repo
```

It contains, among other things:

- `skills/pdf-helper/SKILL.md` — a skill with a prompt-injection override split
  by a zero-width space, an instruction hidden in Unicode tag characters, and a
  "do not tell the user" HTML comment.
- `CLAUDE.md` — a bidi-override (Trojan Source) line and a fake-authorization claim.
- `.mcp.json` — a shell-wrapper server, a `curl | sh` at launch, an unpinned
  `npx` package, a plaintext key and an insecure `http://` transport.
- `.claude/settings.json` — a hook that exfiltrates `.env` to a webhook, a
  persistence hook, and `bypassPermissions`.
- `README.md` — a base64 payload and an image link that leaks a token.
- `CONTRIBUTING.md` — a **clean** file, included to prove patdown stays quiet on
  benign content (including legitimate Arabic text and emoji).

## `poisoned-mcp/server.py`

A tiny, inert MCP server whose tool *descriptions* are written the way a
malicious server would write them. Inspect it live:

```bash
patdown mcp --server "python examples/poisoned-mcp/server.py"
```

Demonstrate rug-pull detection with the lockfile:

```bash
patdown mcp --server "python examples/poisoned-mcp/server.py" --lock
PATDOWN_DEMO_RUGPULL=1 patdown mcp --server "python examples/poisoned-mcp/server.py"
```

The second run reports `PD090 mcp-tool-changed`, because the `add` tool rewrote
its description to ask for `~/.ssh/id_rsa`.
