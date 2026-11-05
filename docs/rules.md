<!-- patdown:ignore-file  (this reference documents attack signatures as examples) -->
# patdown rules

Every rule has a stable id (`PDxxx`) that appears in findings, SARIF output and baselines. Suppress a rule on one line with a `patdown:ignore PDxxx` comment, or a whole file with `patdown:ignore-file` in its first 30 lines.

Severity is **context-aware**. The same pattern is scored differently depending on what the agent does with the file it is in. The kinds are:

| Kind | Examples | Treated as |
| --- | --- | --- |
| `skill` | `SKILL.md` and markdown in a skill dir | instructions |
| `rules` | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, commands, agents | instructions |
| `mcp-tool` | a live tool/prompt description from an MCP server | instructions |
| `mcp-config` | `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json` | execution config |
| `settings` | `.claude/settings.json`, `hooks.json` | execution config |
| `plugin` | `.claude-plugin/plugin.json`, `marketplace.json` | execution config |
| `skill-script` | scripts shipped inside a skill directory | executed code |
| `markdown` / `script` / `config` / `text` | everything else | docs / code |

---

## Unicode (PD001–PD007)

### PD001 invisible-unicode
Zero-width and other invisible characters (ZWSP, ZWNJ, ZWJ, word joiner, soft hyphen, BOM mid-file, …). These let an attacker split a keyword (`i<ZWSP>gnore`) so it dodges a human skim and naive filters but still reads as `ignore` to the model. A run of two distinct invisible symbols is tested as binary-encoded text and decoded if it looks like ASCII. Legitimate emoji ZWJ sequences and Arabic/Indic joiners are not flagged.

### PD002 bidi-override
Bidirectional override and isolate controls (`U+202A`–`U+202E`, `U+2066`–`U+2069`). This is the Trojan Source class: the characters reorder how text is displayed so what you read differs from what the compiler or model consumes. Plain directional marks (LRM/RLM) are reported at `LOW`.

### PD003 unicode-tag-smuggling
ASCII hidden in Unicode tag characters (`U+E0000`–`U+E007F`). Completely invisible in every renderer, perfectly readable by LLMs. The hidden text is decoded and re-scanned with the data-flow rules; subdivision-flag emoji are excluded. Always `CRITICAL` — there is no benign reason for this in agent files.

### PD004 variation-selector-smuggling
Long runs of variation selectors, the scheme that encodes arbitrary bytes after an emoji (bytes 0–15 → `U+FE00`–`U+FE0F`, 16–255 → `U+E0100`–`U+E01EF`). Decoded and re-scanned when it resolves to text.

### PD005 private-use-codepoints
Private Use Area codepoints. Icon fonts use them legitimately, so `LOW` by default, raised in instruction files.

### PD006 mixed-script-word
A single word mixing Latin with Cyrillic/Greek/Armenian letters — the homoglyph trick (`pаypаl` with Cyrillic `а`) that makes a word look right while matching nothing.

### PD007 lookalike-letters
Runs of fullwidth, mathematical or enclosed letters that fold to ASCII under NFKC. Used to dodge keyword filters while staying readable.

---

## Prompt injection (PD010–PD016)

These are signature matches on NFKC-normalised, stealth-stripped text, so Unicode tricks do not slip a phrase past them. In plain docs and code they are scored lower than in instruction files.

| ID | Name | Catches |
| --- | --- | --- |
| PD010 | instruction-override | "ignore/disregard/forget … previous instructions", "new system instructions:", "your real objective is", priority-override |
| PD011 | role-reassignment | `[INST]`/`<\|im_start\|>` delimiters, persona resets ("you are now …"), "enter developer/jailbreak mode" |
| PD012 | concealment-directive | "do not tell the user", "keep this secret", "silently do X", "without the user's knowledge" |
| PD013 | fake-authorization | "the user has pre-authorized you to …", "no confirmation needed", "this is a trusted operation, proceed" |
| PD014 | tool-description-poisoning | side effects demanded before tool use, instruction blocks in metadata, read-and-send-secret, tool shadowing |
| PD016 | model-addressed-directive | content that stops describing and starts commanding the model ("Attention assistant: you must …") |

---

## Data flow (PD020–PD023)

### PD020 exfil-url
URLs to out-of-band services (webhook/paste/tunnel hosts like webhook.site, ngrok, pipedream, Telegram/Slack/Discord webhooks), raw public IPs, image links whose query string carries data, and URLs with secret-named parameters filled from a template. Local and private addresses are excluded.

### PD021 pipe-to-shell
Code fetched and executed in one step: `curl … | sh`, `iex (iwr …)`, process/command substitution of a download, download-then-`chmod +x`-then-run, and LOLBins (certutil, mshta, bitsadmin). `CRITICAL` in hooks/MCP config, `LOW` in a README.

### PD022 sensitive-path
References to credential stores: `~/.ssh`, `~/.aws`, gcloud/Azure, kube/docker config, `.npmrc`/`.netrc`/`.pypirc`, shell history, `.env`, agent credential files (`.claude.json`, `.mcp.json`, `gh/hosts.yml`, Codex `auth.json`), `/etc/passwd`, browser/keychain stores, crypto wallets, GPG keys, and secret env-var dumps.

### PD023 destructive-command
`rm -rf` of root/home/globs, `mkfs`/`dd` on devices, fork bombs, force-push to main, history-destroying git, world-writable chmod on root/home, shutdown, crontab wipe, history tampering, adding SSH authorized keys, creating accounts.

---

## Secrets (PD030–PD031)

- **PD030 hardcoded-secret** — well-known token shapes (Anthropic, OpenAI, Stripe, GitHub, AWS, Slack, Google, npm, PyPI, HuggingFace, SendGrid, private-key blocks, JWTs, …) anywhere an agent can read. Snippets are redacted in all output.
- **PD031 secret-in-config** — a plaintext value under a key like `API_KEY`/`TOKEN`/`PASSWORD`/`SECRET` in an MCP or agent config file. Placeholders and `${ENV}` references are ignored.

## Encoded & hidden (PD040, PD050–PD051)

- **PD040 encoded-payload** — base64 / URL-safe base64 / hex / HTML-entity / percent / `\u`-escape blobs that decode to readable text. The decoded text is re-scanned; if it triggers another rule the finding is raised to `HIGH`.
- **PD050 hidden-content** — text present in the file but invisible when rendered: HTML comments, markdown comments, CSS-hidden spans (`display:none`, `font-size:0`, white/transparent text, off-screen positioning), `hidden`/`aria-hidden`. Benign tooling comments (prettier, eslint, TOC markers) are ignored.
- **PD051 link-text-mismatch** — a link whose visible text names one domain while the target is another.

## MCP config (PD060–PD065)

Static checks on MCP server entries: insecure `http://` transport (PD060), unpinned `npx`/`uvx` packages (PD061), dangerous flags like `--dangerously-skip-permissions` (PD062), shell wrappers that hide the real command (PD063), downloads at launch (PD064), and binaries run from temp/Downloads (PD065). Command lines are also re-scanned with the data-flow rules.

## Hooks & settings (PD070–PD073)

- **PD070 hook-network-call** — a hook command that talks to the network; raised when it also reads tool input or the transcript (the exfil pattern). Local-only calls are `LOW`.
- **PD071 hook-obfuscated-command** — base64-decode-and-run, `-EncodedCommand`, `eval`, `iex`, `FromBase64String`, gzip-pipe-to-shell.
- **PD072 permissive-settings** — `bypassPermissions`/`dontAsk` default mode, `Bash(*)` auto-approve, `dangerouslySkipPermissions`, `enableAllProjectMcpServers`, sandbox disabled.
- **PD073 hook-persistence** — a hook that writes to agent config, shell startup files, crontab/schtasks/launchd, or `core.hooksPath`.

## Skills (PD080–PD083)

- **PD080 skill-overbroad-trigger** — a description engineered to load on every request ("use this for all tasks, always, no matter what").
- **PD081 skill-wide-tools** — `allowed-tools: Bash(*)` / `*`.
- **PD082 skill-symlink-escape** — a symlink inside the skill pointing outside its directory.
- **PD083 skill-binary** — a compiled binary shipped in a skill that cannot be reviewed as text.

## Live MCP (PD090–PD099)

Produced by `patdown mcp` / `patdown --mcp`, which connect to servers and inspect their real tool sets.

- **PD090 mcp-*-changed** — a tool/prompt description or the server instructions changed since it was pinned in `patdown.lock` (rug pull). `HIGH`.
- **PD091 mcp-*-added** / **PD093 mcp-*-removed** — a tool/prompt appeared or disappeared since pinning.
- **PD092 mcp-server-not-pinned** — a server is live but absent from the lockfile.
- **PD094 mcp-cross-server-reference** — one server's tool description names another server's tools (shadowing / confused-deputy).
- **PD095 mcp-tool-name-collision** — the same tool name is offered by more than one server.
- **PD096 mcp-long-description** — an unusually long description, where instructions get buried.
- **PD099 mcp-unreachable** — informational; the server could not be inspected.
