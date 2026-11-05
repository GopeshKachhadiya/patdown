# Changelog

All notable changes to patdown are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-05

Initial release.

### Added
- Static scanner for AI-agent config: skills (`SKILL.md`), rules files
  (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, …), slash commands, subagents,
  MCP config, hooks and settings, plugins.
- Unicode smuggling detection: invisible characters, bidi overrides, Unicode
  tag characters, variation-selector byte-encoding, private-use codepoints,
  homoglyphs and look-alike letters (PD001–PD007).
- Prompt-injection signatures: instruction override, role reassignment,
  concealment, fake authorization, tool-description poisoning (PD010–PD016).
- Data-flow rules: exfiltration URLs, pipe-to-shell, sensitive paths,
  destructive commands (PD020–PD023).
- Secret detection with redaction, and plaintext-credential-in-config checks
  (PD030–PD031).
- Encoded-payload decoding with nested re-scan, and hidden-content detection
  for HTML/markdown comments and CSS-hidden text (PD040, PD050–PD051).
- MCP config checks and hook/settings checks (PD060–PD065, PD070–PD073).
- Skill-level checks including symlink-escape and shipped-binary detection
  (PD080–PD083).
- Live MCP inspection over stdio and streamable HTTP, with a `patdown.lock`
  lockfile that detects tool-description "rug pulls", cross-server shadowing
  and name collisions (PD090–PD099).
- Terminal, JSON and SARIF 2.1.0 reporters.
- Baselines, per-line/per-file ignore markers, context-aware severity.
- `patdown`, `patdown mcp`, `patdown rules`, `patdown explain`,
  `patdown baseline`, `patdown strip` subcommands.
- GitHub Action, pre-commit hook, zero runtime dependencies.

[Unreleased]: https://github.com/GopeshKachhadiya/patdown/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GopeshKachhadiya/patdown/releases/tag/v0.1.0
