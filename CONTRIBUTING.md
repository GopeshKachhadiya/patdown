<!-- patdown:ignore-file  (documents attack signatures as examples) -->
# Contributing to patdown

Thanks for helping make the agent ecosystem safer. The most valuable
contributions are **new detection signatures** and **false-positive fixes** —
both grow directly out of real-world attacks and real-world annoyance.

## Setup

```bash
git clone https://github.com/GopeshKachhadiya/patdown
cd patdown
pip install -e ".[dev]"
pytest
```

Regenerate the demo corpus (it carries real stealth characters, so it is
generated rather than hand-edited):

```bash
python tests/make_fixtures.py
```

## Adding a rule

1. Put it in the right module under `src/patdown/rules/`. A rule subclasses
   `Rule`, has a stable `id` (`PDxxx`), a `name`, a one-line `description`, a
   default `severity`, and optionally `kinds` and `kind_severity`.
2. Register it in `src/patdown/rules/__init__.py`. If it should also run over
   decoded/embedded content (base64, hidden comments, hook command strings),
   add its id to `NESTED_RULE_IDS`.
3. Document it in `docs/rules.md`.
4. **Write tests.** Every rule needs at least:
   - a test proving a true positive, and
   - a test proving a realistic benign input does **not** fire.
   False positives are the main reason people turn a scanner off, so the
   benign-case test matters as much as the detection test.
5. Keep `patdown scan src` clean. A signature module that necessarily contains
   its own patterns carries a `patdown:ignore-file` marker — follow the same
   convention if you add one.

## Principles

- **Context-aware severity.** The same pattern is dangerous in a hook and
  mundane in a README. Use `kind_severity` instead of one flat level.
- **Decode, then scan.** If you detect an encoding, decode it and re-scan the
  result via `ctx.scan_nested` rather than trying to match through the encoding.
- **Zero runtime dependencies.** The standard library only. This keeps patdown
  safe to run as the very first thing on an untrusted repo.
- **Redact secrets** in any snippet that reaches output.

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Please do not file public issues for a bypass
that would help an attacker before a fix ships.
