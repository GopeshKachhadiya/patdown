# Security policy

## Scope

patdown is a defensive static scanner. It reads files and MCP tool metadata and
reports known-dangerous patterns. It does not execute the code it scans.

The one place patdown runs other software is `patdown mcp` / `patdown --mcp`,
which **starts the MCP servers you point it at** so it can list their tools,
exactly as your agent would. Only run it against servers you were already going
to connect to your agent, and prefer inspecting the config statically
(`patdown scan`) first.

## Reporting a vulnerability

If you find a way to make patdown miss a real attack (a signature bypass), or a
way to make patdown itself unsafe to run, please report it privately:

- Use GitHub's **Report a vulnerability** button under the Security tab, or
- open a draft security advisory.

Please avoid filing a public issue for a bypass until a fix is released, since
the details would help an attacker. Signature coverage gaps that are already
public (e.g. a technique described in a blog post) are fine to discuss openly.

## What is not a vulnerability

- A **false positive** — a benign file flagged. Please file a normal issue with
  the input; reducing these is a priority.
- A **false negative for a novel, cleanly-worded attack with no mechanical
  tell.** patdown is a signature scanner, not an LLM or a sandbox; it is the
  cheap first layer, not the whole defense. Keep your agent's permission
  prompts on.
