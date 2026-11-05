from __future__ import annotations

import argparse
import os
import sys
import time

from patdown import __version__
from patdown.baseline import BASELINE_FILENAME, apply_baseline, load_baseline, write_baseline
from patdown.discover import ScanOptions, home_targets, iter_documents
from patdown.engine import Scanner, dedupe
from patdown.findings import Finding, Severity
from patdown.report import render_json, render_sarif, render_terminal
from patdown.report.terminal import want_color
from patdown.rules import ALL_RULES, rule_by_id
from patdown.rules.base import KIND_MCP_CONFIG
from patdown.textutil import is_stealth_char

SUBCOMMANDS = ("scan", "mcp", "rules", "explain", "baseline", "strip")
EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _add_output_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("--json", action="store_true", help="emit JSON instead of the terminal report")
    g.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    g.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    g.add_argument("--fail-on", default="high", metavar="LEVEL", help="exit 1 if any finding is at or above LEVEL (critical/high/medium/low/info/never). Default: high")
    g.add_argument("--min-severity", default="low", metavar="LEVEL", help="hide findings below LEVEL. Default: low")
    g.add_argument("--ignore", action="append", default=[], metavar="RULE", help="disable a rule id (repeatable, comma-separated ok)")
    g.add_argument("--only", action="append", default=[], metavar="RULE", help="run only these rule ids")
    g.add_argument("--baseline", metavar="FILE", help=f"suppress findings listed in FILE (default: {BASELINE_FILENAME} if present)")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    g.add_argument("--color", action="store_true", help="force ANSI colours")
    g.add_argument("-q", "--quiet", action="store_true", help="print nothing but the summary line")
    g.add_argument("-v", "--verbose", action="store_true", help="print progress to stderr")


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", help="files or directories to scan (default: current directory)")
    p.add_argument("--home", action="store_true", help="also scan your user-level agent config (~/.claude, ~/.cursor, ~/.codex, Claude Desktop, ...)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    p.add_argument("--no-default-excludes", action="store_true", help="also scan node_modules, .git, build dirs, ...")
    p.add_argument("--max-file-size", type=int, default=2 * 1024 * 1024, metavar="BYTES", help="skip files larger than this (default 2 MiB)")
    p.add_argument("--follow-symlinks", action="store_true", help="follow symbolic links while walking")
    p.add_argument("--mcp", action="store_true", help="also connect to every MCP server found in scanned config files and inspect its tools")
    p.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for an MCP server (with --mcp)")
    p.add_argument("--lockfile", metavar="FILE", help="MCP lockfile to compare against (default: patdown.lock in the current directory if present)")
    p.add_argument("--lock", action="store_true", help="write/update the MCP lockfile after scanning (with --mcp)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patdown",
        description="Frisk everything your AI agent reads: skills, rules files, hooks and MCP servers.",
        epilog="Run `patdown` with no arguments to scan the current directory. Exit code 1 means findings at or above --fail-on.",
    )
    parser.add_argument("--version", action="version", version=f"patdown {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan", help="scan files and directories (default command)")
    _add_scan_args(scan)
    _add_output_args(scan)

    mcp = sub.add_parser("mcp", help="connect to MCP servers and inspect their tools live")
    mcp.add_argument("configs", nargs="*", help="MCP config files (default: project configs in the current directory)")
    mcp.add_argument("--home", action="store_true", help="also use user-level MCP configs (Claude Desktop, Cursor, Codex, ...)")
    mcp.add_argument("--server", action="append", default=[], metavar="CMD", help="ad-hoc stdio server command line, e.g. --server \"npx -y some-mcp\" (repeatable)")
    mcp.add_argument("--url", action="append", default=[], metavar="URL", help="ad-hoc streamable-HTTP server URL (repeatable)")
    mcp.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for each server (default 20)")
    mcp.add_argument("--lockfile", metavar="FILE", default=None, help="lockfile path (default: patdown.lock)")
    mcp.add_argument("--lock", action="store_true", help="write/update the lockfile with the current tool set")
    mcp.add_argument("--no-lock", action="store_true", help="do not read any lockfile")
    _add_output_args(mcp)

    sub.add_parser("rules", help="list all rules")

    explain = sub.add_parser("explain", help="describe a rule")
    explain.add_argument("rule")

    base = sub.add_parser("baseline", help=f"write {BASELINE_FILENAME} accepting all current findings")
    _add_scan_args(base)
    base.add_argument("--baseline-out", default=BASELINE_FILENAME, metavar="FILE", help="where to write the baseline")
    base.add_argument("--ignore", action="append", default=[], metavar="RULE")
    base.add_argument("--only", action="append", default=[], metavar="RULE")
    base.add_argument("-v", "--verbose", action="store_true")

    strip = sub.add_parser("strip", help="remove invisible / bidi / tag characters from files")
    strip.add_argument("files", nargs="+")
    strip.add_argument("--write", action="store_true", help="modify files in place (default: report only)")
    return parser


def _split_ids(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def _severity(value: str) -> Severity | None:
    if value.lower() in ("never", "none", "off"):
        return None
    return Severity.parse(value)


def _emit(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        try:
            sys.stdout.write(text + "\n")
        except UnicodeEncodeError:
            sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))


def _finish(args: argparse.Namespace, findings: list[Finding], stats: dict[str, object]) -> int:
    min_sev = Severity.parse(args.min_severity)
    shown = [f for f in findings if f.severity >= min_sev]
    fail_on = _severity(args.fail_on)
    if args.sarif:
        _emit(render_sarif(shown, stats), args.output)
    elif args.json:
        _emit(render_json(shown, stats), args.output)
    else:
        color = want_color(True if args.color else (False if args.no_color or args.output else None))
        text = render_terminal([] if args.quiet else shown, stats, color, args.verbose)
        if args.quiet:
            text = text.splitlines()[-2] if shown else text
        _emit(text, args.output)
    if fail_on is not None and any(f.severity >= fail_on for f in shown):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def _scan_paths(args: argparse.Namespace, scanner: Scanner) -> tuple[list[Finding], int, list[str]]:
    roots = list(args.paths) or ["."]
    if args.home:
        roots.extend(home_targets())
    opts = ScanOptions(
        excludes=list(args.exclude), default_excludes=not args.no_default_excludes,
        max_bytes=args.max_file_size, follow_symlinks=args.follow_symlinks,
    )
    findings: list[Finding] = []
    files = 0
    mcp_configs: list[str] = []
    for doc in iter_documents(roots, opts):
        files += 1
        if args.verbose:
            print(f"  scanning {doc.path} [{doc.kind}]", file=sys.stderr)
        if doc.kind == KIND_MCP_CONFIG and doc.abspath:
            mcp_configs.append(doc.abspath)
        findings.extend(scanner.scan_document(doc))
    return findings, files, mcp_configs


def cmd_scan(args: argparse.Namespace) -> int:
    t0 = time.perf_counter()
    scanner = Scanner(ignore_rules=_split_ids(args.ignore), only_rules=_split_ids(args.only) or None)
    findings, files, mcp_configs = _scan_paths(args, scanner)
    stats: dict[str, object] = {"files": files}
    if args.mcp:
        from patdown.mcp.scan import run_mcp_scan, specs_from_file
        specs = [s for p in mcp_configs for s in specs_from_file(p)]
        lock_path = args.lockfile or ("patdown.lock" if os.path.isfile("patdown.lock") or args.lock else None)
        mcp_findings, inventories = run_mcp_scan(specs, scanner, args.timeout, lock_path, args.lock)
        findings.extend(mcp_findings)
        stats["servers"] = len(inventories)
    baseline_path = args.baseline or (BASELINE_FILENAME if os.path.isfile(BASELINE_FILENAME) else None)
    if baseline_path:
        findings, suppressed = apply_baseline(findings, load_baseline(baseline_path))
        stats["baselined"] = suppressed
    stats["seconds"] = round(time.perf_counter() - t0, 3)
    return _finish(args, dedupe(findings), stats)


def cmd_mcp(args: argparse.Namespace) -> int:
    from patdown.mcp.scan import discover_config_files, run_mcp_scan, spec_from_command, specs_from_file
    from patdown.mcp.client import ServerSpec

    t0 = time.perf_counter()
    scanner = Scanner(ignore_rules=_split_ids(args.ignore), only_rules=_split_ids(args.only) or None)
    configs = list(args.configs) or discover_config_files(args.home)
    specs = [s for p in configs for s in specs_from_file(p)]
    for i, cmd in enumerate(args.server, 1):
        specs.append(spec_from_command(cmd, i))
    for i, url in enumerate(args.url, 1):
        specs.append(ServerSpec(name=f"url{i}", url=url, source="--url"))
    if not specs:
        print("patdown: no MCP servers found. Pass a config file, --server \"cmd args\", --url, or --home.", file=sys.stderr)
        return EXIT_ERROR
    if args.verbose:
        for s in specs:
            print(f"  connecting to {s.name}: {s.describe()}", file=sys.stderr)
    lock_path = None if args.no_lock else (args.lockfile or "patdown.lock")
    if lock_path and not args.lock and not os.path.isfile(lock_path):
        lock_path = None
    findings, inventories = run_mcp_scan(specs, scanner, args.timeout, args.lockfile or "patdown.lock" if args.lock else lock_path, args.lock)
    stats: dict[str, object] = {
        "servers": len(inventories),
        "tools": sum(len(i.tools) for i in inventories),
        "seconds": round(time.perf_counter() - t0, 3),
    }
    if args.lock:
        print(f"patdown: lockfile written to {args.lockfile or 'patdown.lock'}", file=sys.stderr)
    baseline_path = args.baseline or (BASELINE_FILENAME if os.path.isfile(BASELINE_FILENAME) else None)
    if baseline_path:
        findings, suppressed = apply_baseline(findings, load_baseline(baseline_path))
        stats["baselined"] = suppressed
    return _finish(args, findings, stats)


def cmd_rules(args: argparse.Namespace) -> int:
    width = max(len(r.name) for r in ALL_RULES) + 2
    for r in ALL_RULES:
        print(f"{r.id}  {r.name.ljust(width)}{r.severity.name.ljust(9)} {r.description}")
    print("\nPD090-PD096  mcp-*  live MCP checks: lockfile drift, cross-server references, name collisions")
    return EXIT_CLEAN


def cmd_explain(args: argparse.Namespace) -> int:
    r = rule_by_id(args.rule)
    if r is None:
        print(f"patdown: unknown rule {args.rule!r}; run `patdown rules`", file=sys.stderr)
        return EXIT_ERROR
    kinds = "all file kinds" if r.kinds is None else ", ".join(sorted(r.kinds))
    print(f"{r.id} {r.name}\n  default severity: {r.severity.name}\n  applies to: {kinds}\n\n  {r.description}")
    if r.kind_severity:
        print("\n  severity by kind:")
        for k, s in sorted(r.kind_severity.items()):
            print(f"    {k.ljust(14)} {s.name}")
    print(f"\n  suppress on one line with a `patdown:ignore {r.id}` comment, or a whole file with `patdown:ignore-file`.")
    return EXIT_CLEAN


def cmd_baseline(args: argparse.Namespace) -> int:
    scanner = Scanner(ignore_rules=_split_ids(args.ignore), only_rules=_split_ids(args.only) or None)
    findings, files, _ = _scan_paths(args, scanner)
    write_baseline(args.baseline_out, findings)
    print(f"patdown: baseline with {len(findings)} finding(s) from {files} file(s) written to {args.baseline_out}")
    return EXIT_CLEAN


def cmd_strip(args: argparse.Namespace) -> int:
    total = 0
    for path in args.files:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"patdown: skipping {path}: {exc}", file=sys.stderr)
            continue
        cleaned = (text[0] if text and ord(text[0]) == 0xFEFF else "") + "".join(
            ch for i, ch in enumerate(text) if not (is_stealth_char(ord(ch)) and not (i == 0 and ord(ch) == 0xFEFF))
        )
        removed = len(text) - len(cleaned)
        total += removed
        if removed and args.write:
            with open(path, "wb") as fh:
                fh.write(cleaned.encode("utf-8"))
        print(f"{path}: {removed} stealth character(s) {'removed' if args.write else 'found'}")
    if total and not args.write:
        print("re-run with --write to remove them", file=sys.stderr)
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args)
        if args.cmd == "mcp":
            return cmd_mcp(args)
        if args.cmd == "rules":
            return cmd_rules(args)
        if args.cmd == "explain":
            return cmd_explain(args)
        if args.cmd == "baseline":
            return cmd_baseline(args)
        if args.cmd == "strip":
            return cmd_strip(args)
    except ValueError as exc:
        print(f"patdown: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("patdown: interrupted", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
