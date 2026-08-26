"""Command-line interface for the artifact triage engine."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import entropy as ent
from . import intel
from .carver import carve_artifacts
from .hexview import hex_lines
from .identify import identify_bytes
from .report import Report
from .util import C, c, enable_colors, human_size

MAX_LOAD = 1 << 30  # 1 GiB hard cap
WARN_LOAD = 128 << 20

BANNER = r"""
   _   _ _____ _____   _____ ___ _   _ ___ ____  _____ ____
  /_\ | |_   _|_ _\ \ / /_ _/ __| | | |_ _|  _ \|_   _/ ___|
 / _ \| | | |  | | \ V / | |\__ \ |_| || || |_) | | |\___ \
/_/ \_\_| |_| |___| \_/  |___|___/\___/|___| .__/  |_| |___/
        universal artifact & binary triage        |_|
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ati",
        description="Universal CTF Artifact & Binary Triage Engine "
                    "(multi-format ID, carving, entropy, string intel, TUI).")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI colors")
    sub = p.add_subparsers(dest="command", metavar="command")

    def add(name, help_, desc=None):
        sp = sub.add_parser(name, help=help_, description=desc or help_)
        sp.add_argument("file", help="artifact to inspect")
        return sp

    add("info", "identify format + structural details + hashes")
    e = add("entropy", "Shannon entropy profile + graph + regions")
    e.add_argument("-w", "--window", type=int, default=1024,
                   help="sliding window size in bytes (default 1024)")
    e.add_argument("--width", type=int, default=72, help="graph width")
    e.add_argument("--height", type=int, default=14, help="graph height")
    s = add("strings", "extract strings (ASCII + UTF-16LE)")
    s.add_argument("-n", "--min-len", type=int, default=5)
    s.add_argument("--limit", type=int, default=5000)
    s.add_argument("-f", "--filter", default="", help="substring filter")
    s.add_argument("--no-wide", action="store_true", help="skip UTF-16 pass")
    f = add("find", "run pattern intel (flags, creds, IPs, URLs, keys...)")
    f.add_argument("--json", metavar="PATH", help="also write findings as JSON")
    f.add_argument("--min-severity", default="low",
                   choices=["critical", "high", "medium", "info", "low"])
    cv = add("carve", "extract embedded objects to disk (recursive)")
    cv.add_argument("-o", "--out", metavar="DIR",
                    help="output directory (default <file>_carved)")
    cv.add_argument("--depth", type=int, default=3,
                    help="max recursion depth into archives (default 3)")
    hx = add("hex", "static hex dump")
    hx.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    hx.add_argument("--length", type=lambda x: int(x, 0), default=512)
    hx.add_argument("--width", type=int, default=16)
    r = add("report", "full triage report (default command)")
    r.add_argument("--json", metavar="PATH", help="also write report JSON here")
    r.add_argument("--width", type=int, default=72)
    r.add_argument("--height", type=int, default=12)
    t = add("tui", "launch the interactive terminal UI")
    return p


def load(path: str) -> bytes:
    if not os.path.isfile(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        raise SystemExit(2)
    size = os.path.getsize(path)
    if size > MAX_LOAD:
        print(f"error: file too large ({human_size(size)}; cap {human_size(MAX_LOAD)})",
              file=sys.stderr)
        raise SystemExit(1)
    if size > WARN_LOAD:
        print(f"warning: {human_size(size)} file; analysis may be slow",
              file=sys.stderr)
    with open(path, "rb") as fh:
        return fh.read()


def cmd_info(args) -> int:
    data = load(args.file)
    fmt = identify_bytes(data)
    import hashlib
    print(f"file      : {args.file}")
    print(f"size      : {len(data)} ({human_size(len(data))})")
    print(f"md5       : {hashlib.md5(data).hexdigest()}")
    print(f"sha256    : {hashlib.sha256(data).hexdigest()}")
    col = {"high": C.GREEN, "medium": C.YELLOW}.get(fmt.confidence, C.RED)
    print(c(f"format    : {fmt.name}", col))
    print(f"category  : {fmt.category}    ext: {fmt.ext or '-'}    "
          f"confidence: {fmt.confidence}")
    if fmt.details:
        print("details:")
        for k, v in fmt.details.items():
            if k.startswith("_"):
                continue
            print(f"  {k:<24}: {v}")
    return 0


def cmd_entropy(args) -> int:
    data = load(args.file)
    pts = ent.profile(data, window=args.window)
    summary = ent.summarize(data)
    regions = ent.suspicious_regions(pts)
    print(c(f"entropy for {args.file} ({human_size(len(data))})", C.BOLD))
    print(f"window={args.window}B  overall={summary['entropy']:.3f} bits/byte  "
          f"-- {summary['verdict']}")
    print(ent.graph(pts, width=args.width, height=args.height))
    if regions:
        print("\nsuspicious regions:")
        for r in regions:
            print(f"  0x{r['start']:08X}-0x{r['end']:08X} avg={r['avg']:.2f}  "
                  f"{r['label']}")
    else:
        print("\nno suspicious uniform-entropy regions detected")
    return 0


def cmd_strings(args) -> int:
    data = load(args.file)
    hits = intel.extract_strings(data, min_len=args.min_len,
                                 wide=not args.no_wide, limit=args.limit)
    q = args.filter.lower()
    try:
        width = min(os.get_terminal_size().columns - 22
                    if sys.stdout.isatty() else 120, 160)
    except OSError:
        width = 120
    count = 0
    for h in hits:
        if q and q not in h.text.lower():
            continue
        kind = c("W", C.MAGENTA) if h.kind == "utf16" else "A"
        text = h.text[:width]
        print(f"{h.offset:08X} {kind} {text}")
        count += 1
    print(f"-- {count} string(s)"
          + (f" (filtered by {args.filter!r})" if q else ""))
    return 0


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}


def cmd_find(args) -> int:
    data = load(args.file)
    findings = intel.scan_findings(data, limit=5000)
    floor = _SEV_ORDER[args.min_severity]
    findings = [f for f in findings if _SEV_ORDER[f.severity] <= floor]
    print(c(f"pattern intelligence for {args.file}", C.BOLD))
    summary = intel.summarize_findings(findings)
    print(f"{summary['total']} finding(s)  by severity: "
          f"{summary['by_severity']}")

    for f in findings:
        col = C.SEVERITY_COLOR.get(f.severity, "")
        val = f.value.replace("\n", " ")[:120]
        line = (f"[{f.severity:<8}] 0x{f.offset:06X} {f.category:<20} {val}")
        print(c("  " + line, col))
        if len(val) < len(f.value) or f.context:
            pass
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"file": os.path.abspath(args.file),
                       "summary": summary,
                       "findings": [vars(f) for f in findings]},
                      fh, indent=2)
        print(f"JSON written -> {args.json}")
    return 0


def _print_tree(nodes, indent=0):
    for nd in nodes:
        e = nd["item"]
        err = f"  [{nd['error']}]" if nd.get("error") else ""
        member = f"  member={nd['member_name']}" if nd.get("member_name") else ""
        guess = "*" if getattr(e, "guessed", False) else " "
        name = getattr(e, "name", "member")
        off = getattr(e, "offset", 0)
        size = getattr(e, "size", len(open(nd["path"], "rb").read()))
        print(f"{'  ' * indent}{guess}[0x{off:08X}] {human_size(size):>9} "
              f"{name:<18} -> {os.path.basename(nd['path'])}{member}{err}")
        _print_tree(nd.get("children", []), indent + 1)


def cmd_carve(args) -> int:
    data = load(args.file)
    outdir = args.out or args.file.rstrip("/") + "_carved"
    print(c(f"carving {args.file} -> {outdir}", C.BOLD))
    fmt = identify_bytes(data)
    # If the file itself is an archive, carve it as an object at offset 0 too,
    # so members are extracted with full recursion.
    nodes = carve_artifacts(data, outdir,
                            source_label=os.path.basename(args.file),
                            max_depth=args.depth,
                            include_zero=(fmt.category == "archive"))
    if not nodes:
        print("  nothing embedded detected")
        return 0
    _print_tree(nodes)

    def count(ns):
        total = 0
        for nd in ns:
            if nd["path"]:
                total += 1
            total += count(nd.get("children", []))
        return total
    total = count(nodes)
    print(f"-- carved {total} object(s) into {outdir}")
    return 0


def cmd_hex(args) -> int:
    data = load(args.file)
    length = min(args.length, max(len(data) - args.offset, 0))
    for line in hex_lines(data, offset=args.offset, length=length,
                          width=args.width):
        print(line)
    return 0


def cmd_report(args) -> int:
    data = load(args.file)
    rep = Report(args.file, data)
    print(c(BANNER.rstrip("\n"), C.CYAN))
    print(rep.render(color=not args.no_color and sys.stdout.isatty(),
                     graph_width=args.width, graph_height=args.height))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep.to_dict(), fh, indent=2, default=str)
        print(f"\nJSON report written -> {args.json}")
    return 0


def cmd_tui(args) -> int:
    from .tui import launch
    return launch(args.file)


_HANDLERS = {
    "info": cmd_info,
    "entropy": cmd_entropy,
    "strings": cmd_strings,
    "find": cmd_find,
    "carve": cmd_carve,
    "hex": cmd_hex,
    "report": cmd_report,
    "tui": cmd_tui,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    known = set(_HANDLERS)
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return 0
    if argv[0] == "--no-color":
        argv.pop(0)
        enable_colors(False)
        if not argv:
            parser.print_help()
            return 0
    if argv[0] not in known:
        argv.insert(0, "report")   # default command
    args = parser.parse_args(argv)
    enable_colors(force=False if args.no_color else None)
    try:
        return _HANDLERS[args.command](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

