"""Interactive terminal triage UI (pure-ANSI, no third-party deps).

The rendering core is separated from raw key input so it can be unit-tested
headlessly; `read_key()` is only touched by run().
"""
from __future__ import annotations

import os
import shutil
import sys

from . import entropy as ent
from . import intel
from .carver import detect_embedded
from .hexview import hex_lines
from .identify import identify_bytes
from .util import C, c, enable_colors, fmt_off, human_size

VIEWS = ["Overview", "Entropy", "Hex", "Strings", "Findings", "Carve"]
VIEW_KEYS = {"1": 0, "2": 1, "3": 2, "4": 3, "5": 4, "6": 5}


# ---------------------------------------------------------------------------
# Key input (platform specific)
# ---------------------------------------------------------------------------

def read_key() -> str:
    """Blocking single-key read returning normalized names for special keys."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            k = msvcrt.getwch()
            return {"H": "up", "P": "down", "K": "left", "M": "right",
                    "G": "home", "O": "end", "I": "pgup", "Q": "pgdn",
                    "S": "del"}.get(k, k.lower())
        return {"\r": "enter", "\n": "enter", "\x1b": "esc",
                "\x08": "bs", "\t": "tab", " ": "space"}.get(ch, ch)
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            r, _, _ = select.select([sys.stdin], [], [], 0.05)
            if r:
                seq = sys.stdin.read(2)
                return {"[A": "up", "[B": "down", "[C": "right", "[D": "left",
                        "[H": "home", "[F": "end", "[5~": "pgup",
                        "[6~": "pgdn"}.get(seq, "esc")
            return "esc"
        return {"\r": "enter", "\n": "enter", "\x7f": "bs", "\t": "tab",
                " ": "space"}.get(ch, ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


class App:
    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.fmt = identify_bytes(data)
        window = max(256, min(4096, max(len(data) // 512, 256)))
        self.profile = ent.profile(data, window=window)
        self.regions = ent.suspicious_regions(self.profile)
        self.overall = ent.summarize(data)
        self.strings = intel.extract_strings(data, limit=5000)
        self.findings = intel.scan_findings(data, limit=3000)
        self.finding_summary = intel.summarize_findings(self.findings)
        archive_at_zero = self.fmt.category == "archive"
        self.embedded = detect_embedded(data, include_zero=archive_at_zero)

        self.view = 0
        self.scroll = {i: 0 for i in range(len(VIEWS))}
        self.hex_line = 0          # first visible hex row (16 bytes per row)
        self.sel = {i: 0 for i in range(len(VIEWS))}   # list cursors
        self.query = ""
        self.input_mode: str | None = None   # None | "search" | "goto"
        self.input_buf = ""
        self.status = "h=help  q=quit"
        self.help_open = False

    # ------------------------------------------------------------- helpers --
    @property
    def filtered_strings(self) -> list:
        if not self.query:
            return self.strings
        q = self.query.lower()
        return [s for s in self.strings if q in s.text.lower()]

    @property
    def filtered_findings(self) -> list:
        if not self.query:
            return self.findings
        q = self.query.lower()
        return [f for f in self.findings
                if q in f.value.lower() or q in f.category.lower()]

    def visible_rows(self, total_h: int) -> int:
        return max(total_h - 6, 4)  # header(3) + footer(2) + margin


    # ------------------------------------------------------------- views --
    def build_frame(self) -> str:
        cols, rows = shutil.get_terminal_size((110, 32))
        width = min(cols, 200)
        body_rows = rows - 4
        lines: list[str] = []

        head = f" ATI triage: {os.path.basename(self.path)} ({human_size(len(self.data))}) :: {self.fmt.name} "
        lines.append(c(head[:width].ljust(width), C.CYAN))
        tabs = "  ".join(
            (f"[{i + 1} {name}]"
             if i != self.view else c(f"[{i + 1} {name}]", C.BOLD + C.INVERT))
            for i, name in enumerate(VIEWS))
        lines.append(tabs[:width])

        body = self.build_body(self.view, width, body_rows)
        lines.extend(body)

        if self.input_mode:
            prompt = {"search": "search> ", "goto": "goto offset> "}[self.input_mode]
            footer = f" {prompt}{self.input_buf}_"
        else:
            footer = f" {self.status}"
        lines.append(c(footer[:width].ljust(width), C.GREY))
        # \x1b[K clears each row to EOL (prevents stale glyphs); \n advances
        return "\x1b[K\n".join(lines)

    def build_body(self, view: int, width: int, rows: int) -> list[str]:
        builder = {
            0: self.body_overview, 1: self.body_entropy, 2: self.body_hex,
            3: self.body_strings, 4: self.body_findings, 5: self.body_carve,
        }[view]
        return builder(width, rows)[:rows]

    def _kv(self, k: str, v: str, width: int) -> str:
        return f"  {k:<22}: {v}"[:width]

    def body_overview(self, width: int, rows: int) -> list[str]:
        out = [c(" == OVERVIEW ==", C.YELLOW)]
        f = self.fmt
        out.append(self._kv("format", f"{f.name} ({f.category})", width))
        out.append(self._kv("confidence", f.confidence, width))
        out.append(self._kv("suggested ext", f.ext or "-", width))
        out.append(self._kv("size", f"{len(self.data)} bytes", width))
        out.append("")
        out.append(c(" identification details", C.GREY))
        shown = 0
        for k, v in f.details.items():
            if k.startswith("_"):
                continue
            flat = str(v).replace("\n", " ")[: max(width - 30, 10)]
            out.append(self._kv(f"  {k}", flat, width))
            shown += 1
            if shown > rows:
                break
        out.append("")
        out.append(c(" quick stats", C.GREY))
        out.append(self._kv(
            "entropy",
            f"{self.overall['entropy']:.3f} -- {self.overall['verdict']}", width))
        out.append(self._kv("embedded objects", str(len(self.embedded)), width))
        fs = self.finding_summary
        out.append(self._kv(
            "findings",
            f"{fs['total']} total, critical={fs['by_severity'].get('critical', 0)}, "
            f"high={fs['by_severity'].get('high', 0)}", width))
        out.append(self._kv("strings extracted", str(len(self.strings)), width))
        return out

    def body_entropy(self, width: int, rows: int) -> list[str]:
        from .entropy import graph
        out = [c(" == ENTROPY PROFILE ==", C.YELLOW)]
        g_h = max(rows - len(self.regions) - 6, 5)
        out.extend(graph(self.profile, width=min(width - 10, 100),
                         height=g_h).splitlines())
        out.append("")
        out.append(self._kv(
            "overall",
            f"{self.overall['entropy']:.3f} bits/byte ({self.overall['verdict']})",
            width))
        for r in self.regions[:8]:
            out.append(f"  0x{r['start']:06x}-0x{r['end']:06x} avg={r['avg']:.2f} "
                       f"{r['label']}")
        return out

    def body_hex(self, width: int, rows: int) -> list[str]:
        highlights = [(e.offset, e.offset + e.size) for e in self.embedded]
        highlights += [(f.offset, f.offset + min(len(f.value), 64))
                       for f in self.findings if f.severity == "critical"]
        n_lines = max(rows - 3, 4)
        start_byte = self.hex_line * 16
        lines = hex_lines(self.data, offset=start_byte,
                          length=n_lines * 16, width=16,
                          highlights=highlights, color=True)
        out = [c(" == HEX VIEW (yellow=embedded objects) ==", C.YELLOW)]
        out.extend(lines[:n_lines])
        out.append(c(f" cursor at {fmt_off(start_byte)}   "
                     "(':' jump to offset; arrows/PgUp/PgDn scroll)", C.GREY))
        return out


    def body_strings(self, width: int, rows: int) -> list[str]:
        items = self.filtered_strings
        out = [c(f" == STRINGS ({len(items)} shown"
                 + (f", filter={self.query!r}" if self.query else "") + ") ==",
                 C.YELLOW)]
        n = max(rows - 2, 1)
        top = min(self.scroll[3], max(len(items) - 1, 0))
        for i in range(top, min(top + n, len(items))):
            s = items[i]
            mark = ">" if i == self.sel[3] else " "
            kind = "W" if s.kind == "utf16" else "A"
            row = f" {mark} {s.offset:08X} {kind} {s.text[:max(width - 18, 0)]}"
            out.append(c(row[:width], C.INVERT) if i == self.sel[3]
                       else row[:width])
        if not items:
            out.append("  (no strings match)")
        return out

    def body_findings(self, width: int, rows: int) -> list[str]:
        items = self.filtered_findings
        out = [c(f" == FINDINGS ({len(items)}"
                 + (f", filter={self.query!r}" if self.query else "") + ") ==",
                 C.YELLOW)]
        n = max(rows - 2, 1)
        top = min(self.scroll[4], max(len(items) - 1, 0))
        for i in range(top, min(top + n, len(items))):
            fd = items[i]
            mark = ">" if i == self.sel[4] else " "
            val = fd.value.replace("\n", " ")
            row = (f" {mark} [{fd.severity:<8}] {fd.offset:06X} "
                   f"{fd.category:<18} {val}")
            if i == self.sel[4]:
                out.append(c(row[:width], C.INVERT))
            else:
                out.append(c(row[:width],
                             C.SEVERITY_COLOR.get(fd.severity, ""))[:width])
        if not items:
            out.append("  (no findings match)")
        return out

    def body_carve(self, width: int, rows: int) -> list[str]:
        items = self.embedded
        out = [c(f" == EMBEDDED / CARVE ({len(items)}) -- x=export selected,"
                 " a=export all ==", C.YELLOW)]
        n = max(rows - 2, 1)
        top = min(self.scroll[5], max(len(items) - 1, 0))
        for i in range(top, min(top + n, len(items))):
            e = items[i]
            mark = ">" if i == self.sel[5] else " "
            flag = "*" if e.guessed else " "
            row = (f" {mark}{flag}[{e.offset:08X}] {human_size(e.size):>9} "
                   f"{e.name:<20} {e.note}")
            out.append(c(row[:width], C.INVERT) if i == self.sel[5]
                       else row[:width])
        if not items:
            out.append("  (nothing embedded detected)")
        return out


    # --------------------------------------------------------- interaction --
    def _list_len(self) -> int:
        return {
            3: len(self.filtered_strings),
            4: len(self.filtered_findings),
            5: len(self.embedded),
        }.get(self.view, 0)

    def _move(self, delta: int) -> None:
        n = self._list_len()
        if not n:
            return
        cur = self.sel[self.view]
        self.sel[self.view] = max(0, min(cur + delta, n - 1))
        rows = max(shutil.get_terminal_size((110, 32)).lines - 6, 4)
        sel_row = self.sel[self.view]
        top = self.scroll[self.view]
        if sel_row < top:
            self.scroll[self.view] = sel_row
        elif sel_row >= top + rows:
            self.scroll[self.view] = sel_row - rows + 1

    def _scroll(self, delta: int) -> None:
        if self.view == 2:  # hex
            total_lines = (len(self.data) + 15) // 16
            self.hex_line = max(0, min(self.hex_line + delta, max(total_lines - 1, 0)))
        else:
            self.scroll[self.view] = max(0, self.scroll[self.view] + delta)

    def _export_selected(self) -> None:
        if self.view != 5 or not self.embedded:
            self.status = "switch to Carve view [6] to export"
            return
        e = self.embedded[min(self.sel[5], len(self.embedded) - 1)]
        out_dir = self.path.rstrip("/") + "_exports"
        os.makedirs(out_dir, exist_ok=True)
        name = f"export_{e.offset:08X}_{e.name.replace(' ', '')}"
        path = os.path.join(out_dir, name + (f".{e.ext}" if e.ext else ".bin"))
        with open(path, "wb") as fh:
            fh.write(self.data[e.offset:e.offset + e.size])
        self.status = f"exported -> {path}"

    def _export_all(self) -> None:
        from .carver import carve_artifacts
        out_dir = self.path.rstrip("/") + "_exports"
        nodes = carve_artifacts(self.data, out_dir,
                                source_label=os.path.basename(self.path),
                                include_zero=bool(self.embedded))

        def count(ns):
            total = 0
            for nd in ns:
                if nd["path"]:
                    total += 1
                total += count(nd.get("children", []))
            return total
        total = count(nodes)
        self.status = f"exported {total} object(s) under {out_dir}"

    def _submit_input(self) -> None:
        mode, buf = self.input_mode, self.input_buf.strip()
        self.input_mode, self.input_buf = None, ""
        if mode == "search":
            self.query = buf
            self.sel[3] = self.sel[4] = 0
            self.scroll[3] = self.scroll[4] = 0
            self.status = (f"filter set to {buf!r}" if buf
                           else "filter cleared")
        elif mode == "goto":
            try:
                off = int(buf, 0)
                row = max(off // 16, 0)
                total = (len(self.data) + 15) // 16
                self.hex_line = min(row, max(total - 1, 0))
                self.view = 2
                self.status = f"hex view jumped to {fmt_off(self.hex_line * 16)}"
            except ValueError:
                self.status = f"bad offset: {buf!r}"

    def handle_key(self, key: str) -> bool:
        """Process one key; return False to exit."""
        if self.input_mode:
            if key == "esc":
                self.input_mode, self.input_buf = None, ""
                self.status = "input cancelled"
            elif key == "enter":
                self._submit_input()
            elif key == "bs":
                self.input_buf = self.input_buf[:-1]
            elif len(key) == 1 and key.isprintable():
                self.input_buf += key
            return True

        if key in ("q", "esc") and not self.help_open:
            return False
        if self.help_open:
            if key in ("h", "esc", "enter"):
                self.help_open = False
            return True

        if key in VIEW_KEYS:
            self.view = VIEW_KEYS[key]
            self.status = f"{VIEWS[self.view]} view"
        elif key == "tab":
            self.view = (self.view + 1) % len(VIEWS)
        elif key == "up":
            if self.view == 2:
                self._scroll(-1)
            else:
                self._move(-1)
        elif key == "down":
            if self.view == 2:
                self._scroll(1)
            else:
                self._move(1)
        elif key == "pgup":
            step = -(shutil.get_terminal_size((110, 32)).lines - 8)
            self._scroll(step if self.view == 2 else max(step, -self.scroll[self.view]))
            if self.view in (3, 4, 5):
                self._move(step // 2)
        elif key == "pgdn":
            step = shutil.get_terminal_size((110, 32)).lines - 8
            self._scroll(step)
            if self.view in (3, 4, 5):
                self._move(step // 2)
        elif key == "home":
            if self.view == 2:
                self.hex_line = 0
            else:
                self.scroll[self.view] = 0
                self.sel[self.view] = 0
        elif key == "end":
            if self.view == 2:
                self.hex_line = max((len(self.data) + 15) // 16 - 1, 0)
            else:
                n = self._list_len()
                self.sel[self.view] = max(n - 1, 0)
        elif key == "/":
            self.input_mode, self.input_buf = "search", ""
        elif key == ":":
            self.input_mode, self.input_buf = "goto", ""
        elif key == "n" and self.view == 4:
            items = self.filtered_findings
            if items:
                self._move(1)
                fd = items[min(self.sel[4], len(items) - 1)]
                row = fd.offset // 16
                self.hex_line, self.view = row, 2
                self.status = f"jumped to finding at {fmt_off(fd.offset)}"
        elif key == "x":
            self._export_selected()
        elif key == "a":
            self._export_all()
        elif key == "h" or key == "?":
            self.help_open = True
        return True


# ---------------------------------------------------------------------------
# Help / draw / run
# ---------------------------------------------------------------------------

HELP_LINES = [
    "ati interactive triage -- key reference",
    "",
    "  1..6 / Tab   switch view (Overview Entropy Hex Strings Findings Carve)",
    "  up/down      move cursor or scroll hex view",
    "  pgup/pgdn    page scroll        home/end   jump to start/end",
    "  /            filter strings & findings by substring",
    "  :            jump hex viewer to offset (accepts 0x... or decimal)",
    "  n            (Findings) jump to next finding location in Hex view",
    "  x            (Carve) export selected embedded object",
    "  a            (Carve) export all detected objects (+ recursion)",
    "  h / ?        toggle this help     q / esc   quit",
]


def _help_frame(app: App) -> str:
    cols, rows = shutil.get_terminal_size((110, 32))
    width = min(cols, 200)
    body = [c(l[:width], C.BOLD if i == 0 else "") for i, l in enumerate(HELP_LINES)]
    lines = [app.build_frame().split("\x1b[K")[0][:width]]
    lines.extend(body)
    lines.append(c(" press h/esc to close ".center(width, "-"), C.GREY))
    return "\x1b[K\n".join(lines)


def _draw(frame: str) -> None:
    sys.stdout.write("\x1b[H\x1b[2J" + frame)
    sys.stdout.flush()


def run(app: App) -> None:
    enable_colors(True)
    sys.stdout.write("\x1b[?1049h\x1b[?25l")
    try:
        while True:
            _draw(_help_frame(app) if app.help_open else app.build_frame())
            key = read_key()
            if not app.handle_key(key):
                break
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\x1b[m\x1b[?25h\x1b[?1049l")
        sys.stdout.flush()


def launch(path: str) -> int:
    with open(path, "rb") as fh:
        data = fh.read()
    app = App(os.path.abspath(path), data)
    run(app)
    return 0





