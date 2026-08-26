"""Canonical hex dump renderer shared by the CLI and the TUI."""
from __future__ import annotations

from .util import C, c


def hex_lines(
    data: bytes,
    offset: int = 0,
    length: int | None = None,
    width: int = 16,
    highlights=(),
    color: bool = False,
) -> list[str]:
    """Return formatted hex dump lines for data[offset:offset+length].

    highlights: iterable of absolute (start, end) byte ranges to mark.
    """
    length = len(data) - offset if length is None else length
    length = max(0, min(length, len(data) - offset))
    width = max(4, width)

    hl_set: set[int] = set()
    if color:
        budget = 300_000
        for s, e in highlights:
            s = max(s, offset)
            e = min(e, offset + length)
            if e <= s:
                continue
            if e - s > budget:
                continue
            budget -= e - s
            hl_set.update(range(s, e))
            if budget <= 0:
                break

    lines = []
    pos = offset
    end = offset + length
    while pos < end:
        chunk = data[pos:min(pos + width, end)]
        hex_parts = []
        ascii_parts = []
        for i, b in enumerate(chunk):
            abs_off = pos + i
            tok = f"{b:02x}"
            asc = chr(b) if 32 <= b < 127 else "."
            if abs_off in hl_set and color:
                # explicit ANSI yellow -- independent of global color switch
                tok = f"\033[33m{tok}\033[0m"
                asc = f"\033[33m{asc}\033[0m"
            hex_parts.append(tok)
            ascii_parts.append(asc)
        left = " ".join(hex_parts[:width // 2])
        right = " ".join(hex_parts[width // 2:])
        left_padded = left + " " * ((width // 2) * 3 - _visible_len(left))
        right_padded = right + " " * (((width + 1) // 2) * 3 - _visible_len(right)) if right else ""
        lines.append(f"{pos:08x}  {left_padded}  {right_padded} |{''.join(ascii_parts)}|")
        pos += width
    if not lines:
        lines.append("(no data at this offset)")
    return lines


def _visible_len(s: str) -> int:
    """Length ignoring ANSI escapes (approximate: strip ESC sequences)."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033":
            j = s.find("m", i)
            i = j + 1 if j != -1 else len(s)
        else:
            out += 1
            i += 1
    return out


def head_tail_dump(data: bytes, span: int = 128, width: int = 16) -> str:
    """Hex snapshot of the first and last `span` bytes."""
    parts = ["--- head ---"]
    parts.extend(hex_lines(data, 0, min(span, len(data)), width))
    if len(data) > 2 * span:
        tail_off = len(data) - span
        parts.append(f"--- tail (0x{tail_off:x}) ---")
        parts.extend(hex_lines(data, tail_off, span, width))
    elif len(data) > span:
        pass
    return "\n".join(parts)
