"""Shared helpers: ANSI coloring, human-readable sizes, offsets."""
from __future__ import annotations

import os
import sys


class C:
    """ANSI SGR codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    INVERT = "\033[7m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    SEVERITY_COLOR = {
        "critical": RED + BOLD,
        "high": MAGENTA,
        "medium": YELLOW,
        "info": CYAN,
        "low": GREY,
    }


_enabled: bool | None = None


def enable_colors(force: bool | None = None) -> None:
    """Enable/disable ANSI output. Auto-detects TTY + NO_COLOR when force is None."""
    global _enabled
    if force is not None:
        _enabled = force
    elif _enabled is None:
        _enabled = (
            sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )
    if os.name == "nt":
        # Enable VT processing on Windows 10+ consoles.
        os.system("")


def colors_on() -> bool:
    if _enabled is None:
        enable_colors()
    return bool(_enabled)


def c(text: object, color: str) -> str:
    """Wrap text in an ANSI color if colors are enabled."""
    s = str(text)
    if colors_on():
        return f"{color}{s}{C.RESET}"
    return s


def human_size(n: int | float) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{int(x)} B" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024.0
    return f"{x:.1f} TB"


def fmt_off(off: int) -> str:
    return f"0x{off:08X}"


def trunc(s: str, width: int) -> str:
    if width <= 0:
        return ""
    return s if len(s) <= width else s[: max(width - 1, 0)] + ">"
