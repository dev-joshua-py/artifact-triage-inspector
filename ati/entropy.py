"""Shannon entropy analysis: point entropy, sliding-window profiles,
ASCII visualization, and suspicious-region detection."""
from __future__ import annotations

import math
from collections import Counter


def shannon(data: bytes | bytearray) -> float:
    """Shannon entropy in bits/byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = Counter(bytes(data))
    n = len(data)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / n
        ent -= p * math.log2(p)
    return ent


def profile(data: bytes, window: int = 1024, step: int | None = None) -> list[tuple[int, float]]:
    """Sliding-window entropy as [(offset, entropy), ...] covering the whole buffer."""
    if not data:
        return []
    if step is None or step <= 0:
        step = max(window // 4, 1)
    window = max(1, min(window, max(len(data), 1)))
    last_start = max(len(data) - window, 0)
    offs = list(range(0, last_start + 1, step))
    if not offs or offs[-1] != last_start:
        offs.append(last_start)
    return [(o, shannon(data[o:o + window])) for o in offs]


def verdict(ent: float) -> str:
    if ent < 0.25:
        return "near-zero -- padding / nulls / single repeated byte"
    if ent < 3.0:
        return "low -- structured or plain-text data"
    if ent < 6.0:
        return "moderate -- mixed content (text + binary)"
    if ent < 7.2:
        return "elevated -- compressed resources or dense binary"
    return "very high -- likely encrypted, compressed or packed"


def summarize(data: bytes, sample_limit: int = 1 << 20) -> dict:
    sample = data[:sample_limit]
    ent = shannon(sample)
    printable = sum(1 for b in sample if 32 <= b < 127) / max(len(sample), 1)
    return {
        "entropy": round(ent, 4),
        "verdict": verdict(ent),
        "printable_ratio": round(printable, 3),
        "sampled_bytes": len(sample),
    }


def graph(points: list[tuple[int, float]], width: int = 64, height: int = 10) -> str:
    """Render an entropy-vs-offset bar graph using ASCII only."""
    if not points:
        return "(no entropy data)"
    cols = max(1, min(width, len(points)))
    per = len(points) / cols
    colmax = []
    for i in range(cols):
        lo = int(i * per)
        hi = max(int((i + 1) * per), lo + 1)
        colmax.append(max(e for _, e in points[lo:hi]))
    rows = []
    for r in range(height):
        thr = 8.0 * (height - r) / height
        line = "".join("#" if cm >= thr - 1e-9 else " " for cm in colmax)
        rows.append(f"{thr:4.1f} |{line}|")
    rows.append("     +" + "-" * cols + "+")
    # Offset ruler aligned under the plot.
    marks = [" "] * cols
    ticks = min(8, cols)
    for i in range(ticks):
        idx = int(round(i * (cols - 1) / max(ticks - 1, 1)))
        label = f"{points[min(idx, len(points) - 1)][0]:x}"
        for j, ch in enumerate(label):
            if idx + j < cols:
                marks[idx + j] = ch
    rows.append("      " + "".join(marks))
    return "\n".join(rows)


def suspicious_regions(
    points: list[tuple[int, float]],
    high: float = 7.0,
    low: float = 0.25,
    min_points: int = 3,
) -> list[dict]:
    """Find contiguous runs of consistently high- or low-entropy windows."""
    regions: list[dict] = []
    cur: dict | None = None

    def close() -> None:
        nonlocal cur
        if cur and cur["n"] >= min_points:
            avg = cur["sum"] / cur["n"]
            label = (
                "high entropy (encrypted / compressed / packed?)"
                if cur["kind"] == "high"
                else "low entropy (padding / nulls)"
            )
            regions.append(
                {"start": cur["start"], "end": cur["last"], "avg": round(avg, 2), "label": label}
            )
        cur = None

    for off, ent in points:
        kind = "high" if ent >= high else ("low" if ent <= low else None)
        if kind and cur and cur["kind"] == kind:
            cur["last"] = off
            cur["sum"] += ent
            cur["n"] += 1
        elif kind:
            close()
            cur = {"kind": kind, "start": off, "last": off, "sum": ent, "n": 1}
        else:
            close()
    close()
    return regions
