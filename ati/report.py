"""Full triage report assembly: text rendering + JSON export."""
from __future__ import annotations

import hashlib
import os

from . import entropy as ent
from . import intel
from .carver import Embedded, detect_embedded
from .hexview import head_tail_dump
from .identify import FileFormat, identify_bytes
from .util import C, c, human_size


class Report:
    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.size = len(data)
        self.hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        self.format: FileFormat = identify_bytes(data)
        window = max(256, min(4096, max(self.size // 512, 256)))
        self.profile = ent.profile(data, window=window)
        self.overall_entropy = ent.summarize(data)
        self.regions = ent.suspicious_regions(self.profile)
        self.embedded: list[Embedded] = detect_embedded(data)
        self.findings = intel.scan_findings(data)
        self.finding_summary = intel.summarize_findings(self.findings)

    # -------------------------------------------------------------- text --
    def render(self, color: bool = True, graph_width: int = 72,
               graph_height: int = 10, max_strings: int = 0) -> str:
        from .entropy import graph
        lines: list[str] = []
        w = lambda s, col: lines.append(c(s, col) if color else s)

        w("=" * 78, C.CYAN)
        w(" ARTIFACT TRIAGE REPORT", C.BOLD)
        w("=" * 78, C.CYAN)

        w("--- identification ---", C.YELLOW)
        lines.append(f"  path       : {self.path}")
        lines.append(f"  size       : {self.size} ({human_size(self.size)})")
        for k in ("md5", "sha1", "sha256"):
            lines.append(f"  {k:<10} : {self.hashes[k]}")
        f = self.format
        col = C.GREEN if f.confidence == "high" else (
            C.YELLOW if f.confidence == "medium" else C.RED)
        lines.append("  format     : " + c(
            f"{f.name}  [category={f.category}, ext={f.ext or '-'}, "
            f"confidence={f.confidence}]", col) if color else
            f"  format     : {f.name}  [category={f.category}, ext={f.ext or '-'},"
            f" confidence={f.confidence}]")
        if f.details:
            w("  details:", C.GREY)
            for k, v in f.details.items():
                if k.startswith("_"):
                    continue
                lines.append(f"    {k:<24}: {_short(v)}")

        w("--- entropy ---", C.YELLOW)
        oe = self.overall_entropy
        lines.append(f"  overall {oe['entropy']:.3f} bits/byte -- {oe['verdict']}")
        lines.append(graph(self.profile, width=graph_width, height=graph_height))
        for r in self.regions:
            lines.append(f"  region 0x{r['start']:06x}-0x{r['end']:06x} "
                         f"(avg {r['avg']:.2f}): {r['label']}")

        w("--- embedded content ---", C.YELLOW)
        if not self.embedded:
            lines.append("  none detected")
        for e in self.embedded:
            flag = "*" if e.guessed else " "
            lines.append(
                f"  {flag}[0x{e.offset:08X}] {human_size(e.size):>9}  "
                f"{e.name:<22} {e.note}")

        w("--- string intelligence ---", C.YELLOW)
        fs = self.finding_summary
        sev = fs["by_severity"]
        lines.append(
            f"  total={fs['total']}  critical={sev.get('critical', 0)}  "
            f"high={sev.get('high', 0)}  medium={sev.get('medium', 0)}  "
            f"info={sev.get('info', 0)}  low={sev.get('low', 0)}")
        shown = [x for x in self.findings
                 if x.severity in ("critical", "high", "medium")]
        if not shown:
            shown = self.findings[:10]
        for fd in shown[:40]:
            scol = C.SEVERITY_COLOR.get(fd.severity, "")
            val = fd.value.replace("\n", " ")[:100]
            row = f"  [{fd.severity:<8}] 0x{fd.offset:06X} {fd.category:<20} {val}"
            lines.append(c(row, scol) if color else row)

        w("--- hex snapshot ---", C.YELLOW)
        lines.append(head_tail_dump(self.data[:4096] if self.size <= 4096
                                    else self.data, span=96, width=16))
        return "\n".join(lines)

    # -------------------------------------------------------------- json --
    def to_dict(self, max_findings: int = 500) -> dict:
        return {
            "path": os.path.abspath(self.path),
            "size": self.size,
            "hashes": self.hashes,
            "format": {
                "name": self.format.name,
                "category": self.format.category,
                "ext": self.format.ext,
                "confidence": self.format.confidence,
                "details": {k: v for k, v in self.format.details.items()
                            if not k.startswith("_")},
            },
            "entropy": {
                **self.overall_entropy,
                "regions": self.regions,
            },
            "embedded": [vars(e) for e in self.embedded],
            "findings": {
                **self.finding_summary,
                "items": [vars(x) for x in self.findings[:max_findings]],
            },
        }


def _short(v) -> str:
    import json
    try:
        s = v if isinstance(v, str) else json.dumps(v, default=str)
    except (TypeError, ValueError):
        s = str(v)
    s = s.replace("\n", " ")
    return s if len(s) <= 160 else s[:157] + "..."
