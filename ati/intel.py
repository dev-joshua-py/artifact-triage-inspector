"""String extraction (ASCII + UTF-16LE) and pattern-based intelligence."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass


@dataclass
class StringHit:
    offset: int
    kind: str   # "ascii" | "utf16"
    text: str


def extract_strings(data: bytes, min_len: int = 5, wide: bool = True,
                    limit: int = 50_000) -> list[StringHit]:
    """Extract printable runs with absolute byte offsets."""
    out: list[StringHit] = []
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % max(min_len, 1))
    for m in pat.finditer(data):
        out.append(StringHit(m.start(), "ascii", m.group().decode("ascii")))
        if len(out) >= limit:
            return out
    if wide:
        wpat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % max(min(min_len - 1, 4), 2))
        for m in wpat.finditer(data):
            txt = m.group().decode("utf-16-le", errors="replace")
            out.append(StringHit(m.start(), "utf16", txt))
            if len(out) >= limit:
                break
    return out


@dataclass
class Finding:
    offset: int
    category: str
    severity: str      # critical | high | medium | info | low
    value: str
    context: str = ""


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}


def _b64_validator(tok: str) -> bool:
    """Accept only Base64 that actually decodes to something meaningful."""
    try:
        pad = tok + "=" * ((4 - len(tok) % 4) % 4)
        raw = base64.b64decode(pad, validate=False)
    except (binascii.Error, ValueError):
        return False
    if len(raw) < 6:
        return False
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13)) / len(raw)
    magic_ok = raw[:2] in (
        b"PK", b"\x1f\x8b", b"\x89P", b"MZ", b"\x7fE", b"BZ", b"%P",
    )
    return printable >= 0.8 or magic_ok


def _jwt_validator(tok: str) -> bool:
    try:
        payload = tok.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        base64.urlsafe_b64decode(payload)
        return True
    except (binascii.Error, ValueError):
        return False


def P(cat: str, sev: str, pattern: str, flags: int = 0, validator=None) -> dict:
    return {"cat": cat, "sev": sev, "rx": re.compile(pattern, flags),
            "validator": validator}


PATTERNS: list[dict] = [
    P("ctf_flag", "critical",
      r"\b(?:flag|FLAG|CTF|ctf|picoCTF|HTB|htb|THM|thm|glacierctf|corCTF|UIUCTF"
      r"|CTFlearn)\{[^{}\n]{3,120}\}"),
    P("aws_access_key", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    P("private_key", "critical", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"),
    P("credential", "critical",
      r"(?i)\b(?:(?:user|root|db|admin|sudo|my|login|ftp|ssh|mysql)[_-])?"
      r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token"
      r"|auth[_-]?token|private[_-]?key)\b[\"'\s:=]{1,4}[^\s\"';&]{3,80}"),
    P("jwt", "high",
      r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*\b",
      validator=_jwt_validator),
    P("url", "high", r"https?://[^\s\"'<>()\[\]{}]{4,200}"),
    P("ipv4", "high",
      r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    P("authorization_header", "high",
      r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*[^\n\r]{4,140}"),
    P("base64", "medium", r"\b[A-Za-z0-9+/]{20,}={0,2}\b",
      validator=_b64_validator),
    P("hex_blob", "medium", r"\b(?:[0-9a-fA-F]{2}){20,}\b"),
    P("sql", "medium",
      r"(?is)\bselect\s+[\w*,\s]{1,60}?from\s+[\w.]+|insert\s+into\s+\w+"
      r"|update\s+\w+\s+set\s|delete\s+from\s+\w+"),
    P("powershell", "medium", r"(?i)\bpowershell(?:\.exe)?\b[^\n\r]{0,120}"),
    P("cmd_invoke", "medium", r"(?i)\bcmd(?:\.exe)?\s+/[cC]\b[^\n\r]{0,120}"),
    P("url_scheme", "medium", r"\b(?:ftp|sftp|ldap|ldaps|gopher|telnet|ws|wss):/{2}[^\s\"'<>]{3,150}"),
    P("ipv6", "medium", r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"),
    P("email", "info", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,12}\b"),
    P("domain", "low",
      r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
      r"(?:com|net|org|io|dev|edu|gov|mil|int|co|ai|app|xyz|info|biz|ru|cn|uk|de|fr"
      r"|nl|jp|kr|br|in|local|lan|test)\b"),
    P("uuid", "info",
      r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
      r"-[0-9a-fA-F]{12}\b"),
    P("mac_address", "info", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    P("unix_path", "info",
      r"\B/(?:usr|etc|var|opt|tmp|home|root|bin|sbin|srv|mnt|media)(?:/[\w.-]+)+\b"),
    P("windows_path", "info",
      r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]{1,100}"),
    P("user_agent", "info", r"(?i)\buser-agent:\s*[^\n\r]{5,90}"),
]

_GENERIC_FLAG = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_]{2,18}\{[^{}\n]{4,100}\}")


def scan_findings(data: bytes, limit: int = 5000) -> list[Finding]:
    """Run every pattern over the whole buffer (latin-1 view keeps byte offsets)."""
    text = data.decode("latin-1")
    found: list[Finding] = []
    per_cap = max(limit // max(len(PATTERNS), 1), 10)
    for spec in PATTERNS:
        count = 0
        for m in spec["rx"].finditer(text):
            val = m.group(0)
            if spec["validator"] and not spec["validator"](val):
                continue
            found.append(Finding(
                offset=m.start(),
                category=spec["cat"],
                severity=spec["sev"],
                value=val[:300],
                context=_line_context(text, m.start()),
            ))
            count += 1
            if count >= per_cap:
                break
    # generic flag-format heuristic (deduped against specific flag hits)
    specific_spans = [(f.offset, f.offset + len(f.value)) for f in found]
    for m in _GENERIC_FLAG.finditer(text):
        s, e = m.span()
        if any(s < pe and ps <= s for ps, pe in specific_spans):
            continue
        found.append(Finding(m.start(), "generic_flag_format", "low",
                             m.group(0)[:300], _line_context(text, m.start())))

    # prune same-offset duplicates keeping highest severity
    found.sort(key=lambda f: (f.offset, SEV_RANK[f.severity]))
    pruned: list[Finding] = []
    last_off = -1
    for f in found:
        if f.offset == last_off:
            continue
        pruned.append(f)
        last_off = f.offset
    return pruned[:limit]


def _line_context(text: str, off: int, span: int = 48) -> str:
    start = max(0, off - span)
    end = min(len(text), off + span)
    ctx = text[start:end].replace("\r", " ").replace("\n", " ")
    return ctx.strip()[:120]


def summarize_findings(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {"total": len(findings), "by_severity": counts, "by_category": by_cat}


