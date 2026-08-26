"""Embedded content detection, size measurement, extraction (carving)."""
from __future__ import annotations

import bz2
import io
import lzma
import os
import re
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field

from .identify import SIGNATURES, Signature, parse_pe, parse_elf, scan_signatures

try:  # Python 3.14+
    from compression.zstd import ZstdDecompressor
except Exception:  # pragma: no cover
    ZstdDecompressor = None


MEMBER_CAP = 64 << 20      # per-member decompression cap
MEMBER_COUNT_CAP = 512


@dataclass
class Embedded:
    offset: int
    size: int
    name: str
    category: str
    ext: str
    note: str = ""
    guessed: bool = False


SKIP_FOR_CARVE = {"ZIP empty", "MP3 ID3"}


def _valid_bmp(data: bytes, off: int) -> bool:
    if off + 6 > len(data):
        return False
    return struct.unpack_from("<I", data, off + 2)[0] in (12, 40, 52, 56, 64, 108, 124)


def _valid_ico(data: bytes, off: int) -> bool:
    if off + 7 > len(data):
        return False
    n = struct.unpack_from("<H", data, off + 4)[0]
    return 0 < n <= 32


PREDICATES = {"BMP": _valid_bmp, "ICO": _valid_ico}


# ---------------------------------------------------------------------------
# Per-format length measurement (returns byte count relative to offset)
# ---------------------------------------------------------------------------

def _m_zip(data: bytes, off: int):
    pos, tries = off, 0
    while tries < 1000:
        pos = data.find(b"PK\x05\x06", pos)
        if pos == -1:
            return None
        if pos + 22 <= len(data):
            csize, coff = struct.unpack_from("<II", data, pos + 12)
            clen = struct.unpack_from("<H", data, pos + 20)[0]
            # central directory should end exactly where EOCD begins
            if coff >= off and abs((coff + csize) - pos) <= 1024:
                end = pos + 22 + clen
                return min(end, len(data)) - off
        pos += 4
        tries += 1
    return None


def _m_stream(data: bytes, off: int, factory):
    chunk = data[off:off + MEMBER_CAP]
    if len(chunk) < 10:
        return None
    try:
        d = factory()
        d.decompress(chunk)
    except Exception:
        return None
    if getattr(d, "eof", False):
        used = len(chunk) - len(getattr(d, "unused_data", b""))
        return used if used > 0 else None
    return None


def _m_gzip(data, off):
    return _m_stream(data, off, lambda: zlib.decompressobj(31))


def _m_bz2(data, off):
    return _m_stream(data, off, bz2.BZ2Decompressor)


def _m_xz(data, off):
    return _m_stream(data, off, lzma.LZMADecompressor)


def _m_png(data: bytes, off: int):
    i = data.find(b"IEND", off)
    if i == -1:
        return None
    end = i + 8  # 'IEND' + CRC32
    return min(end, len(data)) - off


def _m_jpeg(data: bytes, off: int):
    i = data.find(b"\xff\xd9", off)
    if i == -1:
        return None
    return i + 2 - off


def _m_pdf(data: bytes, off: int):
    i = data.rfind(b"%%EOF", off)
    if i == -1:
        return None
    j = i + 5
    while j < len(data) and data[j:j + 2] in (b"\r\n", b"\n\r") or \
            (j < len(data) and data[j] in (10, 13)):
        j += 1
    return j - off


def _m_tar(data: bytes, off: int):
    pos = off
    zeros = 0
    for _ in range(4096):
        blk = data[pos:pos + 512]
        if len(blk) < 512:
            return None
        if blk.count(0) == 512:
            zeros += 1
            if zeros >= 2:
                return pos + 1024 - off
            pos += 512
            continue
        zeros = 0
        try:
            raw = blk[124:136].split(b"\x00")[0].strip() or b"0"
            size = int(raw, 8)
        except ValueError:
            return None
        if size < 0:
            return None
        pos += 512 + ((size + 511) // 512) * 512
    return None


def _m_riff(data: bytes, off: int):
    if off + 12 > len(data):
        return None
    size = struct.unpack_from("<I", data, off + 4)[0]
    end = off + size + 8
    if size < 4 or end > len(data) + 4096:
        return None
    return min(end, len(data)) - off


def _m_mp4(data: bytes, off: int):
    pos, boxes = off, 0
    while pos + 8 <= len(data) and boxes < 64:
        size = struct.unpack_from(">I", data, pos)[0]
        if size < 8:
            return (len(data) - off) if size == 0 else None
        pos += size
        boxes += 1
    return (pos - off) if boxes and pos <= len(data) else None


def _m_ico(data: bytes, off: int):
    try:
        n = struct.unpack_from("<H", data, off + 4)[0]
        total = 6 + 16 * n
        for i in range(n):
            e = off + 6 + 16 * i
            total += struct.unpack_from("<I", data, e + 8)[0] + 4
        return total if total <= len(data) - off + 64 else None
    except struct.error:
        return None


def _m_elf(data: bytes, off: int):
    info = parse_elf(data[off:off + 1024])
    return info.get("_extent")


def _m_pe(data: bytes, off: int):
    info = parse_pe(data[off:off + 4096])
    return info.get("_extent")


def _m_sqlite(data: bytes, off: int):
    if off + 32 > len(data):
        return None
    page = struct.unpack_from(">H", data, off + 16)[0]
    page = 65536 if page == 1 else page
    pages = struct.unpack_from(">I", data, off + 28)[0]
    size = page * pages
    return size if size <= len(data) - off else None


def _m_deb_ar(data: bytes, off: int):
    pos = off + 8
    for _ in range(2000):
        hdr = data[pos:pos + 60]
        if len(hdr) < 60 or hdr[58:60] != b"`\n":
            break
        try:
            size = int(hdr[48:58].strip() or b"0")
        except ValueError:
            break
        pos += 60 + size + (size & 1)
    return (pos - off) if pos > off + 8 else None


def _m_7z(data: bytes, off: int):
    if off + 32 > len(data):
        return None
    nho, nhs = struct.unpack_from("<QQ", data, off + 20)
    total = 32 + nho + nhs
    return total if total <= len(data) - off else None


def _parse_pcap_records(data: bytes, start: int, en: str):
    """Walk PCAP records from header at `start`; returns extent."""
    pos = start + 24
    count = 0
    while pos + 16 <= len(data) and count < 200_000:
        incl = struct.unpack_from(en + "I", data, pos + 8)[0]
        if incl > 0x400000:
            break
        pos += 16 + incl
        count += 1
    return pos


def _m_pcap(data: bytes, off: int):
    magic = data[off:off + 4]
    en = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<\x4d") else "<"
    return _parse_pcap_records(data, off, en) - off


MEASURE = {
    "ZIP": _m_zip,
    "GZIP": _m_gzip,
    "BZIP2": _m_bz2,
    "XZ": _m_xz,
    "PNG": _m_png,
    "JPEG": _m_jpeg,
    "PDF": _m_pdf,
    "TAR": _m_tar,
    "RIFF container": _m_riff,
    "MP4 box chain": _m_mp4,
    "ICO": _m_ico,
    "ELF": _m_elf,
    "PE/MZ": _m_pe,
    "SQLite 3": _m_sqlite,
    "DEB package": _m_deb_ar,
    "7-Zip": _m_7z,
    "PCAP BE": _m_pcap,
    "PCAP LE": _m_pcap,
}


# ---------------------------------------------------------------------------
# Embedded-object detection & carving
# ---------------------------------------------------------------------------

def detect_embedded(data: bytes, min_size: int = 32,
                    include_zero: bool = False) -> list[Embedded]:
    """Find embedded objects without writing anything to disk."""
    results: list[Embedded] = []
    last_end = 0
    for off, sig in scan_signatures(data):
        if sig.name in SKIP_FOR_CARVE or sig.name.startswith("PCAP ns"):
            continue
        pred = PREDICATES.get(sig.name)
        if pred and not pred(data, off):
            continue
        if off == 0 and not include_zero:
            continue
        if off < last_end:
            continue
        measurer = MEASURE.get(sig.name)
        size = measurer(data, off) if measurer else None
        guessed = size is None
        if guessed:
            size = len(data) - off
        if size < min_size:
            continue
        last_end = off + size
        note = ""
        if guessed:
            note = "size unknown; assumed to end at EOF"
        elif size < len(data) - off:
            note = f"{len(data) - off - size} trailing bytes after object"
        results.append(Embedded(off, size, sig.name, sig.category, sig.ext, note, guessed))
    return results


def _safe_member(name: str) -> str:
    name = name.replace("\\", "/").strip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    flat = "_".join(parts)[-120:] or "member"
    return re.sub(r"[^\w.\-()]", "_", flat)


class Budget:
    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self.used = 0

    def spend(self, n: int) -> bool:
        if self.used + n > self.max_bytes:
            return False
        self.used += n
        return True


def extract_archive(blob: bytes, fmt_name: str):
    """Extract members from an archive blob -> (members, note, error)."""
    members: list[tuple[str, bytes]] = []
    note, error = "", ""
    try:
        if fmt_name.startswith("ZIP"):
            zf = zipfile.ZipFile(io.BytesIO(blob))
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    note = "encrypted member(s) skipped"
                    continue
                if len(members) >= MEMBER_COUNT_CAP:
                    note = "member count cap reached"
                    break
                fh = zf.open(info)
                data = fh.read(MEMBER_CAP + 1)
                if len(data) > MEMBER_CAP:
                    note = "member size cap reached"
                    data = data[:MEMBER_CAP]
                members.append((info.filename, data))
        elif fmt_name == "TAR":
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:")
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                if len(members) >= MEMBER_COUNT_CAP:
                    note = "member count cap reached"
                    break
                src = tf.extractfile(m)
                if src is None:
                    continue
                data = src.read(MEMBER_CAP + 1)
                if len(data) > MEMBER_CAP:
                    note = "member size cap reached"
                    data = data[:MEMBER_CAP]
                members.append((m.name, data))
        else:
            factories = {
                "GZIP": lambda: zlib.decompressobj(31),
                "BZIP2": bz2.BZ2Decompressor,
                "XZ": lzma.LZMADecompressor,
            }
            fac = factories.get(fmt_name)
            if fac is None and fmt_name == "Zstandard" and ZstdDecompressor:
                dec = ZstdDecompressor()
                inner = dec.decompress(blob, max_output_size=MEMBER_CAP)
                return [(f"unpacked_{fmt_name.lower()}", inner)], note, error
            if fac:
                d = fac()
                inner = d.decompress(blob, MEMBER_CAP + 1)[:MEMBER_CAP]
                members.append((f"unpacked_{fmt_name.lower()}", inner))
            else:
                return [], "", f"no extractor for {fmt_name}"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return members, note, error


def carve_artifacts(data: bytes, outdir: str, source_label: str = "file",
                    depth: int = 0, max_depth: int = 3,
                    budget: Budget | None = None,
                    counter=None,
                    include_zero: bool | None = None) -> list[dict]:
    """Write every detected embedded object to `outdir`, recursing into archives.

    Returns a manifest tree of dicts:
      {item, path, children[], error}

    include_zero: also treat an object at offset 0 as carvable (used when the
    file itself is an archive). Defaults to True for depth > 0.
    """
    if budget is None:
        budget = Budget(256 << 20)
    if counter is None:
        import itertools
        counter = itertools.count(1)
    if include_zero is None:
        include_zero = depth > 0
    os.makedirs(outdir, exist_ok=True)
    nodes: list[dict] = []
    safe_label = re.sub(r"[^\w.-]", "_", os.path.basename(source_label))

    for emb in detect_embedded(data, include_zero=include_zero):
        seq = next(counter)
        base = f"{seq:03d}_off_{emb.offset:08X}_{safe_label}_{emb.name.replace(' ', '')}"
        fname = base + (f".{emb.ext}" if emb.ext else "")
        blob = data[emb.offset:emb.offset + emb.size]
        if not budget.spend(len(blob)):
            nodes.append({"item": emb, "path": "", "children": [],
                          "error": "byte budget exhausted; skipped"})
            continue
        path = os.path.join(outdir, fname)
        with open(path, "wb") as fh:
            fh.write(blob)
        node: dict = {"item": emb, "path": path, "children": [], "error": ""}

        if depth < max_depth and emb.category == "archive":
            members, note, err = extract_archive(blob, emb.name)
            if note:
                node["error"] = (node["error"] + "; " + note).strip("; ")
            if err:
                node["error"] = (node["error"] + "; " + err).strip("; ")
            if members:
                subdir = path + ".d"
                os.makedirs(subdir, exist_ok=True)
                for mname, mdata in members:
                    mpath = os.path.join(subdir, _safe_member(mname))
                    if not budget.spend(len(mdata)):
                        continue
                    with open(mpath, "wb") as fh:
                        fh.write(mdata)
                    child_nodes = carve_artifacts(
                        mdata, subdir, source_label=mname,
                        depth=depth + 1, max_depth=max_depth,
                        budget=budget, counter=counter)
                    pseudo_item = Embedded(0, len(mdata), "member", "", "", "")
                    node["children"].append({
                        "item": pseudo_item, "path": mpath,
                        "children": child_nodes, "error": "",
                        "member_name": mname,
                    })
        nodes.append(node)
    return nodes



