"""Multi-format identification: magic-byte table plus deep structural parsers."""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

from .entropy import shannon

HEAD = 0x8100  # identification window; covers ISO9660 PVD probe at 0x8001


@dataclass
class Signature:
    name: str
    category: str
    magic: bytes
    ext: str = ""
    offset: int = 0


@dataclass
class FileFormat:
    name: str
    category: str
    ext: str
    confidence: str
    details: dict = field(default_factory=dict)


SIGNATURES: list[Signature] = [
    # ---- archives / compressed ----
    Signature("ZIP", "archive", b"PK\x03\x04", "zip"),
    Signature("ZIP empty", "archive", b"PK\x05\x06", "zip"),
    Signature("RAR v4", "archive", b"Rar!\x1a\x07\x00", "rar"),
    Signature("RAR v5", "archive", b"Rar!\x1a\x07\x01\x00", "rar"),
    Signature("7-Zip", "archive", b"7z\xbc\xaf'\x1c", "7z"),
    Signature("GZIP", "archive", b"\x1f\x8b\x08", "gz"),
    Signature("BZIP2", "archive", b"BZh", "bz2"),
    Signature("XZ", "archive", b"\xfd7zXZ\x00", "xz"),
    Signature("Zstandard", "archive", b"(\xb5/\xfd", "zst"),
    Signature("LZ4 frame", "archive", b"\x04\"M\x18", "lz4"),
    Signature("CAB", "archive", b"MSCF", "cab"),
    Signature("TAR", "archive", b"ustar", "tar", offset=257),
    Signature("DEB package", "archive", b"!<arch>\ndebian-binary", "deb"),
    Signature("RPM package", "archive", b"\xed\xab\xee\xdb", "rpm"),
    # ---- executables ----
    Signature("ELF", "executable", b"\x7fELF", "elf"),
    Signature("PE/MZ", "executable", b"MZ", "exe"),
    Signature("Mach-O 32 BE", "executable", b"\xfe\xed\xfa\xce", "macho"),
    Signature("Mach-O 64 BE", "executable", b"\xfe\xed\xfa\xcf", "macho"),
    Signature("Mach-O 32 LE", "executable", b"\xce\xfa\xed\xfe", "macho"),
    Signature("Mach-O 64 LE", "executable", b"\xcf\xfa\xed\xfe", "macho"),
    Signature("Java class", "executable", b"\xca\xfe\xba\xbe", "class"),
    # ---- documents / databases ----
    Signature("PDF", "document", b"%PDF-", "pdf"),
    Signature("OLE compound", "document", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    Signature("RTF", "document", b"{\\rtf", "rtf"),
    Signature("SQLite 3", "database", b"SQLite format 3\x00", "sqlite"),
    # ---- images ----
    Signature("PNG", "image", b"\x89PNG\r\n\x1a\n", "png"),
    Signature("JPEG", "image", b"\xff\xd8\xff", "jpg"),
    Signature("GIF87a", "image", b"GIF87a", "gif"),
    Signature("GIF89a", "image", b"GIF89a", "gif"),
    Signature("BMP", "image", b"BM", "bmp"),
    Signature("TIFF II", "image", b"II*\x00", "tif"),
    Signature("TIFF MM", "image", b"MM\x00*", "tif"),
    Signature("ICO", "image", b"\x00\x00\x01\x00", "ico"),
    # ---- media ----
    Signature("RIFF container", "media", b"RIFF", "riff"),
    Signature("MP3 ID3", "media", b"ID3", "mp3"),
    Signature("FLAC", "media", b"fLaC", "flac"),
    Signature("Ogg", "media", b"OggS", "ogg"),
    Signature("WOFF", "media", b"wOFF", "woff"),
    Signature("WOFF2", "media", b"wOF2", "woff2"),
    Signature("WebM/MKV EBML", "media", b"\x1aE\xdf\xa3", "mkv"),
    # ---- network / disk ----
    Signature("PCAP BE", "network", b"\xa1\xb2\xc3\xd4", "pcap"),
    Signature("PCAP LE", "network", b"\xd4\xc3\xb2\xa1", "pcap"),
    Signature("PCAP ns BE", "network", b"\xa1\xb2<\x4d", "pcap"),
    Signature("PCAP ns LE", "network", b"\x4d<\xb2\xa1", "pcap"),
    Signature("PCAPNG", "network", b"\x0a\x0d\x0d\x0a", "pcapng"),
    Signature("ISO9660", "disk", b"CD001", "iso", offset=0x8001),
]


def match_signature(head: bytes) -> Signature | None:
    """Best magic match inside `head`; longer magics win."""
    cands = []
    for s in SIGNATURES:
        end = s.offset + len(s.magic)
        if len(head) >= end and head[s.offset:end] == s.magic:
            cands.append(s)
    if not cands:
        return None
    cands.sort(key=lambda s: len(s.magic), reverse=True)
    return cands[0]


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def identify_bytes(data: bytes) -> FileFormat:
    """Identify an in-memory buffer via signatures + deep structural parsing."""
    head = data[:HEAD]
    sig = match_signature(head)

    if sig is None:
        pr = printable_ratio(head[:8192])
        if pr > 0.87:
            return FileFormat("Plain text", "document", "txt", "medium",
                              {"printable_ratio": round(pr, 3)})
        ent = shannon(data[:65536])
        hint = ("high entropy suggests encryption/compression"
                if ent > 7.2 else "no known signature matched")
        return FileFormat("Unknown binary", "data", "bin", "low",
                          {"shannon_entropy": round(ent, 3), "hint": hint})

    name, cat, ext = sig.name, sig.category, sig.ext
    details: dict = {}

    if name.startswith("ZIP"):
        details = _safe(_parse_zip, data)
        fam = details.get("family")
        fmap = {
            "DOCX": ("Microsoft Word document (DOCX)", "docx"),
            "XLSX": ("Microsoft Excel workbook (XLSX)", "xlsx"),
            "PPTX": ("Microsoft PowerPoint deck (PPTX)", "pptx"),
            "OOXML": ("OOXML package", "zip"),
            "JAR": ("Java Archive (JAR)", "jar"),
            "APK": ("Android Package (APK)", "apk"),
            "EPUB": ("EPUB e-book", "epub"),
        }
        if fam in fmap:
            name, ext = fmap[fam]
        else:
            name = "ZIP archive"
    elif name.startswith("PCAP"):
        raw = _safe(_parse_pcap_or_ng, data)
        extent = raw.pop("_extent", None)
        details = {k: v for k, v in raw.items() if not k.startswith("_")}
        if extent:
            details["parsed_size"] = extent
        name = "PCAPNG capture" if sig.name == "PCAPNG" else "PCAP capture"
    elif name.startswith("Mach-O"):
        details = _safe(_parse_macho, data)
        name = f"Mach-O ({details.get('bits', '?')}-bit)"
    elif name == "RIFF container":
        details = _safe(_parse_riff, data)
        form = details.get("form", "")
        if form:
            name = f"RIFF/{form}"
            ext = {"WAVE": "wav", "AVI ": "avi", "WEBP": "webp"}.get(form, "riff")
    else:
        parser = PARSERS.get(name)
        if parser:
            details = _safe(parser, data)

    return FileFormat(name, cat, ext, "high", details)


def identify_file(path: str) -> tuple[bytes, FileFormat]:
    with open(path, "rb") as fh:
        data = fh.read()
    return data, identify_bytes(data)


def scan_signatures(data: bytes) -> list[tuple[int, Signature]]:
    """Every magic occurrence in `data` as [(base_offset, sig), ...]."""
    hits: list[tuple[int, Signature]] = []
    seen: set[tuple[int, str]] = set()
    for s in SIGNATURES:
        start = 0
        while True:
            pos = data.find(s.magic, start)
            if pos == -1:
                break
            base = pos - s.offset
            if base >= 0:
                key = (base, s.name)
                if key not in seen:
                    seen.add(key)
                    hits.append((base, s))
            start = pos + 1
    hits.sort(key=lambda h: (h[0], -len(h[1].magic)))
    return hits


def _safe(fn, data: bytes) -> dict:
    try:
        return fn(data) or {}
    except Exception as exc:  # parsers must never crash triage
        return {"error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Deep parsers
# ---------------------------------------------------------------------------

def _parse_zip(data: bytes) -> dict:
    out: dict = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        return {"error": f"not a readable zip: {exc}"}
    infos = zf.infolist()
    out["entries"] = len(infos)
    out["sample_names"] = [i.filename for i in infos[:12]]
    out["uncompressed_total"] = sum(i.file_size for i in infos)
    out["compressed_total"] = sum(i.compress_size for i in infos)
    enc = [i.filename for i in infos if i.flag_bits & 0x1]
    if enc:
        out["encrypted_count"] = len(enc)
        out["encrypted_entries"] = enc[:10]
    if zf.comment:
        out["zip_comment"] = zf.comment[:200].decode("utf-8", "replace")
    lower = [i.filename.lower() for i in infos]
    if any(n == "meta-inf/manifest.mf" for n in lower):
        out["family"] = "JAR"
    elif any(n == "androidmanifest.xml" for n in lower):
        out["family"] = "APK"
    elif "[content_types].xml" in lower:
        if any(n.startswith("word/") for n in lower):
            out["family"] = "DOCX"
        elif any(n.startswith("xl/") for n in lower):
            out["family"] = "XLSX"
        elif any(n.startswith("ppt/") for n in lower):
            out["family"] = "PPTX"
        else:
            out["family"] = "OOXML"
    elif "mimetype" in lower:
        try:
            mt = zf.read("mimetype")[:60].decode("ascii", "replace")
            if "epub" in mt:
                out["family"] = "EPUB"
                out["mimetype"] = mt
        except Exception:
            pass
    return out


def _parse_gzip(data: bytes) -> dict:
    out: dict = {}
    if len(data) < 10:
        return {"error": "truncated gzip header"}
    flg = data[3]
    off = 10
    try:
        if flg & 4:
            xlen = struct.unpack_from("<H", data, off)[0]
            off += 2 + xlen
        if flg & 8:
            end = data.index(b"\x00", off)
            out["original_name"] = data[off:end].decode("latin-1")
            off = end + 1
        if flg & 16:
            end = data.index(b"\x00", off)
            out["comment"] = data[off:end].decode("latin-1")
    except ValueError:
        pass
    d = zlib.decompressobj(31)
    try:
        # NOTE: feed the FULL buffer -- wbits=31 expects the gzip header too.
        inner = d.decompress(data, 32 << 20)
        out["inner_size_sampled"] = len(inner)
        out["trailing_bytes_after_member"] = len(d.unused_data)
        probe = inner if len(inner) <= (16 << 20) else inner[:HEAD]
        fmt = identify_bytes(probe[:HEAD])
        if fmt.confidence == "high":
            out["inner_format"] = fmt.name
        elif fmt.category == "document" and fmt.name == "Plain text":
            out["inner_format"] = "text"
    except Exception as exc:
        out["decompress_error"] = str(exc)
    return out


def _parse_tar(data: bytes) -> dict:
    import tarfile
    out: dict = {}
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    members = tf.getmembers()
    out["entries"] = len(members)
    out["members"] = [
        {"name": m.name, "size": m.size,
         "type": "dir" if m.isdir() else ("link" if m.issym() or m.islnk() else "file")}
        for m in members[:50]
    ]
    return out


def _parse_png(data: bytes) -> dict:
    out: dict = {}
    meta: dict = {}
    chunks: dict[str, int] = {}
    pos = 8
    while pos + 8 <= len(data):
        ln = struct.unpack_from(">I", data, pos)[0]
        typ_b = data[pos + 4:pos + 8]
        typ = typ_b.decode("latin-1")
        if not all(65 <= c <= 122 for c in typ_b):
            out["warning"] = f"corrupt chunk name at 0x{pos:x}; data may follow PNG"
            break
        chunks[typ] = chunks.get(typ, 0) + 1
        body = data[pos + 8:pos + 8 + ln]
        if typ == "IHDR" and len(body) >= 13:
            w, h, bd, ct, _cm, _fm, il = struct.unpack(">IIBBBBB", body)
            ct_names = {0: "grayscale", 2: "RGB", 3: "palette",
                        4: "gray+alpha", 6: "RGBA"}
            out.update(width=w, height=h, bit_depth=bd,
                       color_type=ct_names.get(ct, ct), interlace=il)
        elif typ == "tEXt":
            k, _, v = body.partition(b"\x00")
            meta.setdefault(k.decode("latin-1"), v.decode("latin-1"))
        elif typ == "zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                val = zlib.decompress(rest[1:]) if rest else b""
                meta.setdefault(k.decode("latin-1"), val.decode("utf-8", "replace"))
            except zlib.error:
                pass
        elif typ == "iTXt" and len(body.split(b"\x00", 1)) == 2:
            k, rest = body.split(b"\x00", 1)
            if len(rest) >= 2:
                comp = rest[0]
                rest3 = rest[2:]
                _lang, _, r4 = rest3.partition(b"\x00")
                _kw, _, txt = r4.partition(b"\x00")
                try:
                    val = zlib.decompress(txt) if comp == 1 else txt
                    meta.setdefault(k.decode("latin-1"), val.decode("utf-8", "replace"))
                except zlib.error:
                    pass
        pos += 12 + ln
        if typ == "IEND" or ln > len(data):
            break
    if chunks:
        out["chunks"] = chunks
    if meta:
        out["text_metadata"] = meta
    return out


def _parse_jpeg(data: bytes) -> dict:
    out: dict = {}
    segs: list = []
    comments: list = []
    exif: dict | None = None
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:  # start of scan; compressed data follows
            segs.append("SOS")
            break
        ln = struct.unpack_from(">H", data, pos + 2)[0]
        body = data[pos + 4:pos + 4 + max(ln - 2, 0)]
        nm = {0xE0: "APP0(JFIF)", 0xE1: "APP1(Exif/XMP)", 0xE2: "APP2(ICC)",
              0xED: "APP13(Photoshop/IPTC)", 0xEE: "APP14(Adobe)",
              0xFE: "COM"}.get(marker, f"M{marker:02X}")
        segs.append(nm)
        if marker == 0xFE:
            comments.append(body[:200].decode("latin-1"))
        if marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            exif = parse_exif(body[6:])
        pos += 2 + ln
    out["segments"] = segs[:24]
    if comments:
        out["jpeg_comments"] = comments
    if exif:
        out.update(exif)
    return out


_EXIF_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
              0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright"}
_EXIF_SUB = {0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
             0x829A: "ExposureTime", 0x8827: "ISO",
             0xA002: "ImageWidth", 0xA003: "ImageHeight",
             0x9286: "UserComment"}
_GPS_TAGS = {0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
             0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude"}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def parse_exif(tiff: bytes) -> dict:
    """Minimal TIFF/EXIF reader: IFD0 + Exif sub-IFD + GPS IFD."""
    out: dict = {}
    if len(tiff) < 8:
        return out
    bo = "<" if tiff[:2] == b"II" else ">"

    def read_ifd(off):
        vals: dict[int, tuple] = {}
        try:
            if off + 2 > len(tiff):
                return vals
            n = struct.unpack_from(bo + "H", tiff, off)[0]
            for i in range(min(n, 512)):
                e = off + 2 + i * 12
                if e + 12 > len(tiff):
                    break
                tg, ty, cnt = struct.unpack_from(bo + "HHI", tiff, e)
                sz = _TYPE_SIZE.get(ty, 1) * cnt
                if sz <= 4:
                    raw = tiff[e + 8:e + 8 + sz]
                else:
                    vo = struct.unpack_from(bo + "I", tiff, e + 8)[0]
                    raw = tiff[vo:vo + sz]
                vals[tg] = (ty, cnt, raw)
        except struct.error:
            pass
        return vals

    def resolve(v):
        ty, cnt, raw = v
        try:
            if ty == 2:
                return raw.split(b"\x00")[0].decode("utf-8", "replace")
            if ty == 3:
                xs = struct.unpack(bo + f"{cnt}H", raw[:2 * cnt])
                return xs[0] if cnt == 1 else list(xs)
            if ty == 4:
                xs = struct.unpack(bo + f"{cnt}I", raw[:4 * cnt])
                return xs[0] if cnt == 1 else list(xs)
            if ty in (5, 10):
                fr = struct.unpack(bo + f"{2 * cnt}I", raw[:8 * cnt])
                rat = [fr[i] / fr[i + 1] if fr[i + 1] else 0.0
                       for i in range(0, len(fr), 2)]
                return rat[0] if len(rat) == 1 else rat
            return raw[:64].hex()
        except struct.error:
            return "<unreadable>"

    try:
        ifd0 = read_ifd(struct.unpack(bo + "I", tiff[4:8])[0])
    except struct.error:
        return out
    for tg, v in ifd0.items():
        if tg in (0x8769, 0x8825):
            continue
        out[_EXIF_TAGS.get(tg, f"Tag_0x{tg:04X}")] = resolve(v)

    def sub_off(tag):
        v = ifd0.get(tag)
        if not v:
            return None
        try:
            return struct.unpack(bo + "I", v[2][:4])[0]
        except struct.error:
            return None

    xo = sub_off(0x8769)
    if xo is not None:
        for tg, v in read_ifd(xo).items():
            out[_EXIF_SUB.get(tg, f"Exif_0x{tg:04X}")] = resolve(v)
    go = sub_off(0x8825)
    if go is not None:
        gps = {_GPS_TAGS.get(tg, f"GPS_0x{tg:04X}"): resolve(v)
               for tg, v in read_ifd(go).items()}

        def dms(x):
            try:
                return float(x[0]) + float(x[1]) / 60 + float(x[2]) / 3600
            except (TypeError, IndexError, ValueError):
                return None

        lat = dms(gps.get("GPSLatitude") or [])
        lon = dms(gps.get("GPSLongitude") or [])
        if lat is not None and lon is not None:
            if gps.get("GPSLatitudeRef") == "S":
                lat = -lat
            if gps.get("GPSLongitudeRef") == "W":
                lon = -lon
            out["GPS"] = f"{lat:.6f},{lon:.6f}"
    return out


# ---------------------------------------------------------------------------
# Binary executable / network / misc parsers
# ---------------------------------------------------------------------------

_ELF_MACHINES = {0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
                 0x28: "ARM", 0x32: "IA-64", 0x3E: "x86-64",
                 0xB7: "AArch64", 0xF3: "RISC-V"}
_ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN (shared obj)", 4: "CORE"}


def parse_elf(data: bytes) -> dict:
    out: dict = {}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"error": "bad ELF header"}
    cls, en = data[4], ("<" if data[5] == 1 else ">")
    out["bits"] = 64 if cls == 2 else 32
    out["endian"] = "LE" if data[5] == 1 else "BE"
    if cls == 2:
        f = en + "HHIQQQIHHHHHH"
    else:
        f = en + "HHIIIIIHHHHHH"
    (t, m, _v, entry, phoff, shoff, _fl,
     _eh, phes, phn, shes, shn, _sx) = struct.unpack_from(f, data, 16)
    out["type"] = _ELF_TYPES.get(t, str(t))
    out["machine"] = _ELF_MACHINES.get(m, hex(m))
    out["entry_point"] = entry
    out["program_headers"] = phn
    out["sections"] = shn if shn != 0 else "none (stripped?)"
    extent = shoff + shes * shn if (shn and shes) else phoff + phes * phn
    out["_extent"] = min(extent, len(data)) if extent and extent <= len(data) else None
    return out


def parse_pe(data: bytes) -> dict:
    import datetime as _dt
    out: dict = {}
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return {"error": "bad MZ header"}
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if e + 24 > len(data) or data[e:e + 4] != b"PE\x00\x00":
            return {"error": "PE signature not found"}
        mach, nsec, ts, _p, _n, opt, _ch = struct.unpack_from("<HHIIIHH", data, e + 4)
        out["machine"] = {0x14C: "i386", 0x8664: "x86-64",
                          0xAA64: "ARM64", 0x1C0: "ARM"}.get(mach, hex(mach))
        out["compiled_utc"] = _dt.datetime.fromtimestamp(
            ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "n/a"
        optmagic = struct.unpack_from("<H", data, e + 24)[0]
        out["format"] = "PE32+" if optmagic == 0x20B else "PE32"
        sub = struct.unpack_from("<H", data, e + 24 + 68)[0]
        out["subsystem"] = {1: "Native", 2: "GUI", 3: "Console",
                            9: "WinCE", 14: "EFI"}.get(sub, str(sub))
        secoff = e + 24 + opt
        names: list = []
        ext = 0
        for i in range(min(nsec, 96)):
            so = secoff + i * 40
            if so + 40 > len(data):
                break
            nm = data[so:so + 8].rstrip(b"\x00").decode("latin-1")
            _vsz, _va, rsz, rp = struct.unpack_from("<IIII", data, so + 8)
            names.append(nm)
            ext = max(ext, rp + rsz)
        out["section_names"] = names
        out["_extent"] = min(ext, len(data)) if ext else None
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


_LINK_TYPES = {0: "NULL (BSD loopback)", 1: "Ethernet", 6: "Token Ring",
               101: "SLIP", 104: "CHDLC", 105: "PPP", 113: "Linux SLL",
               127: "Radiotap", 228: "IPv4", 229: "IPv6"}


def _parse_pcap_or_ng(data: bytes) -> dict:
    out: dict = {}
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":  # pcapng section header block
        out["format_note"] = "pcapng Section Header Block"
        pos = struct.unpack_from("<I", data, 0)[0]  # LE guess; walk blocks
        en = "<"
        blocks = 0
        while pos + 8 <= len(data) and blocks < 100_000:
            blen = struct.unpack_from(en + "I", data, pos)[0]
            if blen < 12 or pos + blen > len(data):
                break
            pos += blen
            blocks += 1
        out["_extent"] = pos
        out["blocks_walked"] = blocks
        return out
    en = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<\x4d") else "<"
    vmaj, vmin, _tz, _sf, snap, link = struct.unpack_from(en + "HHiIII", data, 4)
    out.update(version=f"{vmaj}.{vmin}", snaplen=snap,
               linktype=_LINK_TYPES.get(link, str(link)))
    from .carver import _parse_pcap_records  # local import avoids load cycle
    end = _parse_pcap_records(data, 0, en)
    # count packets during the same style of walk:
    pos, n = 24, 0
    while pos + 16 <= len(data) and n < 200_000:
        incl = struct.unpack_from(en + "I", data, pos + 8)[0]
        if incl > 0x400000:
            break
        pos += 16 + incl
        n += 1
    out["packets"] = n
    out["_extent"] = min(end, len(data))
    return out


# ---------------------------------------------------------------------------
# Media / misc parsers
# ---------------------------------------------------------------------------

def _parse_riff(data: bytes) -> dict:
    out: dict = {}
    form = data[8:12].decode("latin-1", "replace")
    out["form"] = form
    chunks: list = []
    pos = 12
    while pos + 8 <= min(len(data), 4096) and len(chunks) < 24:
        cid = data[pos:pos + 4].decode("latin-1", "replace")
        csz = struct.unpack_from("<I", data, pos + 4)[0]
        chunks.append(f"{cid}:{csz}")
        pos += 8 + csz + (csz & 1)
        if csz == 0:
            break
    out["subchunks"] = chunks
    return out


def _parse_mp4(data: bytes) -> dict:
    out: dict = {}
    boxes: list = []
    pos = 0
    while pos + 8 <= len(data) and len(boxes) < 16:
        size = struct.unpack_from(">I", data, pos)[0]
        typ = data[pos + 4:pos + 8].decode("latin-1", "replace")
        if size < 8:
            break
        boxes.append(typ)
        if typ == "ftyp":
            out["major_brand"] = data[pos + 8:pos + 12].decode("latin-1", "replace")
            compat_n = max((size - 16) // 4, 0)
            out["compatible_brands"] = [
                data[pos + 16 + k * 4:pos + 20 + k * 4].decode("latin-1", "replace")
                for k in range(min(compat_n, 8))
            ]
        pos += size
    out["boxes"] = boxes
    return out


def _parse_macho(data: bytes) -> dict:
    out: dict = {}
    le = data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    en = "<" if le else ">"
    out["bits"] = 64 if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    cputype, cpusub, ftype, ncmds = struct.unpack_from(en + "IIII", data, 4)
    cpu = {7: "i386", 0x01000007: "x86-64", 12: "ARM",
           0x0100000C: "AArch64"}.get(cputype, hex(cputype))
    ft = {1: "object", 2: "execute", 5: "dylib", 6: "bundle", 7: "core"}
    out.update(cpu=cpu, cpusubtype=cpusub & 0xFFFFFF,
               filetype=ft.get(ftype, str(ftype)), load_commands=ncmds)
    return out


def _parse_sqlite(data: bytes) -> dict:
    out: dict = {}
    page = struct.unpack_from(">H", data, 16)[0]
    out["page_size"] = 65536 if page == 1 else page
    out["write_version"] = {1: "legacy", 2: "WAL"}.get(data[18], str(data[18]))
    enc = struct.unpack_from(">I", data, 56)[0]
    out["text_encoding"] = {1: "UTF-8", 2: "UTF-16le",
                            3: "UTF-16be"}.get(enc, str(enc))
    pages = struct.unpack_from(">I", data, 28)[0]
    out["pages"] = pages
    return out


def _parse_ole(data: bytes) -> dict:
    out: dict = {}
    sshift = struct.unpack_from("<H", data, 30)[0]
    mshift = struct.unpack_from("<H", data, 32)[0]
    out["sector_size"] = 1 << sshift
    out["mini_sector_size"] = 1 << mshift
    out["note"] = "legacy Office doc / MSI / Outlook msg container"
    return out


def _parse_pdf(data: bytes) -> dict:
    out: dict = {}
    m = __import__("re").search(rb"%PDF-(\d\.\d)", data[:1024])
    if m:
        out["pdf_version"] = m.group(1).decode()
    out["has_eof_marker"] = b"%%EOF" in data[-2048:]
    out["objects_hint"] = data.count(b"/Type") 
    return out


def _parse_iso(data: bytes) -> dict:
    out: dict = {}
    pvd = data[0x8000:0x8810]
    if pvd[1:6] != b"CD001":
        return {"error": "PVD not found"}
    out["volume_id"] = pvd[40:72].decode("ascii", "replace").strip()
    out["system_id"] = pvd[8:40].decode("ascii", "replace").strip()
    return out


def _parse_bzip2(data: bytes) -> dict:
    lvl = chr(data[3]) if 0x31 <= data[3] <= 0x39 else "?"
    return {"compression_level": lvl}


def _parse_7z(data: bytes) -> dict:
    return {"version": f"{data[6]}.{data[7]}"}


PARSERS: dict[str, object] = {
    "GZIP": _parse_gzip,
    "BZIP2": _parse_bzip2,
    "TAR": _parse_tar,
    "PNG": _parse_png,
    "JPEG": _parse_jpeg,
    "ELF": parse_elf,
    "PE/MZ": parse_pe,
    "PDF": _parse_pdf,
    "OLE compound": _parse_ole,
    "SQLite 3": _parse_sqlite,
    "RIFF container": _parse_riff,
    "ISO9660": _parse_iso,
    "7-Zip": _parse_7z,
}






