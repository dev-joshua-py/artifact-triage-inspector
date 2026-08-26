"""Generate synthetic CTF-style sample artifacts for verification."""
from __future__ import annotations

import gzip
import io
import os
import struct
import tarfile
import zipfile
import zlib


def png_chunk(typ: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + typ + body +
            struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def build_png(width=16, height=16, text_chunks: dict | None = None) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([120, 40, 200] * width) for _ in range(height))
    out = b"\x89PNG\r\n\x1a\n"
    out += png_chunk(b"IHDR", ihdr)
    for k, v in (text_chunks or {}).items():
        out += png_chunk(b"tEXt", k.encode() + b"\x00" + v.encode())
    out += png_chunk(b"IDAT", zlib.compress(raw))
    out += png_chunk(b"IEND", b"")
    return out


def build_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def build_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def gz(data: bytes, name: str | None = None) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name or "", mode="wb", fileobj=buf) as f:
        f.write(data)
    return buf.getvalue()


def _ipv4(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def build_pcap(payloads: list[tuple[bytes, int]]) -> bytes:
    """payloads: list of (l3bytes, timestamp_us)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    ip_h = b"\x45\x00\x00\x28\x12\x34\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x07\xc0\xa8\x01\x01"
    tcp_h = b"\xc3\x50\x00\x50\x00\x00\x00\x01\x00\x00\x00\x02\x50\x02\x20\x00\x91\x7c\x00\x00"
    for i, (pl, ts) in enumerate(payloads):
        pkt = eth + ip_h + tcp_h + pl
        rec = struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000,
                          len(pkt), len(pkt))
        out += rec + pkt
    return out


def http_get(host: str, path: str, auth_b64: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Authorization: Basic {auth_b64}\r\n"
            f"User-Agent: ctf-agent/1.0\r\n\r\n").encode()


def http_body(body: str) -> bytes:
    return (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
            f"\r\n{body}").encode()


def build_jpeg_with_exif(exif_entries: list[tuple[int, object]],
                         comment: bytes = b"") -> bytes:
    """Minimal JPEG: SOI + APP1(Exif) + DQT + SOS + fake entropy + EOI."""
    bo = b"II"
    entries = []
    for tag, val in exif_entries:
        if isinstance(val, str):
            raw = val.encode() + b"\x00"
            entries.append((tag, 2, len(raw), raw))
        elif isinstance(val, int):
            entries.append((tag, 4, 1, struct.pack("<I", val)))
        elif isinstance(val, tuple):
            flat = []
            for x in val:
                if isinstance(x, tuple):
                    flat.extend(x)
                else:
                    flat.append(x)
            rationals = [(flat[i], flat[i + 1])
                         for i in range(0, len(flat) - len(flat) % 2, 2)]
            data = b"".join(struct.pack("<II", n, d) for n, d in rationals)
            entries.append((tag, 5, len(rationals), data))

    n = len(entries)
    base_off = 8 + 2 + n * 12 + 4          # first byte after IFD0
    ifd_body = struct.pack("<H", n)
    ext_data = b""
    for tg, ty, cnt, raw in entries:
        if len(raw) > 4:
            val_field = struct.pack("<I", base_off + len(ext_data))
            ext_data += raw
        else:
            val_field = raw[:4].ljust(4, b"\x00")
        ifd_body += struct.pack("<HHI", tg, ty, cnt) + val_field
    ifd_body += struct.pack("<I", 0)       # no next IFD
    tiff = bo + struct.pack("<HI", 42, 8) + ifd_body + ext_data
    app1_payload = b"Exif\x00\x00" + tiff

    out = b"\xff\xd8\xff"
    out += b"\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    if comment:
        out += b"\xfe" + struct.pack(">H", len(comment) + 2) + comment
    dqt = bytes([0x00] + [16] * 64)
    out += b"\xdb" + struct.pack(">H", len(dqt) + 2) + dqt
    sos = b"\x01\x11\x00"
    out += b"\xda" + struct.pack(">H", len(sos) + 2) + sos
    out += bytes([0x33] * 40)          # fake scan data
    out += b"\xff\xd9"
    return out


def build_elf_stub() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000,
                      64, 120, 0, 64, 56, 1, 64, 3, 2)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0x400000, 0x400000,
                       0x80, 0x80)
    return ident + hdr + phdr + bytes([0xCC] * 56)


def build_pe_stub() -> bytes:
    dos = bytearray(b"MZ" + b"\x00" * 58)
    e_lfanew = 0x40
    dos[0x3C:0x40] = struct.pack("<I", e_lfanew)
    pe = (b"PE\x00\x00" +
          struct.pack("<HHIIIHH", 0x8664, 1, 0x66000000, 0, 0, 240, 0x22))
    opt = bytearray(struct.pack("<HBB", 0x20B, 14, 0)) + b"\x00" * 236
    opt[68:70] = struct.pack("<H", 3)  # console subsystem
    sec = (b".text\x00\x00\x00" + struct.pack("<IIII", 0x200, 0x1000,
                                              0x200, 0x400) + b"\x00" * 20)
    body = bytes(dos) + b"PADDING" * 4 + pe + bytes(opt) + sec
    body += bytes([0x90]) * 512
    return body


FLAG1 = "flag{m3ta_dat4_hunt3r}"
FLAG2 = "flag{n3st3d_arch1ve_w1n}"
FLAG3 = "flag{pcap_http_exfil}"


def make_all(outdir="samples") -> list[str]:
    os.makedirs(outdir, exist_ok=True)
    made = []

    def write(name: str, blob: bytes) -> str:
        p = os.path.join(outdir, name)
        with open(p, "wb") as fh:
            fh.write(blob)
        made.append(p)
        return p

    # 1. plain-text config leak
    write("config_leak.ini",
          ("[deploy]\nserver=10.0.0.7\nbackup_server=192.168.13.37\n"
           "endpoint=https://cdn.example-cdn.example/assets\n"
           "contact=admin@evil-corp.example.com\n"
           "password=Sup3rS3cretP@ss!\napi_key=AKIAIOSFODNN7EXAMPLE\n"
           f"token={FLAG1}\n").encode())

    # 2. PNG with metadata flag + appended ZIP containing a nested ZIP
    inner_zip = build_zip({"secret/flag.txt": FLAG2.encode()})
    outer_zip = build_zip({
        "note.txt": b"hidden note: password=hunter2 server=172.16.4.2",
        "inner.zip": inner_zip,
    })
    write("image_payload.png", build_png(text_chunks={"Comment": FLAG1}) + outer_zip)

    # 3. PCAP with HTTP Basic auth and a flag in the response
    import base64
    creds = base64.b64encode(b"admin:P@ssw0rd!").decode()
    payloads = [
        (http_get("files.totally-legit.example", "/dl/payload.bin", creds), 1750000000),
        (http_body(f"download ready... {FLAG3}"), 1750000010),
    ]
    write("capture.pcap", build_pcap(payloads))

    # 4. firmware image: padding + TAR(kernel+creds) + appended GZIP secrets
    kernel = bytes(bytearray(__import__("os").urandom(6144)))
    tar_blob = build_tar({
        "boot/kernel.img": kernel,
        "etc/deploy.conf": b"root_password=t0ughGu3ss\n"
                           b"ntp=time.sync.example\nmgmt_ip=10.10.255.1\n",
    })
    gz_blob = gz(b"AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\n"
                 b"db_url=postgres://svc:S3cret@10.0.9.9/prod\n")
    write("firmware.img", b"\x00" * 1024 + tar_blob + gz_blob)

    # 5. packed-looking PE stub with high-entropy section + appended 7z decoy
    pe = build_pe_stub()
    noise = __import__("os").urandom(3072)
    strings = (b"https://c2.malware-demo.example/gate\r\ndnslock.local\r\n"
               b"powershell -enc AAAA\r\nC:\\Users\\Public\\drop.exe\r\n")
    write("packed_stub.exe.bin", pe + noise + strings +
          b"7z\xbc\xaf'\x1c" + bytes(24) + noise[:1024])

    # 6. nested archive: gzip(tar(a.txt + zip(flag)))
    nested = gz(build_tar({"docs/readme.txt": b"outer layer ok",
                           "deep.zip": build_zip({"flag_nested.txt": FLAG2.encode()})}))
    write("nested.tar.gz", nested)

    # 7. JPEG with EXIF + GPS + appended secret comment block
    jpg = build_jpeg_with_exif(
        [(0x010F, "FlagCam"), (0x0110, "Model-X"),
         (0x9003, "2026:07:04 03:14:15"),
         (0x0002, (37 * 3600 + 46 * 60 + 22, 10000)),
         (0x0004, ((122 * 3600 + 25 * 60 + 9, 10000)))],
        comment=b"stashed: flag{jpeg_appended} ip=203.0.113.66")
    write("exif_trip.jpg", jpg)

    print(f"wrote {len(made)} sample artifacts to ./{outdir}/:")
    for p in made:
        print(f"  {p} ({len(open(p,'rb').read())} bytes)")
    return made


if __name__ == "__main__":
    import sys
    make_all(sys.argv[1] if len(sys.argv) > 1 else "samples")

