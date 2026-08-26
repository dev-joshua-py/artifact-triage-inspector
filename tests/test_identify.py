import io
import os
import struct
import sys
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ati.identify import identify_bytes, scan_signatures  # noqa: E402


def minimal_png():
    def chunk(typ, body):
        return (struct.pack(">I", len(body)) + typ + body +
                struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", 3, 4, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(b"\x00" * 40)) + chunk(b"IEND", b""))


def elf64():
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000,
                      64, 120, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0x400000, 0x400000, 0x80, 0x80)
    return ident + hdr + phdr + b"\xCC" * 56


def pe64():
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(struct.pack("<HBB", 0x20B, 14, 0)) + b"\x00" * 236
    opt[68:70] = struct.pack("<H", 3)
    sec = (b".text\x00\x00\x00" + struct.pack("<IIII", 0x200, 0x1000,
                                              0x200, 0x400) + b"\x00" * 16)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec + b"\x00" * 1180


def pcap_le():
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt = b"\x00" * 24
    out += struct.pack("<IIII", 1750000000, 0, len(pkt), len(pkt)) + pkt
    return out


class TestIdentify(unittest.TestCase):
    def test_png(self):
        fmt = identify_bytes(minimal_png())
        self.assertEqual(fmt.name, "PNG")
        self.assertEqual(fmt.confidence, "high")
        self.assertEqual(fmt.details["width"], 3)
        self.assertEqual(fmt.details["height"], 4)

    def test_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hi")
        fmt = identify_bytes(buf.getvalue())
        self.assertIn("ZIP", fmt.name)
        self.assertEqual(fmt.details["entries"], 1)

    def test_gzip_inner(self):
        import gzip as g
        blob = g.compress(b"plain text payload here")
        fmt = identify_bytes(blob)
        self.assertEqual(fmt.name, "GZIP")
        self.assertTrue(fmt.details.get("inner_size_sampled", 0) > 0)

    def test_elf(self):
        fmt = identify_bytes(elf64())
        self.assertEqual(fmt.name, "ELF")
        self.assertEqual(fmt.details["machine"], "x86-64")
        self.assertEqual(fmt.details["_extent"], 120)

    def test_pe(self):
        fmt = identify_bytes(pe64())
        self.assertIn("PE/MZ", fmt.name)
        self.assertEqual(fmt.details["machine"], "x86-64")
        self.assertEqual(fmt.details["section_names"], [".text"])
        self.assertEqual(fmt.details["_extent"], 0x600)

    def test_pcap(self):
        fmt = identify_bytes(pcap_le())
        self.assertEqual(fmt.name, "PCAP capture")
        self.assertEqual(fmt.details["linktype"], "Ethernet")
        self.assertEqual(fmt.details["packets"], 1)

    def test_tar(self):
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:") as tf:
            info = tarfile.TarInfo("f.txt")
            data = b"x" * 10
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        fmt = identify_bytes(buf.getvalue())
        self.assertEqual(fmt.name, "TAR")
        self.assertEqual(fmt.details["entries"], 1)

    def test_plain_text_fallback(self):
        fmt = identify_bytes(b"hello world " * 200)
        self.assertEqual(fmt.name, "Plain text")

    def test_unknown_binary(self):
        fmt = identify_bytes(os.urandom(512))
        self.assertEqual(fmt.category, "data")

    def test_scan_signatures_offsets(self):
        data = b"A" * 300 + minimal_png() + b"B" * 10
        hits = scan_signatures(data)
        png_hits = [off for off, s in hits if s.name == "PNG"]
        self.assertEqual(png_hits, [300])


if __name__ == "__main__":
    unittest.main()
