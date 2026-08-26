import gzip
import io
import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ati.carver import carve_artifacts, detect_embedded  # noqa: E402


def minimal_png():
    def chunk(typ, body):
        return (struct.pack(">I", len(body)) + typ + body +
                struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(b"\x00" * 12)) + chunk(b"IEND", b""))


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    return buf.getvalue()


class TestDetect(unittest.TestCase):
    def test_appended_zip_detected(self):
        blob = minimal_png() + make_zip({"x.txt": b"A" * 100})
        found = detect_embedded(blob)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "ZIP")
        self.assertEqual(found[0].offset, len(minimal_png()))
        self.assertFalse(found[0].guessed)

    def test_offset_zero_excluded_by_default(self):
        zip_only = make_zip({"a.txt": b"data"})
        self.assertEqual(detect_embedded(zip_only), [])
        self.assertEqual(len(detect_embedded(zip_only, include_zero=True)), 1)

    def test_gzip_measured(self):
        gz = gzip.compress(os.urandom(500))
        blob = b"C" * 64 + gz + b"D" * 32
        found = detect_embedded(blob)
        g = [f for f in found if f.name == "GZIP"]
        self.assertTrue(g)
        self.assertEqual(g[0].size, len(gz))

    def test_pcap_clean(self):
        pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.assertEqual(detect_embedded(pcap), [])


class TestCarve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _walk_files(self, nodes):
        for nd in nodes:
            yield nd["path"]
            yield from self._walk_files(nd.get("children", []))

    def test_recursive_zip_in_png(self):
        inner = make_zip({"secret/flag.txt": b"flag{nested_win}"})
        outer = make_zip({"note.txt": b"hello", "inner.zip": inner})
        blob = minimal_png() + outer
        out = os.path.join(self.tmp, "carved")
        nodes = carve_artifacts(blob, out, source_label="sample.png")
        paths = list(self._walk_files(nodes))
        flat = " ".join(paths)
        # outer zip carved at PNG boundary and its members extracted
        self.assertIn("note", flat)
        self.assertIn("inner", flat)
        content_found = False
        for p in paths:
            try:
                with open(p, "rb") as fh:
                    if b"flag{nested_win}" in fh.read():
                        content_found = True
            except OSError:
                pass
        self.assertTrue(content_found,
                        "flag from nested archive was extracted")

    def test_gzip_carved_from_tail(self):
        blob = b"Z" * 128 + gzip.compress(b"secret=gz_payload " + b"x" * 50)
        out = os.path.join(self.tmp, "c2")
        nodes = carve_artifacts(blob, out, source_label="blob.bin")
        self.assertTrue(nodes)
        member = nodes[0]["children"][0]["path"]
        with open(member, "rb") as fh:
            self.assertIn(b"gz_payload", fh.read())


if __name__ == "__main__":
    unittest.main()
