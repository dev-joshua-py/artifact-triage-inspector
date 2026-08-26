import io
import os
import struct
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ati.hexview import head_tail_dump, hex_lines  # noqa: E402


import re


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


class TestHexview(unittest.TestCase):
    def test_offsets_and_columns(self):
        lines = hex_lines(bytes(range(256)) * 2, offset=0x100, length=2)
        line = lines[0]
        self.assertTrue(line.startswith("00000100"), line)
        self.assertIn("00 01", line)
        self.assertIn("|..|", line)

    def test_wrapping(self):
        data = bytes(range(256))
        lines = hex_lines(data, offset=0, length=256, width=16)
        self.assertEqual(len(lines), 16)
        self.assertTrue(lines[5].startswith("00000050"))

    def test_highlight_marks_bytes(self):
        data = b"HELLO WORLD"
        lines = hex_lines(data, offset=0, length=11,
                          highlights=[(0, 5)], color=True)
        joined = "".join(lines)
        self.assertIn("\033[33m48\033[0m", joined)   # 'H' = 0x48 highlighted
        plain = _strip_ansi(joined)
        self.assertIn("|HELLO WORLD|", plain)

    def test_head_tail(self):
        dump = head_tail_dump(bytes(range(256)), span=16)
        self.assertIn("--- head ---", dump)
        self.assertIn("--- tail ", dump)


class TestTuiViews(unittest.TestCase):
    def _app(self, data: bytes):
        from ati.tui import App
        return App("sample.bin", data)

    def sample_data(self) -> bytes:
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("n.txt", "password=hunter2")
        header = b"config http://10.0.0.9/x flag{tui_flag}\n"
        return header + zbuf.getvalue() + b"\x00" * 64

    def test_overview_lines(self):
        app = self._app(self.sample_data())
        lines = app.body_overview(120, 30)
        text = "\n".join(lines)
        self.assertIn("format", text)
        self.assertIn("embedded objects", text)

    def test_frame_has_multiple_rows(self):
        app = self._app(self.sample_data())
        frame = app.build_frame()
        rows = frame.replace("\x1b[K", "").split("\n")
        self.assertGreaterEqual(len(rows), 6)   # header + tabs + body + footer
        self.assertTrue(rows[0].startswith(" ATI triage:"))

    def test_view_switching_and_search(self):
        app = self._app(self.sample_data())
        self.assertTrue(app.handle_key("4"))          # Strings view
        self.assertEqual(app.view, 3)
        total = len(app.filtered_strings)
        self.assertTrue(app.handle_key("/"))          # enter search input
        self.assertEqual(app.input_mode, "search")
        for ch in "hunter":
            app.handle_key(ch)
        self.assertEqual(app.input_buf, "hunter")
        app.handle_key("enter")
        filtered = app.filtered_strings
        self.assertLessEqual(len(filtered), total)
        self.assertTrue(any("hunter2" in s.text for s in filtered))

    def test_goto_offset(self):
        app = self._app(bytes(range(256)))
        app.input_mode, app.input_buf = "goto", "0x80"
        app._submit_input()
        self.assertEqual(app.view, 2)
        self.assertEqual(app.hex_line, 8)

    def test_export_selected(self):
        import tempfile
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "f.bin")
        with open(path, "wb") as fh:
            fh.write(self.sample_data())
        from ati.tui import App
        with open(path, "rb") as fh:
            app = App(path, fh.read())
        app.view = 5
        self.assertTrue(app.embedded)
        app.handle_key("x")
        exports = os.listdir(path + "_exports")
        self.assertTrue(exports)
        self.assertIn("exported", app.status)

    def test_quit_key(self):
        app = self._app(b"x" * 10)
        self.assertFalse(app.handle_key("q"))


if __name__ == "__main__":
    unittest.main()
