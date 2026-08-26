import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ati.entropy import (graph, profile, shannon,  # noqa: E402
                         summarize, suspicious_regions)


class TestEntropy(unittest.TestCase):
    def test_zeros_zero_entropy(self):
        self.assertAlmostEqual(shannon(b"\x00" * 1024), 0.0)

    def test_single_repeat(self):
        self.assertAlmostEqual(shannon(b"a" * 500), 0.0)

    def test_uniform_two_symbols(self):
        self.assertAlmostEqual(shannon(b"\x00\xff" * 256), 1.0, places=5)

    def test_random_high(self):
        ent = shannon(os.urandom(8192))
        self.assertGreater(ent, 7.7)
        self.assertLessEqual(ent, 8.0)

    def test_profile_covers_file(self):
        pts = profile(b"A" * 1000 + os.urandom(4000) + b"\x00" * 1000,
                      window=256, step=128)
        self.assertEqual(pts[0][0], 0)
        self.assertGreater(pts[-1][0], 4000)
        self.assertTrue(all(0 <= e <= 8 for _, e in pts))

    def test_graph_shape(self):
        pts = profile(os.urandom(2048), window=256, step=256)
        g = graph(pts, width=32, height=6)
        lines = g.splitlines()
        self.assertEqual(len(lines), 8)   # 6 rows + axis + ruler
        self.assertIn("|", lines[0])

    def test_suspicious_regions_found(self):
        blob = b"B" * 1500 + os.urandom(6000) + b"\x00" * 1500
        regions = suspicious_regions(profile(blob, window=256, step=256))
        kinds = {r["label"].split()[0] for r in regions}
        self.assertIn("high", kinds)
        self.assertIn("low", kinds)

    def test_summarize(self):
        s = summarize(os.urandom(2048))
        self.assertGreater(s["entropy"], 7.5)
        self.assertIn("likely encrypted", s["verdict"])


if __name__ == "__main__":
    unittest.main()
