import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ati.intel import extract_strings, scan_findings  # noqa: E402

JWT = ("eyJhbGciOiJIUzI1NiJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")


class TestStrings(unittest.TestCase):
    def test_ascii_extraction(self):
        hits = extract_strings(b"\x01ab\x00hello world!\xff tail")
        texts = [h.text for h in hits]
        # default min_len=5 keeps 'hello world!' and ' tail' only
        self.assertIn("hello world!", texts)
        self.assertNotIn("ab", texts)

    def test_min_len_respected(self):
        hits = extract_strings(b"abcde fghij\x00klmno", min_len=5)
        self.assertTrue(all(len(h.text) >= 5 for h in hits))

    def test_utf16_extraction(self):
        blob = "hidden\u2000secret".encode("utf-16-le")
        hits = extract_strings(b"\x00" * 4 + blob + b"\xff", min_len=5)
        wide = [h.text for h in hits if h.kind == "utf16"]
        self.assertTrue(any("hidden" in w for w in wide))


class TestFindings(unittest.TestCase):
    def setUp(self):
        b64tok = base64.b64encode(
            b"user:SuperSecretPassword!").decode().encode()
        self.data = (
            b"server 10.0.0.7 gw\n"
            b"http://evil.example.com/payload?q=1\n"
            b"password=Tr0ub4dor&3\n"
            b"AKIAIOSFODNN7EXAMPLE\n"
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"
            b"-----END RSA PRIVATE KEY-----\n"
            + JWT.encode() + b"\n"
            + b"token_b64=" + b64tok + b"\n"
            b"flag{v3ry_s3cr3t_fl4g}\n"
            b"contact root@host.internal.test\n"
            b"/etc/passwd C:\\Windows\\system32\n"
        )

    def find_cat(self, cats, cat):
        return [f for f in cats if f.category == cat]

    def test_core_categories_detected(self):
        fs = scan_findings(self.data)
        cats = {f.category for f in fs}
        for expected in ("ipv4", "url", "credential", "aws_access_key",
                         "private_key", "jwt", "base64", "ctf_flag",
                         "email", "unix_path", "windows_path"):
            self.assertIn(expected, cats, f"missing category {expected}")

    def test_flag_values(self):
        fs = scan_findings(self.data)
        flags = [f.value for f in self.find_cat(fs, "ctf_flag")]
        self.assertTrue(any("flag{v3ry_s3cr3t_fl4g}" in v for v in flags))

    def test_base64_validated_and_decoded(self):
        fs = scan_findings(self.data)
        b64 = self.find_cat(fs, "base64")
        self.assertTrue(b64)

    def test_invalid_base64_rejected(self):
        fs = scan_findings(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertFalse(self.find_cat(fs, "base64"))

    def test_offsets_are_absolute(self):
        pad = b"\x00" * 1234
        fs = scan_findings(pad + self.data)
        fs2 = scan_findings(self.data)
        self.assertEqual(fs[0].offset - fs2[0].offset, len(pad))


if __name__ == "__main__":
    unittest.main()
