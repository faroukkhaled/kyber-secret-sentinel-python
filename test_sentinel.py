import tempfile
import unittest
from pathlib import Path
from sentinel import scan, render

class SentinelTests(unittest.TestCase):
    def test_values_never_appear_in_report(self):
        with tempfile.TemporaryDirectory() as directory:
            value = "ghp_" + "A" * 36
            Path(directory, "sample.txt").write_text(value)
            result = scan(directory)
            self.assertEqual(len(result["findings"]), 1)
            self.assertNotIn(value, str(result))
            self.assertNotIn(value, render(result))

    def test_exclusions_binary_size_and_html_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / ".git" / "key.txt").write_text("ghp_" + "A" * 36)
            (root / "binary").write_bytes(b"\0" + b"x" * 20)
            (root / "large").write_text("x" * 100)
            result = scan(root, max_bytes=50)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["files_skipped"], 2)
            result["findings"] = [{"path": "<script>", "line": 1, "rule": "test", "severity": "low", "fingerprint": "redacted"}]
            self.assertNotIn("<script>", render(result))
            self.assertIn("&lt;script&gt;", render(result))

if __name__ == "__main__":
    unittest.main()
