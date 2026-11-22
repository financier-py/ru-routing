import tempfile
import unittest
from pathlib import Path

from ru_routing import verify


def variant(root, geosite=None, geoip=None):
    for kind, lists in (("geosite", geosite or {}), ("geoip", geoip or {})):
        folder = Path(root, "text", kind)
        folder.mkdir(parents=True, exist_ok=True)
        for name, lines in lists.items():
            (folder / f"{name}.txt").write_text("\n".join(lines) + "\n")
    return root


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = variant(self.tmp.name,
                            {"video": ["domain:youtube.com", "full:youtu.be", "keyword:tube"]},
                            {"tg": ["91.108.4.0/22"]})
        self.lists = verify.Lists(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_lookup(self):
        self.assertTrue(self.lists.contains("video", "www.youtube.com"))
        self.assertTrue(self.lists.contains("video", "youtu.be"))
        self.assertTrue(self.lists.contains("video", "mytube.example"))
        self.assertFalse(self.lists.contains("video", "example.com"))
        self.assertTrue(self.lists.contains("tg", "91.108.5.1"))
        self.assertFalse(self.lists.contains("tg", "8.8.8.8"))

    def test_failures_and_skipped_categories(self):
        checks = [(1, "youtube.com", ["video", "!tg"]), (2, "example.com", ["video"]), (3, "a.com", ["missing"])]
        self.assertEqual(verify.check(self.root, checks), ["checks.txt:2: example.com is not in video"])


class DiffTest(unittest.TestCase):
    def test_counts(self):
        with tempfile.TemporaryDirectory() as old, tempfile.TemporaryDirectory() as new:
            variant(old, {"x": ["domain:a.com", "domain:b.com"]})
            variant(new, {"x": ["domain:b.com", "domain:c.com"]})
            self.assertEqual(list(verify.diff(old, new)),
                             ["text/geosite/x.txt: +1 -1  +domain:c.com, -domain:a.com"])


if __name__ == "__main__":
    unittest.main()
