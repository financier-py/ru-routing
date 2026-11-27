import json
import tempfile
import unittest
from pathlib import Path

from ru_routing import sweep

OK = {"status": 200, "bytes": 50000, "error": None, "stage": None}
STALL = {"status": None, "bytes": 16000, "error": "TimeoutError", "stage": "body"}


class SweepTest(unittest.TestCase):
    def setUp(self):
        self.db = sweep.connect(":memory:")
        sweep.add(self.db, ["2 b.com", "1 a.com", "# comment", "3 c.com"], "test")

    def check(self, host, record, at):
        sweep.record_check(self.db, host, {"host": host, **record}, at)

    def test_best_priority_first(self):
        self.assertEqual(sweep.due(self.db, "home", 2, 0), ["a.com", "b.com"])

    def test_a_better_priority_wins(self):
        sweep.add(self.db, ["0 c.com"], "other")
        self.assertEqual(sweep.due(self.db, "home", 1, 0), ["c.com"])

    def test_second_pass_waits(self):
        self.check("a.com", OK, 1000)
        self.assertNotIn("a.com", sweep.due(self.db, "home", 10, 1000 + 60))
        self.assertIn("a.com", sweep.due(self.db, "home", 10, 1000 + sweep.GAP + 1))

    def test_third_pass_only_when_passes_disagree(self):
        later = 1000 + 3 * sweep.GAP
        self.check("a.com", OK, 1000)
        self.check("a.com", OK, 1000 + sweep.GAP)
        self.check("b.com", OK, 1000)
        self.check("b.com", STALL, 1000 + sweep.GAP)
        due = sweep.due(self.db, "home", 10, later)
        self.assertNotIn("a.com", due)
        self.assertIn("b.com", due)

    def test_abroad_needs_one_pass(self):
        self.check("a.com", OK, 1000)
        self.assertNotIn("a.com", sweep.due(self.db, "abroad", 10, 1000 + 3 * sweep.GAP))

    def test_export_writes_one_file_per_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "s.db")
            db = sweep.connect(db_path)
            sweep.add(db, ["1 a.com", "2 b.com"], "test")
            for host, at in (("a.com", 1), ("b.com", 2), ("a.com", 3)):
                sweep.record_check(db, host, {"host": host, **OK}, at)
            db.commit()
            self.assertEqual(sweep.export(db_path, Path(tmp, "out")), {1: 2, 2: 1})
            second = Path(tmp, "out", "pass-2.jsonl").read_text().splitlines()
            self.assertEqual([json.loads(line)["host"] for line in second], ["a.com"])


if __name__ == "__main__":
    unittest.main()
