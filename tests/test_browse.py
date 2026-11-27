import unittest

from ru_routing.browse import agree, compare


def hosts(**kw):
    return {h: {"ok": ok, "failed": failed, "bytes": 0, "errors": errors}
            for h, (ok, failed, errors) in kw.items()}


def visit(status=200, error=None, marks=(), **requests):
    return {"status": status, "error": error, "marks": list(marks), "requests": hosts(**requests)}


ABROAD = visit(site=(5, 0, []), cdn=(10, 0, []), ads=(0, 1, ["net::ERR_FAILED"]))


class CompareTest(unittest.TestCase):
    def test_works(self):
        self.assertEqual(compare(visit(site=(5, 0, []), cdn=(10, 0, [])), ABROAD), ("works", []))

    def test_page_loads_but_its_cdn_stalls(self):
        home = visit(site=(5, 0, []), cdn=(0, 0, ["stalled"]))
        self.assertEqual(compare(home, ABROAD), ("works", ["cdn"]))

    def test_page_never_loads(self):
        home = visit(status=None, error="Timeout 30000ms exceeded", site=(0, 1, ["net::ERR_TIMED_OUT"]))
        self.assertEqual(compare(home, ABROAD), ("broken", ["site"]))

    def test_host_failing_abroad_too_proves_nothing(self):
        home = visit(site=(5, 0, []), cdn=(10, 0, []), ads=(0, 1, ["net::ERR_FAILED"]))
        self.assertEqual(compare(home, ABROAD), ("works", []))

    def test_geoblocked_by_text(self):
        self.assertEqual(compare(visit(marks=["geo"], site=(5, 0, [])), ABROAD)[0], "geoblocked")

    def test_no_good_visit_abroad(self):
        self.assertEqual(compare(visit(site=(5, 0, [])), visit(status=None, error="x")), ("unknown", []))
        self.assertEqual(compare(visit(site=(5, 0, [])), visit(marks=["challenge"])), ("unknown", []))


class AgreeTest(unittest.TestCase):
    def test_every_pass_must_agree(self):
        self.assertEqual(agree([("works", ["cdn", "api"]), ("works", ["cdn"])]), ("works", ["cdn"]))
        self.assertEqual(agree([("broken", ["site"]), ("works", [])]), ("unstable", []))

    def test_one_pass(self):
        self.assertEqual(agree([("geoblocked", ["site"])]), ("geoblocked", ["site"]))


if __name__ == "__main__":
    unittest.main()
