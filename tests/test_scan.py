import unittest

from ru_routing.scan import verdict

OK = {"status": 200, "bytes": 50000, "stage": None, "marks": []}


def home(**kw):
    return {**OK, **kw}


class VerdictTest(unittest.TestCase):
    def test_works(self):
        self.assertEqual(verdict(home(), OK), "works")

    def test_blocked_at_handshake(self):
        self.assertEqual(verdict(home(status=None, stage="tls", bytes=0), OK), "blocked")

    def test_throttled_mid_page(self):
        self.assertEqual(verdict(home(status=None, stage="body", bytes=16000), OK), "throttled")

    def test_stall_after_a_redirect(self):
        stalled = home(status=301, stage="body", bytes=16000, error="TimeoutError: The read operation timed out")
        self.assertEqual(verdict(stalled, OK), "throttled")

    def test_geoblocked_by_text_or_status(self):
        self.assertEqual(verdict(home(marks=["geo"]), OK), "geoblocked")
        self.assertEqual(verdict(home(status=451), OK), "geoblocked")

    def test_api_refusal(self):
        self.assertEqual(verdict(home(status=403), {**OK, "status": 401}), "geoblocked")

    def test_stub_page(self):
        self.assertEqual(verdict(home(marks=["block"]), OK), "blocked")

    def test_no_answer_proves_nothing(self):
        self.assertEqual(verdict(home(status=None, stage="dns", bytes=0), OK), "unknown")
        self.assertEqual(verdict(home(status=None, stage="dns", error="gaierror: no A record for hp.com"), OK), "blocked")
        self.assertEqual(verdict(home(status=None, stage="connect", error="OSError: [Errno 19] No such device"), OK), "unknown")
        self.assertEqual(verdict(home(status=403), {**OK, "status": 404}), "unknown")
        self.assertEqual(verdict(home(status=404), {**OK, "status": 404}), "works")

    def test_nothing_to_compare_with(self):
        self.assertEqual(verdict(home(status=None, stage="dns"), None), "unknown")
        self.assertEqual(verdict(home(), {**OK, "status": 503}), "unknown")
        self.assertEqual(verdict(home(), {**OK, "marks": ["challenge"]}), "unknown")


if __name__ == "__main__":
    unittest.main()
