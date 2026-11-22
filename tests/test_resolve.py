import unittest

from ru_routing.resolve import Origin, Resolver, matches, minimize
from ru_routing.rules import FormatError, Link, Rule, parse, parse_line


class FakeSource:
    def __init__(self, bulk):
        self.bulk = bulk

    def is_bulk(self, name):
        return name in self.bulk


class FakeUpstream:
    def __init__(self, lists, bulk=()):
        self.lists = lists
        self.bulk = bulk

    def source(self, name):
        return FakeSource(self.bulk)

    def category(self, source, name):
        ref = f"{source}/{name}"
        return parse(name, self.lists[ref], ref)

    def asn(self, number):
        return {"62041": ["91.108.4.0/22", "91.108.8.0/22"]}[number]


def resolver(local, upstream=None, bulk=()):
    categories = {name: parse(name, text, f"data/{name}") for name, text in local.items()}
    return Resolver(categories, FakeUpstream(upstream or {}, bulk))


def values(entries):
    return sorted(str(r) for r in entries)


class ParseTest(unittest.TestCase):
    def test_bare_domain_is_domain(self):
        self.assertEqual(parse_line("Example.COM."), Rule("domain", "example.com"))

    def test_attributes(self):
        self.assertEqual(parse_line("full:ads.example.com @ads"), Rule("full", "ads.example.com", frozenset({"ads"})))
        self.assertEqual(parse_line("include:google @ads @-cn"), Link("include", "google", frozenset({"ads"}), frozenset({"cn"})))

    def test_idn(self):
        self.assertEqual(parse_line("пример.рф").value, "xn--e1afmkfd.xn--p1ai")

    def test_errors_point_to_line(self):
        with self.assertRaisesRegex(FormatError, r"data/x:2: bad domain"):
            parse("x", "ok.com\nbad!.com\n", "data/x")
        with self.assertRaisesRegex(FormatError, r"data/x:1: unexpected 'b.com'"):
            parse("x", "a.com b.com\n", "data/x")

    def test_description(self):
        self.assertEqual(parse("x", "# One.\n# Two.\n\na.com\n# not this\n", "x").description, "One. Two.")


class ResolveTest(unittest.TestCase):
    def test_include_with_attributes(self):
        r = resolver({"video": "include:v2fly/google @ads\nyoutube.com"},
                     {"v2fly/google": "google.com\nfull:ads.google.com @ads\n"})
        self.assertEqual(values(r.resolve("video")), ["domain:youtube.com", "full:ads.google.com"])

    def test_upstream_includes_stay_in_their_source(self):
        r = resolver({"x": "include:v2fly/youtube"},
                     {"v2fly/youtube": "include:google\nyoutube.com", "v2fly/google": "google.com"})
        self.assertEqual(values(r.resolve("x")), ["domain:google.com", "domain:youtube.com"])

    def test_exclude_removes_subdomains(self):
        r = resolver({"blocked": "a.com\nb.a.com\nc.com\nexclude:checkers", "checkers": "a.com"})
        self.assertEqual(values(r.resolve("blocked")), ["domain:c.com"])

    def test_cycle(self):
        r = resolver({"a": "include:b", "b": "include:a"})
        with self.assertRaisesRegex(FormatError, "cycle"):
            r.resolve("a")

    def test_asn(self):
        r = resolver({"tg": "asn:62041"})
        self.assertEqual(values(r.resolve("tg")), ["ip:91.108.4.0/22", "ip:91.108.8.0/22"])

    def test_origin(self):
        r = resolver({"x": "include:v2fly/y", "z": "a.com"}, {"v2fly/y": "\nb.com"})
        self.assertEqual(r.resolve("x"), {Rule("domain", "b.com"): Origin("v2fly/y:2", False)})

    def test_curated_origin_wins_over_bulk(self):
        r = resolver({"x": "include:reg/all\ninclude:reg/short"},
                     {"reg/all": "a.com\nb.com", "reg/short": "a.com"}, bulk={"all"})
        self.assertEqual({str(k): v.bulk for k, v in r.resolve("x").items()},
                         {"domain:a.com": False, "domain:b.com": True})


class MinimizeTest(unittest.TestCase):
    def test_drops_covered_domains(self):
        o = Origin("", False)
        entries = {Rule("domain", "a.com"): o, Rule("domain", "x.a.com"): o, Rule("full", "a.com"): o,
                   Rule("full", "b.com"): o}
        self.assertEqual(values(minimize(entries)), ["domain:a.com", "full:b.com"])

    def test_merges_networks(self):
        o = Origin("", False)
        entries = {Rule("ip", "10.0.0.0/25"): o, Rule("ip", "10.0.0.128/25"): o, Rule("ip", "::1/128"): o}
        self.assertEqual(values(minimize(entries)), ["ip:10.0.0.0/24", "ip:::1/128"])


class MatchTest(unittest.TestCase):
    def test_kinds(self):
        self.assertTrue(matches(Rule("domain", "a.com"), "x.a.com"))
        self.assertFalse(matches(Rule("domain", "a.com"), "xa.com"))
        self.assertFalse(matches(Rule("full", "a.com"), "x.a.com"))
        self.assertTrue(matches(Rule("keyword", "tube"), "youtube.com"))
        self.assertTrue(matches(Rule("ip", "10.0.0.0/8"), "10.1.2.3"))
        self.assertFalse(matches(Rule("ip", "10.0.0.0/8"), "a.com"))


if __name__ == "__main__":
    unittest.main()
