import unittest

from ru_routing import formats, variants
from ru_routing.resolve import Origin
from ru_routing.rules import Rule


class DatTest(unittest.TestCase):
    def test_geosite_wire_format(self):
        data = formats.geosite({"x": [Rule("domain", "a.com")]})
        domain = b"\x08\x02" + b"\x12\x05a.com"
        site = b"\x0a\x01X" + b"\x12" + bytes([len(domain)]) + domain
        self.assertEqual(data, b"\x0a" + bytes([len(site)]) + site)

    def test_keyword_type_is_omitted(self):
        self.assertNotIn(b"\x08\x00", formats.geosite({"x": [Rule("keyword", "ab")]}))

    def test_geoip_wire_format(self):
        data = formats.geoip({"x": [Rule("ip", "10.0.0.0/8")]})
        cidr = b"\x0a\x04\x0a\x00\x00\x00" + b"\x10\x08"
        ip = b"\x0a\x01X" + b"\x12" + bytes([len(cidr)]) + cidr
        self.assertEqual(data, b"\x0a" + bytes([len(ip)]) + ip)

    def test_long_varint(self):
        self.assertEqual(formats._varint(300), b"\xac\x02")


class MihomoTest(unittest.TestCase):
    def test_domain_ruleset(self):
        rules = [Rule("domain", "a.com"), Rule("full", "b.com"), Rule("keyword", "c")]
        self.assertEqual(formats.mihomo_domains(rules), "+.a.com\nb.com\n")
        self.assertEqual(formats.mihomo_classical(rules), "DOMAIN-SUFFIX,a.com\nDOMAIN,b.com\nDOMAIN-KEYWORD,c\n")


CURATED = Origin("data/x:1", False)
BULK = Origin("registry/all", True)
CATEGORIES = {
    "blocked": {
        Rule("domain", "kept.com"): CURATED,
        Rule("domain", "popular.com"): BULK,
        Rule("domain", "visited.com"): BULK,
        Rule("domain", "nobody.com"): BULK,
    },
    "big": {Rule("domain", "x.com"): CURATED},
}
RANKS = {"www.popular.com": 1000, "visited.com": 500000}


class VariantTest(unittest.TestCase):
    def pick(self, **kw):
        out = variants.apply(variants.Variant("v", **kw), CATEGORIES, RANKS)
        return {n: sorted(r.value for r in e) for n, e in out.items()}

    def test_limit_takes_most_popular(self):
        self.assertEqual(self.pick(bulk=1)["blocked"], ["kept.com", "popular.com"])

    def test_popular_drops_unvisited(self):
        self.assertEqual(self.pick(bulk="popular")["blocked"], ["kept.com", "popular.com", "visited.com"])

    def test_all_and_skip(self):
        picked = self.pick(bulk="all", skip=["big"])
        self.assertEqual(list(picked), ["blocked"])
        self.assertEqual(len(picked["blocked"]), 4)


if __name__ == "__main__":
    unittest.main()
