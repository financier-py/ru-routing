"""Output formats: geosite.dat / geoip.dat for Xray, rule-sets for Mihomo, plain text.

The .dat files are protobuf (see v2ray-core app/router/routercommon/common.proto).
The encoding is simple enough to write by hand, which keeps the project free of
dependencies. Mihomo's .mrs is a compressed succinct trie, so it is made by the
mihomo binary itself (`mihomo convert-ruleset`).
"""

import ipaddress
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

DOMAIN_TYPE = {"keyword": 0, "regexp": 1, "domain": 2, "full": 3}


def _varint(n):
    out = bytearray()
    while n > 0x7F:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _bytes(field, payload):
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def _int(field, value):
    return _varint(field << 3) + _varint(value) if value else b""


def geosite(categories):
    """{name: [Rule]} -> geosite.dat. Xray looks codes up in upper case."""
    entries = []
    for name, rules in sorted(categories.items()):
        domains = b"".join(
            _bytes(2, _int(1, DOMAIN_TYPE[r.kind]) + _bytes(2, r.value.encode())) for r in rules
        )
        entries.append(_bytes(1, _bytes(1, name.upper().encode()) + domains))
    return b"".join(entries)


def geoip(categories):
    """{name: [Rule]} with ip rules -> geoip.dat."""
    entries = []
    for name, rules in sorted(categories.items()):
        nets = map(ipaddress.ip_network, (r.value for r in rules))
        cidrs = b"".join(_bytes(2, _bytes(1, n.network_address.packed) + _int(2, n.prefixlen)) for n in nets)
        entries.append(_bytes(1, _bytes(1, name.upper().encode()) + cidrs))
    return b"".join(entries)


def text(rules):
    return "".join(f"{r}\n" for r in rules)


def mihomo_domains(rules):
    """Mihomo's domain rule-set: +.example.com for a domain with subdomains,
    example.com for an exact name. Keywords and regexps don't fit the format."""
    return "".join(("+." if r.kind == "domain" else "") + r.value + "\n"
                   for r in rules if r.kind in ("domain", "full"))


def mihomo_classical(rules):
    """The slower classical format, for categories that need keywords or regexps."""
    kind = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN", "keyword": "DOMAIN-KEYWORD", "regexp": "DOMAIN-REGEX"}
    return "".join(f"{kind[r.kind]},{r.value}\n" for r in rules if r.kind in kind)


def find_mihomo():
    return os.environ.get("MIHOMO") or shutil.which("mihomo")


def mrs(binary, behavior, text_data, out):
    """Convert a text rule-set to .mrs. behavior is "domain" or "ipcidr"."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as src:
        src.write(text_data)
        src.flush()
        subprocess.run([binary, "convert-ruleset", behavior, "text", src.name, str(out)],
                       check=True, capture_output=True, timeout=600)
    return Path(out)
