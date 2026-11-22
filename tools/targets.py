"""Hosts worth scanning from Russia, most visited first.

    python tools/targets.py dist/lite > targets.txt

Two kinds of hosts, mixed by popularity:
- everything the variant sends through a tunnel (ru-unreachable): is it really
  broken, or does it open fine without a VPN?
- foreign sites popular in Russia that no list mentions: do any of them fail?

Service checks from probes.txt go first.

Popularity comes from the CrUX lists in the cache (run `python -m ru_routing fetch`).
A domain from the lists is checked through its most visited host, so that
`example.com` is tested as `www.example.com` when that is what people open.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ru_routing import sources
from ru_routing.variants import UNRANKED

RUSSIAN = ("ru", "su", "xn--p1ai")


def main():
    variant = Path(sys.argv[1] if len(sys.argv) > 1 else "dist/lite")
    listed = set()
    for line in (variant / "text" / "geosite" / "ru-unreachable.txt").read_text().splitlines():
        kind, _, value = line.partition(":")
        if kind in ("domain", "full"):
            listed.add(value)

    cache = sources.Cache(sources.load_config("sources.toml"), ".cache", offline=True)
    best, russian = {}, {}
    for host, rank in cache.ranks():
        best[host] = min(rank, best.get(host, UNRANKED))
    for host, rank in cache.ranks(countries=["ru"]):
        russian[host] = min(rank, russian.get(host, UNRANKED))

    picked = {}  # host -> rank
    covered = set()
    for host, rank in best.items():
        parts = host.split(".")
        owner = next((".".join(parts[i:]) for i in range(len(parts)) if ".".join(parts[i:]) in listed), None)
        if owner:
            covered.add(owner)
            picked[host] = rank
        elif host in russian and parts[-1] not in RUSSIAN:
            picked[host] = russian[host]
    for domain in listed - covered:
        picked.setdefault(domain, UNRANKED)

    for line in Path("probes.txt").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            print(0, line.strip())
    for host, rank in sorted(picked.items(), key=lambda x: (x[1], x[0])):
        print(rank if rank < UNRANKED else "-", host)


if __name__ == "__main__":
    main()
