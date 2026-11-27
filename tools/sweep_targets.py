"""Targets for a sweep: practically every site people open, in one queue.

    python tools/sweep_targets.py dist/full > world.txt
    python -m ru_routing sweep add world.txt --source world

Sources, in order: the service checks, sites from the Chrome UX Report for
Russia, the rest of the CrUX lists in the cache, then the Tranco, Cisco
Umbrella and Majestic top million lists. Umbrella counts DNS lookups, so it
brings the API and CDN hosts that apps use and no web ranking has.

Left out: Russian zones, .ua (tunnelled as a whole), and whatever the variant
already sends through a tunnel.
"""

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ru_routing import sources

LISTS = [
    ("tranco", "https://tranco-list.eu/top-1m.csv.zip", 1),
    ("umbrella", "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1),
    ("majestic", "https://downloads.majestic.com/majestic_million.csv", 2),
]
SKIP_ZONES = ("ru", "su", "xn--p1ai", "ua")
TIER = 10_000_000  # priorities of one source stay within their own band


def top_list(name, url, column, cache=Path(".cache/world")):
    path = cache / name
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        data = sources.download(url)
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                data = z.read(z.namelist()[0])
        path.write_bytes(data)
    for rank, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        fields = line.split(",")
        if len(fields) > column and "." in fields[column]:
            yield fields[column].strip().lower(), rank


def main():
    variant = Path(sys.argv[1] if len(sys.argv) > 1 else "dist/full")
    listed = {line.partition(":")[2] for line in
              (variant / "text" / "geosite" / "ru-unreachable.txt").read_text(encoding="utf-8").splitlines()
              if line.startswith(("domain:", "full:"))}

    def wanted(host):
        parts = host.split(".")
        return parts[-1] not in SKIP_ZONES and not any(".".join(parts[i:]) in listed for i in range(len(parts)))

    cache = sources.Cache(sources.load_config("sources.toml"), ".cache", offline=True)
    queue = {}

    def put(host, priority):
        if host not in queue and wanted(host):
            queue[host] = priority

    for line in Path("probes.txt").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            queue[line.strip()] = 0
    for host, rank in cache.ranks(countries=["ru"]):
        put(host, TIER + rank)
    for host, rank in cache.ranks():
        put(host, 2 * TIER + rank)
    for tier, (name, url, column) in enumerate(LISTS, 3):
        for host, rank in top_list(name, url, column):
            put(host, tier * TIER + rank)
    for host, priority in sorted(queue.items(), key=lambda x: x[1]):
        print(priority, host)
    print(f"{len(queue)} targets", file=sys.stderr)


if __name__ == "__main__":
    main()
