"""Which hosting networks are slowed down from Russia.

Blocking by address hits whole networks at once: a site on a throttled
hosting freezes after the first few kilobytes, whatever its name. So hostings
are checked by sample: sites that load fully from abroad are grouped by the
network (ASN) of their address, and a few from each network are scanned from
home like any other target.

    python tools/hostings.py pick abroad.jsonl... --skip ru-unreachable.txt > hostings.txt
    python -m ru_routing scan hostings.txt -o home.jsonl --jobs 20
    python tools/hostings.py report home.jsonl --abroad abroad-now.jsonl

Addresses are mapped to networks with the iptoasn.com table (public domain).
"""

import argparse
import bisect
import gzip
import ipaddress
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ru_routing import scan, sources

TABLE = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
FULL_PAGE = 100_000  # a scan reads 128 KB at most; a page this big shows a freeze at 16 KB


class Networks:
    def __init__(self, path):
        path = Path(path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(sources.download(TABLE))
        self.starts, self.rows = [], []
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                start, end, asn, country, name = line.rstrip("\n").split("\t")
                if asn != "0":
                    self.starts.append(int(ipaddress.ip_address(start)))
                    self.rows.append((int(ipaddress.ip_address(end)), int(asn), country, name))

    def lookup(self, ip):
        """(asn, country, name) for an address, or None."""
        n = int(ipaddress.ip_address(ip))
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.rows[i][0]:
            return self.rows[i][1:]
        return None


def skipped(host, names):
    parts = host.split(".")
    return any(".".join(parts[i:]) in names for i in range(len(parts)))


def pick(args):
    networks = Networks(args.table)
    names = set()
    for path in args.skip:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        names |= {line.split(":")[-1].strip() for line in lines if line.strip()}
    by_asn = defaultdict(dict)
    info = {}
    for host, r in scan.load(*args.abroad).items():
        if "://" in host or r["status"] != 200 or r["bytes"] < FULL_PAGE or not r.get("ip"):
            continue
        if host.endswith((".ru", ".su", ".xn--p1ai")) or skipped(host, names):
            continue  # a blocked name would hide what the network does
        found = networks.lookup(r["ip"])
        if not found or found[1] == "RU":
            continue
        subnet = r["ip"].rsplit(".", 1)[0]
        by_asn[found[0]].setdefault(subnet, []).append(host)
        info[found[0]] = found
    sizes = Counter({asn: sum(map(len, subnets.values())) for asn, subnets in by_asn.items()})
    wanted = [asn for asn, _ in sizes.most_common(args.networks)]
    wanted += [asn for asn in args.also if asn in sizes and asn not in wanted]
    for asn in wanted:
        total = sizes[asn]
        # one site per /24 first, so a network is not judged by a single address
        subnets = sorted(by_asn[asn].values(), key=len, reverse=True)
        chosen = []
        while len(chosen) < args.per_network and any(subnets):
            for hosts in subnets:
                if hosts and len(chosen) < args.per_network:
                    chosen.append(hosts.pop())
        print(f"# AS{asn} {info[asn][2]} ({info[asn][1]}): {total} sites")
        print("\n".join(chosen))


def report(args):
    networks = Networks(args.table)
    home, abroad = scan.load(*args.home), scan.load(*args.abroad)
    rows = defaultdict(Counter)
    stall = defaultdict(list)
    info = {}
    for host, r in home.items():
        a = abroad.get(host)
        ip = (a or {}).get("ip") or r.get("ip")
        found = networks.lookup(ip) if ip else None
        if not found:
            continue
        info[found[0]] = found
        verdict = scan.verdict(r, a)
        rows[found[0]][verdict] += 1
        if verdict == "throttled":
            stall[found[0]].append(r["bytes"])
    print("| Network | Sites | Works | Throttled | Blocked | Unknown | Freezes at | Verdict |")
    print("|---|---:|---:|---:|---:|---:|---:|---|")
    for asn, c in sorted(rows.items(), key=lambda x: -sum(x[1].values())):
        total = sum(c.values())
        known = total - c["unknown"]
        broken = c["throttled"] + c["blocked"] + c["geoblocked"]
        if known < 3:
            verdict = "too few answers"
        elif broken >= known * 0.7:
            verdict = "slowed down"
        elif broken <= known * 0.2:
            verdict = "works"
        else:
            verdict = "mixed"
        sizes = sorted(stall[asn])
        freeze = f"{sizes[len(sizes) // 2] // 1024} KB" if sizes else ""
        print(f"| AS{asn} {info[asn][2][:28]} ({info[asn][1]}) | {total} | {c['works']} | {c['throttled']} "
              f"| {c['blocked'] + c['geoblocked']} | {c['unknown']} | {freeze} | {verdict} |")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--table", default=".cache/ip2asn-v4.tsv.gz")
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("pick", help="choose sample sites for the biggest networks")
    p.add_argument("abroad", nargs="+", help="scans from abroad to pick sites from")
    p.add_argument("--skip", action="append", default=[], help="lists of names to leave out")
    p.add_argument("--networks", type=int, default=50)
    p.add_argument("--per-network", type=int, default=20)
    p.add_argument("--also", type=lambda s: [int(a) for a in s.split(",")], default=[],
                   help="more networks to sample, e.g. 20473,63949")
    p.set_defaults(func=pick)
    p = sub.add_parser("report", help="a table of networks from a home scan")
    p.add_argument("home", nargs="+")
    p.add_argument("--abroad", nargs="+", required=True)
    p.set_defaults(func=report)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
