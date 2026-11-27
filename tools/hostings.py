"""Which hosting networks are slowed down from Russia.

Blocking by address hits whole networks at once: a site on a throttled
hosting freezes after the first few kilobytes, whatever its name. So hostings
are checked by sample: sites that load fully from abroad are grouped by the
network (ASN) of their address, and a few from each network are scanned from
home like any other target.

    python tools/hostings.py pick abroad.jsonl... --skip ru-unreachable.txt > hostings.txt
    python -m ru_routing scan hostings.txt -o home.jsonl --jobs 20
    python tools/hostings.py report home.jsonl --abroad abroad-now.jsonl

To go down to single /24 subnets, start from a big list of sites instead:
resolve it abroad, take a few names per subnet, scan those abroad to find the
ones that give a full page, and pick from that scan with --per-subnet.

    python tools/hostings.py resolve top-1m.txt > resolved.tsv
    python tools/hostings.py spread resolved.tsv --skip ru-unreachable.txt > candidates.txt

Addresses are mapped to networks with the iptoasn.com table (public domain).
"""

import argparse
import bisect
import gzip
import ipaddress
import socket
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ru_routing import scan, sources

TABLE = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
FULL_PAGE = 100_000
SLOWED_HEADER = """# Hosting networks where pages freeze after the first 15 KB or so from a Russian
# home connection, while abroad they load in full. A /24 is listed when most of
# the sites sampled in it froze in every home scan. Blocking here also depends on
# the site, so a few sites in these networks still work. Written by
# tools/hostings.py report --subnets --slowed, don't edit by hand.
"""  # a scan reads 128 KB at most; a page this big shows a freeze at 16 KB


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


def address(host):
    try:
        return socket.gethostbyname(host)
    except (OSError, UnicodeError):
        return None


def resolve(args):
    """In chunks: pool.map over a million names would queue them all at once."""
    hosts = scan.load_targets(args.sites)
    with ThreadPoolExecutor(args.jobs) as pool:
        for start in range(0, len(hosts), 10_000):
            chunk = hosts[start:start + 10_000]
            for host, ip in zip(chunk, pool.map(address, chunk)):
                if ip:
                    print(f"{host}\t{ip}")
            sys.stdout.flush()


def skip_names(paths):
    names = set()
    for path in paths:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        names |= {line.split(":")[-1].strip() for line in lines if line.strip()}
    return names


def wanted(host, names):
    """Russian zones and blocked names would hide what the network does."""
    return not host.endswith((".ru", ".su", ".xn--p1ai")) and not skipped(host, names)


def spread(args):
    """A few names from every /24 of the chosen networks, busiest subnets first."""
    networks = Networks(args.table)
    names = skip_names(args.skip)
    subnets = defaultdict(lambda: defaultdict(list))
    for line in Path(args.resolved).read_text(encoding="utf-8").splitlines():
        host, ip = line.split("\t")
        found = networks.lookup(ip)
        if not found or found[1] == "RU" or (args.asn and found[0] not in args.asn) or not wanted(host, names):
            continue
        subnets[found[0]][ip.rsplit(".", 1)[0]].append(host)
    for asn, by_subnet in subnets.items():
        busiest = sorted(by_subnet.values(), key=len, reverse=True)[:args.max_subnets]
        print(f"# AS{asn}: {len(busiest)} of {len(by_subnet)} subnets")
        print("\n".join(h for hosts in busiest for h in hosts[:args.per_subnet]))


def skipped(host, names):
    parts = host.split(".")
    return any(".".join(parts[i:]) in names for i in range(len(parts)))


def pick(args):
    networks = Networks(args.table)
    names = skip_names(args.skip)
    by_asn = defaultdict(dict)
    info = {}
    for host, r in scan.load(*args.abroad).items():
        if "://" in host or r["status"] != 200 or r.get("error") or r["bytes"] < FULL_PAGE or not r.get("ip"):
            continue
        if not wanted(host, names):
            continue
        found = networks.lookup(r["ip"])
        if not found or found[1] == "RU":
            continue
        subnet = r["ip"].rsplit(".", 1)[0]
        by_asn[found[0]].setdefault(subnet, []).append(host)
        info[found[0]] = found
    sizes = Counter({asn: sum(map(len, subnets.values())) for asn, subnets in by_asn.items()})
    if args.per_subnet:
        for asn, subnets in sorted(by_asn.items(), key=lambda x: -sizes[x[0]]):
            print(f"# AS{asn} {info[asn][2]} ({info[asn][1]}): {len(subnets)} subnets")
            print("\n".join(h for hosts in subnets.values() for h in hosts[:args.per_subnet]))
        return
    chosen_asns = [asn for asn, _ in sizes.most_common(args.networks)]
    chosen_asns += [asn for asn in args.also if asn in sizes and asn not in chosen_asns]
    for asn in chosen_asns:
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
    """One file per home pass. A site counts only where every pass agrees;
    a site that froze once and loaded once is "unstable", not slowed down."""
    networks = Networks(args.table)
    passes, abroad = [scan.records(p) for p in args.home], scan.load(*args.abroad)
    rows = defaultdict(Counter)
    stall = defaultdict(list)
    info = {}
    for host in set.intersection(*(set(p) for p in passes)):
        a = abroad.get(host)
        ip = (a or {}).get("ip") or passes[0][host].get("ip")
        found = networks.lookup(ip) if ip else None
        if not found:
            continue
        key = ip.rsplit(".", 1)[0] + ".0/24" if args.subnets else found[0]
        info[key] = found
        verdicts = {scan.verdict(p[host], a) for p in passes}
        verdict = verdicts.pop() if len(verdicts) == 1 else "unstable"
        rows[key][verdict] += 1
        if verdict == "throttled":
            stall[key].extend(p[host]["bytes"] for p in passes)
    table = []
    for asn, c in sorted(rows.items(), key=lambda x: -sum(x[1].values())):
        total = sum(c.values())
        known = total - c["unknown"] - c["unstable"]
        broken = c["throttled"] + c["blocked"] + c["geoblocked"]
        if known < (2 if args.subnets else 3):
            verdict = "too few answers"
        elif broken >= known * 0.7:
            verdict = "slowed down"
        elif broken <= known * 0.2:
            verdict = "works"
        else:
            verdict = "mixed"
        sizes = sorted(stall[asn])
        freeze = f"{sizes[len(sizes) // 2] // 1024} KB" if sizes else ""
        name = f"{asn} AS{info[asn][0]}" if args.subnets else f"AS{asn}"
        row = (f"| {name} {info[asn][2][:28]} ({info[asn][1]}) | {total} | {c['works']} | {c['throttled']} "
               f"| {c['blocked'] + c['geoblocked']} | {c['unstable']} | {c['unknown']} | {freeze} | {verdict} |")
        table.append((asn, verdict, row))
    if args.slowed:
        print(SLOWED_HEADER)
        print("\n".join(f"ip:{key}" for key, verdict, _ in sorted(table, key=lambda x: ipaddress.ip_network(x[0]))
                        if verdict == "slowed down"))
        return
    print("| Network | Sites | Works | Throttled | Blocked | Unstable | Unknown | Freezes at | Verdict |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    print("\n".join(row for _, _, row in table))


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
    p.add_argument("--per-subnet", type=int, help="every /24 instead: this many sites from each")
    p.set_defaults(func=pick)
    p = sub.add_parser("resolve", help="the address of every site in a list, as host<TAB>ip")
    p.add_argument("sites")
    p.add_argument("--jobs", type=int, default=128)
    p.set_defaults(func=resolve)
    p = sub.add_parser("spread", help="a few names from every /24 of a resolved list")
    p.add_argument("resolved")
    p.add_argument("--skip", action="append", default=[])
    p.add_argument("--per-subnet", type=int, default=3)
    p.add_argument("--max-subnets", type=int, default=1500, help="per network")
    p.add_argument("--asn", type=lambda s: {int(a) for a in s.split(",")}, help="only these networks")
    p.set_defaults(func=spread)
    p = sub.add_parser("report", help="a table of networks from a home scan")
    p.add_argument("home", nargs="+", help="one file per home pass")
    p.add_argument("--abroad", nargs="+", required=True)
    p.add_argument("--subnets", action="store_true", help="one row per /24 instead of per network")
    p.add_argument("--slowed", action="store_true", help="only the /24s that are slowed down, as a category file")
    p.set_defaults(func=report)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
