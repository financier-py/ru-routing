import argparse
import sys
from pathlib import Path

from . import formats, rules, sources, variants
from .resolve import Resolver, matches, minimize, split


def load_local(data_dir):
    return {p.name: rules.load(p) for p in sorted(Path(data_dir).iterdir()) if p.is_file()}


def open_sources(args):
    return sources.Cache(sources.load_config(args.sources), args.cache, offline=args.offline)


def report(cache):
    for warning in cache.warnings:
        print("warning:", warning, file=sys.stderr)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def write_variant(out, chosen, mihomo):
    domains, networks = {}, {}
    for name, entries in chosen.items():
        domains[name], networks[name] = split(minimize(entries))

    write(out / "geosite.dat", formats.geosite(domains))
    write(out / "geoip.dat", formats.geoip({n: r for n, r in networks.items() if r}))
    for name in chosen:
        write(out / "text" / "geosite" / f"{name}.txt", formats.text(domains[name]))
        if networks[name]:
            write(out / "text" / "geoip" / f"{name}.txt", "".join(f"{r.value}\n" for r in networks[name]))
        if not mihomo:
            continue
        (out / "mihomo" / "geosite").mkdir(parents=True, exist_ok=True)
        (out / "mihomo" / "geoip").mkdir(parents=True, exist_ok=True)
        if domains[name]:
            formats.mrs(mihomo, "domain", formats.mihomo_domains(domains[name]), out / "mihomo" / "geosite" / f"{name}.mrs")
            if any(r.kind in ("keyword", "regexp") for r in domains[name]):
                write(out / "mihomo" / "geosite" / f"{name}.list", formats.mihomo_classical(domains[name]))
        if networks[name]:
            text = "".join(f"{r.value}\n" for r in networks[name])
            formats.mrs(mihomo, "ipcidr", text, out / "mihomo" / "geoip" / f"{name}.mrs")
    return {n: (len(domains[n]), len(networks[n])) for n in chosen}


def print_counts(names, plan, counts):
    """One row per category, one column per variant: domains, plus networks if any."""
    width = max(map(len, names)) + 2
    print("".ljust(width) + "".join(v.name.rjust(16) for v in plan))
    for name in names:
        cells = []
        for v in plan:
            d, n = counts[v.name].get(name, (None, 0))
            cell = "-" if d is None else f"{d}" + (f" + {n} ip" if n else "")
            cells.append(cell.rjust(16))
        print(name.ljust(width) + "".join(cells))


def build(args):
    cache = open_sources(args)
    resolver = Resolver(load_local(args.data), cache)
    resolved = {name: resolver.resolve(name) for name in resolver.local}
    plan = variants.load_config(args.variants)
    rank = {}
    if any(v.bulk != "all" for v in plan):
        rank = variants.popularity(variants.bulk_domains(resolved), cache.ranks())
    mihomo = formats.find_mihomo()
    if not mihomo:
        cache.warnings.append("mihomo not found (set MIHOMO or add it to PATH): skipping .mrs")

    counts = {}
    for variant in plan:
        chosen = variants.apply(variant, resolved, rank)
        counts[variant.name] = write_variant(Path(args.out) / variant.name, chosen, mihomo)

    print_counts(list(resolver.local), plan, counts)
    report(cache)


def fetch(args):
    cache = open_sources(args)
    asns = {r.value for c in load_local(args.data).values() for r, _ in c.rules if r.kind == "asn"}
    cache.fetch_all(sorted(asns))
    report(cache)


def why(args):
    cache = open_sources(args)
    resolver = Resolver(load_local(args.data), cache)
    target = args.target.lower().rstrip(".")
    found = False
    for name in resolver.local:
        hits = [(r, o) for r, o in resolver.resolve(name).items() if matches(r, target)]
        for rule, origin in sorted(hits):
            print(f"{name}: {rule}  ({origin.where})")
            found = True
    if not found:
        print(f"{target}: not in any category")
    report(cache)


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default="data")
    common.add_argument("--sources", default="sources.toml")
    common.add_argument("--cache", default=".cache")
    common.add_argument("--offline", action="store_true", help="use cached upstream lists only")

    parser = argparse.ArgumentParser(prog="ru_routing")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("build", parents=[common], help="build every variant into dist/")
    p.add_argument("--variants", default="variants.toml")
    p.add_argument("-o", "--out", default="dist")
    p.set_defaults(func=build)

    p = sub.add_parser("fetch", parents=[common], help="download upstream lists into the cache")
    p.set_defaults(func=fetch)

    p = sub.add_parser("why", parents=[common], help="show which categories match a domain or an IP")
    p.add_argument("target")
    p.set_defaults(func=why)

    args = parser.parse_args()
    try:
        args.func(args)
    except (rules.FormatError, KeyError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
