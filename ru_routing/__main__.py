import argparse
import shutil
import sys
from pathlib import Path

from . import browse, direct, formats, probe, rules, scan, sources, variants, verify
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
    """Write one variant, a category at a time: .dat files are just entries one
    after another, so nothing has to hold every category at once."""
    for old in ("text", "mihomo"):  # a category the variant no longer has must not linger
        shutil.rmtree(out / old, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    counts = {}
    with open(out / "geosite.dat", "wb") as geosite, open(out / "geoip.dat", "wb") as geoip:
        for name in sorted(chosen):
            domains, networks = split(minimize(chosen[name]))
            counts[name] = (len(domains), len(networks))
            geosite.write(formats.geosite({name: domains}))
            write(out / "text" / "geosite" / f"{name}.txt", formats.text(domains))
            if networks:
                geoip.write(formats.geoip({name: networks}))
                write(out / "text" / "geoip" / f"{name}.txt", "".join(f"{r.value}\n" for r in networks))
            if mihomo:
                write_mihomo(out / "mihomo", name, domains, networks, mihomo)
    return counts


def write_mihomo(out, name, domains, networks, binary):
    (out / "geosite").mkdir(parents=True, exist_ok=True)
    (out / "geoip").mkdir(parents=True, exist_ok=True)
    if domains:
        formats.mrs(binary, "domain", formats.mihomo_domains(domains), out / "geosite" / f"{name}.mrs")
        if any(r.kind in ("keyword", "regexp") for r in domains):
            write(out / "geosite" / f"{name}.list", formats.mihomo_classical(domains))
    if networks:
        formats.mrs(binary, "ipcidr", "".join(f"{r.value}\n" for r in networks), out / "geoip" / f"{name}.mrs")


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
    plan = [v for v in variants.load_config(args.variants) if not args.only or v.name in args.only.split(",")]
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
    local = [r for c in load_local(args.data).values() for r, _ in c.rules]
    cache.fetch_all(sorted({r.value for r in local if r.kind == "asn"}))
    for host in sorted({r.value for r in local if r.kind == "resolve"}):
        cache.addresses(host)
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


def check(args):
    checks = verify.load_checks(args.checks)
    failed = 0
    for variant in sorted(p for p in Path(args.dist).iterdir() if p.is_dir()):
        failures = verify.check(variant, checks)
        failed += len(failures)
        print(f"{variant.name}: {len(checks)} checks, {len(failures)} failed")
        for failure in failures:
            print("  " + failure)
    if failed:
        sys.exit(1)


def diff(args):
    for line in verify.diff(args.old, args.new):
        print(line)


def run_scan(args):
    route = direct.Direct(interface=args.interface or "", dns=args.dns or "") if args.interface else None
    if args.no_vpn_check:
        resolver = probe.resolve_via(args.dns, route) if args.dns else None
    else:
        route, resolver = scan.prepare(route)
    direct.keep_awake()
    scan.run(scan.load_targets(args.targets, args.limit), args.out, args.jobs, route, resolver)


def run_verdicts(args):
    pages, resources, unchecked = scan.verdicts(args.home, *args.abroad)
    found = dict(pages)
    for host, v in resources.items():
        if v != "works":
            found.setdefault(host, v)
    counts = {}
    for v in found.values():
        counts[v] = counts.get(v, 0) + 1
    print(", ".join(f"{v}: {n}" for v, n in sorted(counts.items(), key=lambda x: -x[1])))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for kind in ("blocked", "throttled", "geoblocked", "works"):
        (out / f"{kind}.txt").write_text("".join(f"{h}\n" for h, v in sorted(found.items()) if v == kind), encoding="utf-8")
    if unchecked:
        (out / "recheck.txt").write_text("".join(f"{u}\n" for u in sorted(unchecked)), encoding="utf-8")
        print(f"{len(unchecked)} resources failed at home with nothing to compare abroad: "
              f"scan {out / 'recheck.txt'} abroad and pass it as one more abroad file")


def run_browse(args):
    browse.run(scan.load_targets(args.targets, args.limit), args.out, args.jobs, args.proxy, args.browser)


def run_browse_verdicts(args):
    home, abroad = scan.records(args.home), scan.load(*args.abroad)
    pages, hosts = {}, {}
    for site, record in home.items():
        page, broken = browse.compare(record, abroad.get(site))
        pages[site] = page
        for host in broken:
            hosts.setdefault(host, []).append(site)
    counts = {}
    for v in pages.values():
        counts[v] = counts.get(v, 0) + 1
    print(", ".join(f"{v}: {n}" for v, n in sorted(counts.items(), key=lambda x: -x[1])))
    print(f"{len(hosts)} hosts broken at home on {sum(map(len, hosts.values()))} pages")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "pages.txt").write_text("".join(f"{s} {v}\n" for s, v in sorted(pages.items())), encoding="utf-8")
    (out / "hosts.txt").write_text("".join(f"{h} {' '.join(sorted(s))}\n" for h, s in sorted(hosts.items())),
                                   encoding="utf-8")


def readme(args):
    """Rewrite the category table in README.md from the descriptions in data/."""
    rows = []
    for name, category in load_local(args.data).items():
        first = category.description.split(". ")[0].rstrip(".")
        rows.append(f"| `{name}` | {first} |")
    table = "| Category | Contents |\n|---|---|\n" + "\n".join(rows) + "\n"
    path = Path("README.md")
    text = path.read_text(encoding="utf-8")
    start, end = "<!-- categories -->\n", "<!-- /categories -->"
    head, rest = text.split(start, 1)
    path.write_text(head + start + table + end + rest.split(end, 1)[1], encoding="utf-8")


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
    p.add_argument("--only", help="comma-separated variants to build, e.g. lite,full")
    p.add_argument("-o", "--out", default="dist")
    p.set_defaults(func=build)

    p = sub.add_parser("fetch", parents=[common], help="download upstream lists into the cache")
    p.set_defaults(func=fetch)

    p = sub.add_parser("why", parents=[common], help="show which categories match a domain or an IP")
    p.add_argument("target")
    p.set_defaults(func=why)

    p = sub.add_parser("readme", parents=[common], help="update the category table in README.md")
    p.set_defaults(func=readme)

    p = sub.add_parser("check", help="run checks.txt against every built variant")
    p.add_argument("--checks", default="checks.txt")
    p.add_argument("dist", nargs="?", default="dist")
    p.set_defaults(func=check)

    p = sub.add_parser("diff", help="compare two builds")
    p.add_argument("old")
    p.add_argument("new")
    p.set_defaults(func=diff)

    p = sub.add_parser("scan", help="check from Russia which sites open")
    p.add_argument("targets", help="file with one host per line, most important first")
    p.add_argument("-o", "--out", default="scan.jsonl")
    p.add_argument("--jobs", type=int, default=64)
    p.add_argument("--limit", type=int, help="check only the first N hosts")
    p.add_argument("--interface", help="go out through this interface instead of finding one")
    p.add_argument("--dns", help="DNS server to use with --interface")
    p.add_argument("--no-vpn-check", action="store_true")
    p.set_defaults(func=run_scan)

    p = sub.add_parser("browse", help="open sites in a browser and note every host they use")
    p.add_argument("targets")
    p.add_argument("-o", "--out", default="browse.jsonl")
    p.add_argument("--jobs", type=int, default=4, help="pages open at once")
    p.add_argument("--limit", type=int)
    p.add_argument("--proxy", help="e.g. socks5://127.0.0.1:1080 for the run from abroad")
    p.add_argument("--browser", help="path to Chrome or Chromium instead of the one Playwright installs")
    p.set_defaults(func=run_browse)

    p = sub.add_parser("browse-verdicts", help="compare browser visits from Russia and from abroad")
    p.add_argument("home")
    p.add_argument("abroad", nargs="+")
    p.add_argument("-o", "--out", default="findings-browser")
    p.set_defaults(func=run_browse_verdicts)

    p = sub.add_parser("verdicts", help="compare a scan from Russia with one from abroad")
    p.add_argument("home")
    p.add_argument("abroad", nargs="+")
    p.add_argument("-o", "--out", default="findings")
    p.set_defaults(func=run_verdicts)

    args = parser.parse_args()
    try:
        args.func(args)
    except (rules.FormatError, KeyError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
