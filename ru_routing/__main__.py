import argparse
import sys
from pathlib import Path

from . import rules, sources
from .resolve import Resolver, matches, minimize, split


def load_local(data_dir):
    return {p.name: rules.load(p) for p in sorted(Path(data_dir).iterdir()) if p.is_file()}


def make_resolver(args):
    cache = sources.Cache(sources.load_config(args.sources), args.cache, offline=args.offline)
    return Resolver(load_local(args.data), cache), cache


def build(args):
    resolver, cache = make_resolver(args)
    out = Path(args.out)
    (out / "geosite").mkdir(parents=True, exist_ok=True)
    (out / "geoip").mkdir(parents=True, exist_ok=True)
    width = max(map(len, resolver.local))
    for name in resolver.local:
        domains, networks = split(minimize(resolver.resolve(name)))
        (out / "geosite" / f"{name}.txt").write_text("".join(f"{r}\n" for r in domains))
        if networks:
            (out / "geoip" / f"{name}.txt").write_text("".join(f"{r.value}\n" for r in networks))
        print(f"{name:<{width}}  {len(domains):>8} domains  {len(networks):>6} networks")
    for warning in cache.warnings:
        print("warning:", warning, file=sys.stderr)


def why(args):
    resolver, _ = make_resolver(args)
    target = args.target.lower().rstrip(".")
    found = False
    for name in resolver.local:
        hits = [(r, w) for r, w in resolver.resolve(name).items() if matches(r, target)]
        for rule, where in sorted(hits):
            print(f"{name}: {rule}  ({where})")
            found = True
    if not found:
        print(f"{target}: not in any category")


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data", default="data")
    common.add_argument("--sources", default="sources.toml")
    common.add_argument("--cache", default=".cache")
    common.add_argument("--offline", action="store_true", help="use cached upstream lists only")

    parser = argparse.ArgumentParser(prog="ru_routing")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("build", parents=[common], help="expand every category into plain lists")
    p.add_argument("-o", "--out", default="dist")
    p.set_defaults(func=build)

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
