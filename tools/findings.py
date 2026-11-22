"""Turn scan results into the scan-broken and scan-working categories.

    python tools/findings.py --home first.jsonl --home second.jsonl --abroad se.jsonl --abroad fi.jsonl

A host counts only if every home scan agrees: broken in all of them (and fine
abroad), or working in all of them. One flaky connection should not move a site.
Pages and the resources they load are both looked at.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ru_routing import probe, scan, verify

BROKEN = ("blocked", "throttled", "geoblocked")

# Hosting and CDN zones shared by unrelated sites: list the host, never the zone.
SHARED = ("cloudfront.net", "amazonaws.com", "azureedge.net", "azurefd.net", "azurewebsites.net", "akamaized.net",
          "akamaihd.net", "edgekey.net", "fastly.net", "fastlylb.net", "googleusercontent.com", "appspot.com",
          "firebaseapp.com", "web.app", "github.io", "githubusercontent.com", "vercel.app", "netlify.app",
          "pages.dev", "workers.dev", "herokuapp.com", "onrender.com", "fly.dev", "b-cdn.net", "r2.dev",
          "cdn77.org", "jsdelivr.net", "blogspot.com", "wordpress.com", "tumblr.com", "substack.com",
          "myshopify.com", "wixsite.com", "webflow.io", "gitbook.io", "notion.site", "readthedocs.io")

HEADER = {
    "scan-broken": """# Sites that don't open from a Russian home connection but do from abroad:
# blocked, throttled or geoblocked. Each one failed in every home scan and
# loaded abroad. Written by tools/findings.py, don't edit by hand.
""",
    "scan-working": """# Sites on block lists that open fine from a Russian home connection, in every
# home scan. Written by tools/findings.py, don't edit by hand.
""",
}


def rule(host):
    if any(host == z or host.endswith("." + z) for z in SHARED):
        return f"full:{host}"
    return host.removeprefix("www.")


def verdicts(home, abroad):
    """host -> verdict for pages and for the resources they pull in."""
    out = {host: scan.verdict(record, abroad.get(host)) for host, record in home.items()}
    pages = {probe.split_target(h)[0]: v for h, v in out.items()}
    resources, _ = scan.resource_verdicts(home, abroad)
    return {**resources, **pages}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--home", action="append", required=True)
    parser.add_argument("--abroad", action="append", required=True)
    parser.add_argument("--data", default="data")
    parser.add_argument("--lists", default="dist/full", help="a build to tell which sites are on block lists")
    args = parser.parse_args()

    listed = verify.Lists(args.lists)
    abroad = scan.load(*args.abroad)
    runs = [verdicts(scan.load(path), abroad) for path in args.home]
    hosts = set.intersection(*(set(r) for r in runs))
    found = {"scan-broken": set(), "scan-working": set()}
    for host in hosts:
        seen = [r[host] for r in runs]
        if all(v in BROKEN for v in seen):
            found["scan-broken"].add(rule(host))
        elif all(v == "works" for v in seen) and listed.contains("ru-unreachable", host):
            found["scan-working"].add(rule(host))
    for name, rules in found.items():
        Path(args.data, name).write_text(HEADER[name] + "\n" + "".join(f"{r}\n" for r in sorted(rules)), encoding="utf-8")
        print(name, len(rules))


if __name__ == "__main__":
    main()
