"""Checks on built lists: expectations from checks.txt and diffs between builds."""

import ipaddress
import re
from pathlib import Path


class Lists:
    """Text lists of one variant, loaded for lookups."""

    def __init__(self, variant):
        self.domains, self.full, self.keywords, self.regexps, self.networks = {}, {}, {}, {}, {}
        for path in sorted(Path(variant, "text", "geosite").glob("*.txt")):
            name = path.stem
            self.domains[name], self.full[name] = set(), set()
            self.keywords[name], self.regexps[name] = [], []
            for line in path.read_text().splitlines():
                kind, _, value = line.partition(":")
                if kind == "domain":
                    self.domains[name].add(value)
                elif kind == "full":
                    self.full[name].add(value)
                elif kind == "keyword":
                    self.keywords[name].append(value)
                elif kind == "regexp":
                    self.regexps[name].append(re.compile(value))
        for path in sorted(Path(variant, "text", "geoip").glob("*.txt")):
            self.networks[path.stem] = [ipaddress.ip_network(line) for line in path.read_text().split()]

    @property
    def names(self):
        return set(self.domains) | set(self.networks)

    def contains(self, name, target):
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            parts = target.split(".")
            suffixes = {".".join(parts[i:]) for i in range(len(parts))}
            return bool(suffixes & self.domains.get(name, set())
                        or target in self.full.get(name, ())
                        or any(k in target for k in self.keywords.get(name, ()))
                        or any(r.search(target) for r in self.regexps.get(name, ())))
        return any(address in net for net in self.networks.get(name, ()))


def load_checks(path):
    """Lines of `target  category !category ...`."""
    checks = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.split("#", 1)[0].split()
        if line:
            checks.append((n, line[0].lower(), line[1:]))
    return checks


def check(variant, checks):
    """Return a list of failed expectations for one built variant."""
    lists = Lists(variant)
    failures = []
    for n, target, wants in checks:
        for want in wants:
            name = want.lstrip("!")
            if name not in lists.names:
                continue  # a variant may skip a category
            if lists.contains(name, target) != (not want.startswith("!")):
                verb = "should not be" if want.startswith("!") else "is not"
                failures.append(f"checks.txt:{n}: {target} {verb} in {name}")
    return failures


def diff(old, new, sample=5):
    """Yield one line per changed list: counts and a few examples."""
    old, new = Path(old), Path(new)
    files = {p.relative_to(old) for p in old.rglob("text/**/*.txt")} | {p.relative_to(new) for p in new.rglob("text/**/*.txt")}
    for rel in sorted(files):
        before = set((old / rel).read_text().splitlines()) if (old / rel).exists() else set()
        after = set((new / rel).read_text().splitlines()) if (new / rel).exists() else set()
        added, removed = sorted(after - before), sorted(before - after)
        if added or removed:
            examples = ", ".join([f"+{x}" for x in added[:sample]] + [f"-{x}" for x in removed[:sample]])
            yield f"{rel}: +{len(added)} -{len(removed)}  {examples}"
