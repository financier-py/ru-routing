"""Variants: the same categories, with bulk lists cut down to a size.

Bulk lists (the full registry and the like) hold millions of domains, most of
which nobody opens. A variant keeps every curated entry and takes bulk entries
in order of popularity in Russia, as seen by Chrome (CrUX), until its limit.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

UNRANKED = 10**7


@dataclass
class Variant:
    name: str
    description: str = ""
    bulk: int | str = "all"  # a number, "popular" or "all"
    skip: list[str] = field(default_factory=list)


def load_config(path):
    config = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return [Variant(name, **spec) for name, spec in config.items()]


def popularity(values, ranks):
    """Best rank of any visited host under each domain.

    `ranks` is an iterable of (host, rank). Each host's suffixes are checked once,
    so the cost depends on the number of ranked hosts, not on the size of the lists."""
    wanted = set(values)
    best = {}
    for host, rank in ranks:
        parts = host.split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            if suffix in wanted and rank < best.get(suffix, UNRANKED):
                best[suffix] = rank
    return best


def bulk_domains(categories):
    return {r.value for entries in categories.values() for r, o in entries.items() if o.bulk}


def apply(variant, categories, rank):
    """Cut bulk entries of every category down to what the variant allows.

    `categories` maps a name to {Rule: Origin}, and so does the result. `rank` holds
    the popularity of bulk domains (see `popularity`); unranked ones nobody visits.
    The limit is shared by all categories, so a domain that sits in several of them
    counts once and is kept or dropped everywhere."""
    categories = {n: e for n, e in categories.items() if n not in variant.skip}
    if variant.bulk == "all":
        return categories

    bulk = {r for entries in categories.values() for r, o in entries.items() if o.bulk}
    ordered = sorted((r for r in bulk if r.value in rank), key=lambda r: (rank[r.value], r.value))
    if variant.bulk != "popular":
        ordered = ordered[: variant.bulk]
    keep = set(ordered)
    return {n: {r: o for r, o in e.items() if not o.bulk or r in keep} for n, e in categories.items()}
