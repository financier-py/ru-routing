"""Expanding categories: includes, excludes, attribute filters and ASNs."""

import ipaddress
import re
from typing import NamedTuple

from .rules import DOMAIN_KINDS, FormatError, Rule


class Origin(NamedTuple):
    where: str  # file and line, or the upstream list
    bulk: bool  # came only from a bulk list, so variants may trim it


def merge(out, rule, origin):
    """Add a rule, preferring an origin that is not bulk."""
    old = out.get(rule)
    if old is None or (old.bulk and not origin.bulk):
        out[rule] = origin


def excluder(excluded):
    """Predicate telling whether a rule is matched by one of the excluded rules."""
    exact = {(r.kind, r.value) for r in excluded}
    domains = {r.value for r in excluded if r.kind == "domain"}
    nets = [ipaddress.ip_network(r.value) for r in excluded if r.kind == "ip"]

    def hit(rule):
        if (rule.kind, rule.value) in exact:
            return True
        if rule.kind in ("domain", "full"):
            parts = rule.value.split(".")
            return any(".".join(parts[i:]) in domains for i in range(len(parts)))
        if rule.kind == "ip" and nets:
            net = ipaddress.ip_network(rule.value)
            return any(net.version == n.version and net.subnet_of(n) for n in nets)
        return False

    return hit


def matches(rule, target):
    """Does `rule` match a host name or an IP address?"""
    if rule.kind == "ip":
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(rule.value)
        except ValueError:
            return False
    if rule.kind == "domain":
        return target == rule.value or target.endswith("." + rule.value)
    if rule.kind == "full":
        return target == rule.value
    if rule.kind == "keyword":
        return rule.value in target
    if rule.kind == "regexp":
        return re.search(rule.value, target) is not None
    return False


def minimize(entries):
    """Drop duplicates and rules already matched by a broader domain or network."""
    unique = {}
    for rule, origin in entries.items():
        merge(unique, Rule(rule.kind, rule.value), origin)
    entries = unique
    domains = {r.value for r in entries if r.kind == "domain"}

    def redundant(rule):
        if rule.kind not in ("domain", "full"):
            return False
        parts = rule.value.split(".")
        parents = {".".join(parts[i:]) for i in range(1, len(parts))}
        return bool(parents & domains) or (rule.kind == "full" and rule.value in domains)

    kept = {r: w for r, w in entries.items() if not redundant(r)}
    nets = [ipaddress.ip_network(r.value) for r in kept if r.kind == "ip"]
    collapsed = {str(n) for v in (4, 6) for n in ipaddress.collapse_addresses(x for x in nets if x.version == v)}
    out = {r: w for r, w in kept.items() if r.kind != "ip" or r.value in collapsed}
    for value in collapsed - {r.value for r in out if r.kind == "ip"}:
        out[Rule("ip", value)] = Origin("merged", False)
    return out


class Resolver:
    def __init__(self, local, upstream):
        self.local = local  # name -> Category
        self.upstream = upstream  # Cache
        self._done = {}

    def _category(self, ref):
        namespace, _, name = ref.rpartition("/")
        if not namespace:
            if name not in self.local:
                raise KeyError(f"unknown category: {name}")
            return self.local[name]
        return self.upstream.category(namespace, name)

    def resolve(self, ref, _stack=()):
        """Map every rule of a category to the place it came from."""
        if ref in self._done:
            return self._done[ref]
        if ref in _stack:
            raise FormatError("include cycle: " + " -> ".join(_stack + (ref,)))
        category = self._category(ref)
        namespace, _, name = ref.rpartition("/")
        bulk = bool(namespace) and self.upstream.source(namespace).is_bulk(name)

        out = {}
        origins = {}  # one Origin per place, not per rule: lists can have millions of rules
        for rule, where in category.rules:
            if rule.kind == "asn":
                for prefix in self.upstream.asn(rule.value):
                    merge(out, Rule("ip", prefix, rule.attrs), Origin(f"{where} AS{rule.value}", bulk))
            else:
                origin = origins.get(where) or origins.setdefault(where, Origin(where, bulk))
                merge(out, rule, origin)

        excluded = []
        for link, where in category.links:
            # inside a v2fly list, `include:google` means v2fly/google
            target = link.target if "/" in link.target or not namespace else f"{namespace}/{link.target}"
            picked = {r: w for r, w in self.resolve(target, _stack + (ref,)).items() if link.accepts(r)}
            if link.op == "include":
                for rule, origin in picked.items():
                    merge(out, rule, origin)
            else:
                excluded.extend(picked)

        if excluded:
            hit = excluder(excluded)
            out = {r: w for r, w in out.items() if not hit(r)}
        if not namespace:  # upstream lists are included once, keeping them would only cost memory
            self._done[ref] = out
        return out


def _net_key(net):
    return net.version, net.network_address, net.prefixlen


def split(entries):
    domains = sorted(r for r in entries if r.kind in DOMAIN_KINDS)
    networks = sorted((r for r in entries if r.kind == "ip"), key=lambda r: _net_key(ipaddress.ip_network(r.value)))
    return domains, networks
