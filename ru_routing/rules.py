"""Category file format.

A superset of v2fly/domain-list-community:

    # first comment block is the description
    youtube.com                  same as domain:youtube.com
    full:www.example.com
    keyword:example
    regexp:^ex(am)?ple\\.
    ip:91.108.4.0/22
    asn:62041
    resolve:mc.hypixel.net       the addresses this name has at build time
    include:other-category @attr @-attr
    include:v2fly/google @ads
    exclude:ip-check

`include:` and `exclude:` take a local category or `<source>/<list>`.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

DOMAIN_KINDS = ("domain", "full", "keyword", "regexp")
KINDS = DOMAIN_KINDS + ("ip", "asn", "resolve")

_label = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class FormatError(ValueError):
    pass


@dataclass(frozen=True, order=True, slots=True)
class Rule:
    kind: str
    value: str
    attrs: frozenset[str] = frozenset()

    def __str__(self):
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True)
class Link:
    op: str  # include or exclude
    target: str
    want: frozenset[str] = frozenset()
    drop: frozenset[str] = frozenset()

    def accepts(self, rule):
        return self.want <= rule.attrs and not self.drop & rule.attrs


@dataclass
class Category:
    name: str
    description: str = ""
    rules: list[tuple[Rule, str]] = field(default_factory=list)
    links: list[tuple[Link, str]] = field(default_factory=list)
    skipped: int = 0


def normalize_domain(value):
    value = value.strip().lower().rstrip(".")
    if not value.isascii():
        try:
            value = value.encode("idna").decode()
        except UnicodeError:
            raise FormatError(f"bad domain: {value}") from None
    if not all(_label.match(part) for part in value.split(".")):
        raise FormatError(f"bad domain: {value}")
    return value


def parse_rule(text, attrs=frozenset()):
    kind, sep, value = text.partition(":")
    if not sep or kind not in KINDS:
        kind, value = "domain", text
    if kind in ("domain", "full", "resolve"):
        value = normalize_domain(value)
    elif kind == "keyword":
        value = value.lower()
    elif kind == "regexp":
        try:
            re.compile(value)
        except re.error as e:
            raise FormatError(f"bad regexp: {e}") from None
    elif kind == "ip":
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise FormatError(f"bad network: {value}") from None
    elif kind == "asn":
        value = value.upper().removeprefix("AS")
        if not value.isdigit():
            raise FormatError(f"bad asn: {value}")
    return Rule(kind, value, attrs)


def parse_line(line):
    """Return a Rule, a Link or None for a blank line."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    head, *tail = line.split()
    stray = [t for t in tail if not t.startswith(("@", "&"))]
    if stray:
        raise FormatError(f"unexpected {stray[0]!r}")
    attrs = frozenset(t[1:] for t in tail if t.startswith("@") and not t.startswith("@-"))
    drop = frozenset(t[2:] for t in tail if t.startswith("@-"))
    # v2fly affiliations (&name) only matter for v2fly's own build
    if head.startswith(("include:", "exclude:")):
        op, target = head.split(":", 1)
        return Link(op, target, attrs, drop)
    if drop:
        raise FormatError("@-attr is only allowed after include: or exclude:")
    return parse_rule(head, attrs)


def parse(name, text, origin, strict=True, lines=True):
    """Parse a category file.

    strict=False counts and skips bad lines, which is what upstream lists need:
    one typo there should not stop the build. lines=False records only the list
    name as the origin, which saves a lot of memory on lists with millions of lines."""
    category = Category(name)
    description = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") and not category.rules and not category.links:
            description.append(stripped.lstrip("#").strip())
            continue
        try:
            item = parse_line(line)
        except FormatError as e:
            if strict:
                raise FormatError(f"{origin}:{n}: {e}") from None
            category.skipped += 1
            continue
        where = f"{origin}:{n}" if lines else origin
        if isinstance(item, Rule):
            category.rules.append((item, where))
        elif isinstance(item, Link):
            category.links.append((item, where))
    category.description = " ".join(d for d in description if d)
    return category


def load(path):
    path = Path(path)
    return parse(path.name, path.read_text(encoding="utf-8"), path.as_posix())
