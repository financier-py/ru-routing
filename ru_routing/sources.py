"""Downloading and reading upstream lists.

Every download lands in the cache. A failed or suspiciously small download
keeps the previous copy, so one broken upstream never breaks the build.
"""

import datetime
import gzip
import http.client
import io
import ipaddress
import json
import socket
import tarfile
import tomllib
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import rules

USER_AGENT = "ru-routing"


@dataclass
class Source:
    name: str
    format: str
    homepage: str = ""
    license: str = ""
    url: str = ""
    countries: list[str] = field(default_factory=list)
    lists: dict[str, dict] = field(default_factory=dict)

    def is_bulk(self, list_name):
        return self.lists.get(list_name, {}).get("bulk", False)


def load_config(path):
    config = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return {name: Source(name, **spec) for name, spec in config.items()}


def download(url, timeout=300):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except http.client.HTTPException as e:  # a connection cut mid-file is not an OSError
        raise OSError(f"{type(e).__name__}: {e}") from e


def count_lines(data):
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return sum(1 for line in data.splitlines() if line.strip() and not line.startswith(b"#"))


def plain_domains(text):
    """Lists of bare domains come with all sorts of noise: comments, quotes, wildcards."""
    for line in io.StringIO(text):
        line = line.split("#", 1)[0].strip().strip('"').removeprefix("*.").lstrip(".")
        if line:
            yield line


def named_hosts(text):
    """no-russia-hosts lists a whole domain but names in a comment above it the
    hosts that actually refuse Russia: copilot.microsoft.com for microsoft.com.
    Where every comment line of a block is such a host, take those hosts."""
    named = []
    for line in io.StringIO(text):
        line = line.strip()
        if line.startswith("#"):
            words = line.lstrip("#").split()
            named.append(words[0].split("/")[0].lower() if words else "")
            continue
        domain = next(plain_domains(line), None)
        if domain:
            hosts = [h for h in named if h.endswith("." + domain) and h != "www." + domain]
            yield from hosts if named and len(hosts) == len(named) else [domain]
        named = []


def ripe_delegated(text, country):
    """Networks a RIR has delegated to a country, from its delegated-extended file."""
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 7 or parts[1] != country or parts[6] not in ("allocated", "assigned"):
            continue
        if parts[2] == "ipv4":
            first = ipaddress.IPv4Address(parts[3])
            yield from ipaddress.summarize_address_range(first, first + int(parts[4]) - 1)
        elif parts[2] == "ipv6":
            yield ipaddress.IPv6Network(f"{parts[3]}/{parts[4]}")


class Cache:
    def __init__(self, sources, root, offline=False):
        self.sources = sources
        self.root = Path(root)
        self.offline = offline
        self._warnings = []
        self._streamed = []
        self._archives = {}
        self._fetched = set()

    def _fetch(self, key, urls, minimum=1):
        path = self.root / key
        if not self.offline and key not in self._fetched:
            self._fetched.add(key)
            try:
                data = self._download_first(urls)
                n = count_lines(data)
                if n < minimum:
                    raise ValueError(f"only {n} entries, expected at least {minimum}")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            except (OSError, ValueError) as e:
                self._warnings.append(f"{key}: {e}; using the cached copy")
        if not path.exists():
            raise FileNotFoundError(f"{key}: not downloaded and no cached copy")
        return path.read_bytes()

    @staticmethod
    def _download_first(urls):
        if isinstance(urls, str):
            return download(urls)
        error = None
        for url in urls:
            try:
                return download(url)
            except OSError as e:
                error = e
        raise error

    def source(self, name):
        if name not in self.sources:
            raise KeyError(f"unknown source: {name}")
        return self.sources[name]

    def category(self, source_name, list_name):
        source = self.source(source_name)
        ref = f"{source_name}/{list_name}"
        if source.format == "v2fly":
            text = self._v2fly(source).get(list_name)
            if text is None:
                raise KeyError(f"{ref}: no such list in v2fly")
            return rules.parse(list_name, text, ref, strict=False)

        spec = source.lists.get(list_name)
        if spec is None:
            raise KeyError(f"unknown list: {ref}")
        text = self._fetch(ref, spec["url"], spec.get("min", 1)).decode("utf-8", "replace")
        if source.format == "domains":
            lines = named_hosts(text) if spec.get("narrow") else plain_domains(text)
        elif source.format == "cidr":
            lines = (f"ip:{line.strip()}" for line in io.StringIO(text) if line.strip())
        elif source.format == "ripe":
            lines = (f"ip:{net}" for net in ripe_delegated(text, spec["country"]))
        else:
            lines = io.StringIO(text)
        category = rules.stream(list_name, lines, ref)
        self._streamed.append((ref, category))
        return category

    @property
    def warnings(self):
        skipped = [f"{ref}: skipped {c.skipped} malformed lines" for ref, c in self._streamed if c.skipped]
        return self._warnings + skipped

    def _v2fly(self, source):
        if source.name not in self._archives:
            data = self._fetch(f"{source.name}.tar.gz", source.url)
            files = {}
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar:
                    parts = member.name.split("/")
                    if member.isfile() and len(parts) == 3 and parts[1] == "data":
                        files[parts[2]] = tar.extractfile(member).read().decode()
            self._archives[source.name] = files
        return self._archives[source.name]

    def asn(self, number):
        """Announced prefixes of an autonomous system, from RIPEstat."""
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{number}&sourceapp={USER_AGENT}"
        data = json.loads(self._fetch(f"asn/{number}.json", url))
        return sorted(p["prefix"] for p in data["data"]["prefixes"])

    def addresses(self, host):
        """Current IPv4 and IPv6 addresses of a name, for services that are reached
        by address (game servers, voice) and so can't be matched by domain.
        Offline builds reuse what the last online build saw."""
        path = self.root / "resolve" / host
        if not self.offline:
            try:
                found = sorted({a[4][0] for a in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("".join(f"{a}\n" for a in found))
            except OSError as e:
                self._warnings.append(f"resolve {host}: {e}; using the cached addresses")
        if not path.exists():
            raise FileNotFoundError(f"resolve {host}: no answer and no cached addresses")
        return [str(ipaddress.ip_network(a)) for a in path.read_text().split()]

    def ranks(self, name="crux", countries=None):
        """Yield (host, rank bucket) from the CrUX top lists of every configured country.

        A host shows up once per list it is in; the caller keeps the best rank.
        Monthly files appear a few weeks after the month ends, so try the last few."""
        source = self.source(name)
        for country in countries or source.countries:
            path = "global" if country == "global" else f"country/{country}"
            data = self._fetch(f"{name}/{country}.csv.gz", self._months(source.url, path))
            with gzip.open(io.BytesIO(data), "rt", encoding="utf-8") as lines:
                next(lines)  # header
                for line in lines:
                    origin, rank = line.rstrip().rsplit(",", 1)
                    yield origin.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0], int(rank)

    @staticmethod
    def _months(template, path, back=4):
        month = datetime.date.today().replace(day=1)
        urls = []
        for _ in range(back):
            month = (month - datetime.timedelta(days=1)).replace(day=1)
            urls.append(template.format(path=path, month=month.strftime("%Y%m")))
        return urls

    def fetch_all(self, asns=()):
        """Download everything sources.toml mentions, for a later --offline build."""
        jobs = []
        for source in self.sources.values():
            if source.format == "v2fly":
                jobs.append(lambda s=source: self._v2fly(s))
            elif source.format == "crux":
                jobs.append(lambda s=source: [None for _ in self.ranks(s.name)])
            else:
                for name, spec in source.lists.items():
                    jobs.append(lambda key=f"{source.name}/{name}", spec=spec: self._fetch(key, spec["url"], spec.get("min", 1)))
        jobs += [lambda n=n: self.asn(n) for n in asns]
        for job in jobs:  # one missing list should not stop the others
            try:
                job()
            except FileNotFoundError as e:
                self._warnings.append(str(e))
