"""Downloading and reading upstream lists.

Every download lands in the cache. A failed or suspiciously small download
keeps the previous copy, so one broken upstream never breaks the build.
"""

import io
import json
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
    license: str
    homepage: str = ""
    url: str = ""
    lists: dict[str, dict] = field(default_factory=dict)


def load_config(path):
    config = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return {name: Source(name, **spec) for name, spec in config.items()}


def download(url, timeout=120):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


class Cache:
    def __init__(self, sources, root, offline=False):
        self.sources = sources
        self.root = Path(root)
        self.offline = offline
        self.warnings = []
        self._archives = {}

    def _fetch(self, key, url, check=None):
        path = self.root / key
        if not self.offline:
            try:
                data = download(url)
                if check:
                    check(data)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            except (OSError, ValueError) as e:
                self.warnings.append(f"{key}: {e}, using cached copy")
        if not path.exists():
            raise FileNotFoundError(f"{key}: not downloaded and no cached copy")
        return path.read_bytes()

    def category(self, source_name, list_name):
        source = self.sources.get(source_name)
        if source is None:
            raise KeyError(f"unknown source: {source_name}")
        ref = f"{source_name}/{list_name}"
        if source.format == "v2fly":
            text = self._v2fly(source).get(list_name)
            if text is None:
                raise KeyError(f"{ref}: no such list in v2fly")
            return rules.parse(list_name, text, ref)

        spec = source.lists.get(list_name)
        if spec is None:
            raise KeyError(f"unknown list: {ref}")

        def check(data):
            n = sum(1 for line in data.splitlines() if line.strip() and not line.startswith(b"#"))
            if n < spec.get("min", 1):
                raise ValueError(f"only {n} entries")

        text = self._fetch(f"{source_name}/{list_name}", spec["url"], check).decode()
        if source.format == "cidr":
            text = "\n".join(f"ip:{line.strip()}" for line in text.splitlines() if line.strip())
        return rules.parse(list_name, text, ref)

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
        """Announced IPv4 and IPv6 prefixes of an autonomous system, from RIPEstat."""
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{number}&sourceapp={USER_AGENT}"
        data = json.loads(self._fetch(f"asn/{number}.json", url))
        return sorted(p["prefix"] for p in data["data"]["prefixes"])
