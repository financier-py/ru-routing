"""Checking from Russia which sites open and which don't.

A scan only records what happened. Whether a site is broken is decided later
by comparing with the same scan made from abroad (see `verdicts`): a page that
fails at home but loads abroad is blocked, throttled or geoblocked.
"""

import json
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import probe

# Cloudflare answers /cdn-cgi/trace on every site it serves, with the country it sees.
# One plain site and a few that a split-tunnel VPN would route through the tunnel.
TRACE_SITES = ["www.cloudflare.com", "chatgpt.com", "discord.com", "rutracker.org"]


def exit_countries(interface=None, resolver=None):
    """Country Cloudflare sees for each trace site; None where it didn't answer."""
    out = {}
    for host in TRACE_SITES:
        sock = None
        try:
            sock, _ = probe.connect(host, 443, interface, resolver)
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := sock.recv(4096):
                data += chunk
            out[host] = next((line[4:] for line in data.decode(errors="replace").splitlines()
                              if line.startswith("loc=")), None)
        except OSError:
            out[host] = None
        finally:
            if sock:
                sock.close()
    return out


def check_no_vpn(interface=None, resolver=None):
    """Refuse to scan through a VPN: the results would say everything works."""
    seen = exit_countries(interface, resolver)
    foreign = {h: c for h, c in seen.items() if c and c != "RU"}
    if foreign:
        sys.exit("A VPN seems to be on: Cloudflare sees you in "
                 + ", ".join(f"{c} ({h})" for h, c in foreign.items())
                 + ". Turn it off completely and run again.")
    if "RU" not in seen.values():
        print("warning: could not confirm the exit country, going on anyway", file=sys.stderr)


def load_targets(path, limit=None):
    """One host per line; an optional leading rank is ignored. Order is kept."""
    hosts = []
    for line in Path(path).read_text().splitlines():
        parts = line.split("#", 1)[0].split()
        if parts:
            hosts.append(parts[-1].lower())
    return hosts[:limit]


def run(targets, out, jobs=64, interface=None, resolver=None):
    """Probe every target not already in `out`, appending one JSON line per host."""
    out = Path(out)
    done = set()
    if out.exists():
        done = {json.loads(line)["host"] for line in out.read_text().splitlines() if line.strip()}
    todo = [t for t in targets if t not in done]
    print(f"{len(todo)} to check, {len(done)} already done", file=sys.stderr)
    with out.open("a") as f, ThreadPoolExecutor(jobs) as pool:
        futures = [pool.submit(probe.fetch, host, interface, resolver) for host in todo]
        for n, future in enumerate(as_completed(futures), 1):
            f.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
            if n % 500 == 0:
                f.flush()
                print(f"{n}/{len(todo)}", file=sys.stderr)


def load(path):
    return {r["host"]: r for r in map(json.loads, Path(path).read_text().splitlines()) if r}


def verdict(home, abroad):
    """Compare one host as seen from Russia and from abroad."""
    if not abroad or abroad["status"] is None or abroad["status"] >= 500 or "challenge" in abroad.get("marks", []):
        return "unknown"  # no good page abroad either: dead, broken or behind a bot check
    if home["status"] is None:
        if home["stage"] == "body" and 0 < home["bytes"] < abroad["bytes"]:
            return "throttled"
        return "blocked"
    marks = home.get("marks", [])
    if "block" in marks:
        return "blocked"
    if "challenge" in marks:
        return "unknown"
    if ("geo" in marks and "geo" not in abroad.get("marks", [])) or (
            home["status"] in (403, 451) and abroad["status"] == 200):
        return "geoblocked"
    return "works"


def verdicts(home_path, abroad_path):
    home, abroad = load(home_path), load(abroad_path)
    return {host: verdict(record, abroad.get(host)) for host, record in home.items()}
