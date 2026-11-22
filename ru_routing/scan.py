"""Checking from Russia which sites open and which don't.

A scan only records what happened. Whether a site is broken is decided later
by comparing with the same scan made from abroad (see `verdicts`): a page that
fails at home but loads abroad is blocked, throttled or geoblocked.
"""

import json
import ssl
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from . import direct, probe

# Cloudflare answers /cdn-cgi/trace on every site it serves, with the country it sees.
# One plain site and a few that a split-tunnel VPN would route through the tunnel.
TRACE_SITES = ["www.cloudflare.com", "chatgpt.com", "discord.com", "rutracker.org"]


def exit_countries(route=None, resolver=None):
    """Country Cloudflare sees for each trace site; None where it didn't answer."""
    out = {}
    for host in TRACE_SITES:
        sock = None
        try:
            sock, _ = probe.connect(host, 443, route, resolver)
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


def prepare(route=None):
    """Find a way to scan as a Russian user without a VPN; return (route, resolver).

    No VPN: scan as is. A VPN: go around it through the home connection, and make
    sure Cloudflare sees Russia that way on every site. Otherwise stop."""
    if route:
        resolver = probe.resolve_via(route.dns, route) if route.dns else None
        _expect_russia(exit_countries(route, resolver), f"through {route}")
        return route, resolver

    seen = exit_countries()
    if all(c in (None, "RU") for c in seen.values()):
        if "RU" not in seen.values():
            print("warning: could not confirm the country, going on anyway", file=sys.stderr)
        return None, None

    route = direct.find()
    if route is None:
        sys.exit("A VPN is on and there is no home connection to go around it. Turn the VPN off and run again.")
    resolver = probe.resolve_via(route.dns, route) if route.dns else None
    _expect_russia(exit_countries(route, resolver), "with the VPN still on")
    print(f"A VPN is on; scanning around it through {route}", file=sys.stderr)
    return route, resolver


def _expect_russia(seen, how):
    if "RU" not in seen.values() or any(c and c != "RU" for c in seen.values()):
        where = ", ".join(f"{h}: {c or 'no answer'}" for h, c in seen.items())
        sys.exit(f"Can't scan as a user in Russia {how} ({where}). Turn the VPN off and run again.")


def load_targets(path, limit=None):
    """One host per line; an optional leading rank is ignored. Order is kept."""
    hosts = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        parts = line.split("#", 1)[0].split()
        if parts:
            hosts.append(parts[-1].lower())
    return hosts[:limit]


def run(targets, out, jobs=64, route=None, resolver=None):
    """Probe every target not already in `out`, appending one JSON line per host."""
    out = Path(out)
    done = set()
    if out.exists():
        done = set(records(out))
    todo = [t for t in targets if t not in done]
    print(f"{len(todo)} to check, {len(done)} already done", file=sys.stderr)
    # Submit as slots free up instead of all at once: with hundreds of thousands
    # of targets, finished results would otherwise pile up in memory.
    pending, queue, n = set(), iter(todo), 0
    with out.open("a", encoding="utf-8") as f, ThreadPoolExecutor(jobs) as pool:
        while True:
            for host in queue:
                future = pool.submit(probe.fetch, host, route, resolver)
                future.host = host
                pending.add(future)
                if len(pending) >= jobs * 2:
                    break
            if not pending:
                break
            done_now, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done_now:
                f.write(json.dumps(_result(future), ensure_ascii=False) + "\n")
                n += 1
                if n % 100 == 0:
                    f.flush()
                if n % 1000 == 0:
                    print(f"{n}/{len(todo)}", file=sys.stderr)


def _result(future):
    """One odd site must not stop a run that takes a day: record the error and go on."""
    try:
        return future.result()
    except Exception as e:  # noqa: BLE001
        return {"host": future.host, "status": None, "bytes": 0, "stage": "scanner", "ip": None,
                "error": f"{type(e).__name__}: {e}"[:120]}


def records(path):
    """host -> record from a results file. A line cut short by a stopped scan is skipped."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[record["host"]] = record
    return out


def load(*paths):
    out = {}
    for path in paths:
        out.update(records(path))
    return out


def verdict(home, abroad):
    """Compare one host or URL as seen from Russia and from abroad."""
    if not abroad or abroad["status"] is None or abroad["status"] >= 500 or "challenge" in abroad.get("marks", []):
        return "unknown"  # no good page abroad either: dead, broken or behind a bot check
    if home["status"] is None:
        if _no_answer(home) or _local_error(home.get("error")):
            # under load the resolver times out too; half of such hosts open on a calm rerun
            return "unknown"
        if home["stage"] == "body" and 0 < home["bytes"] < abroad["bytes"]:
            return "throttled"
        return "blocked"
    marks, abroad_marks = home.get("marks", []), abroad.get("marks", [])
    if "block" in marks:
        return "blocked"
    if "challenge" in marks:
        return "unknown"
    if "geo" in marks and "geo" not in abroad_marks:
        return "geoblocked"
    # 403 at home where abroad gets the page, or a plain "log in" 401 for an API
    if home["status"] in (403, 451) and abroad["status"] in (200, 401):
        return "geoblocked"
    if home["status"] >= 400 and home["status"] != abroad["status"]:
        return "unknown"  # an error at home that abroad didn't get proves nothing either way
    return "works"


def _no_answer(record):
    """DNS gave no answer at all. An answer without an address is different: some
    services hand Russian resolvers an empty reply, and that is a refusal."""
    return record["stage"] == "dns" and "no A record" not in (record.get("error") or "")


def _local_error(error):
    """The scanning computer lost its network, not the site."""
    return any(e in (error or "") for e in ("No such device", "Network is unreachable", "No route to host"))


def resource_verdicts(home, abroad):
    """Hosts a page pulls scripts and styles from, broken at home but fine abroad.

    Pages differ a little between countries, so a resource host is compared with
    whatever the abroad scan fetched from the same host."""
    seen_abroad = {}
    for record in abroad.values():
        # resources fetched with their pages, and the ones rechecked on their own
        for r in record.get("resources", []) + [record]:
            host = probe.split_target(r["host"])[0]
            if r["status"] and r["status"] < 400:
                seen_abroad.setdefault(host, r)
    out, unchecked = {}, set()
    for record in home.values():
        for r in record.get("resources", []):
            host = probe.split_target(r["host"])[0]
            if r["status"] is not None:
                continue
            if host in seen_abroad:
                out[host] = verdict(r, seen_abroad[host])
            else:
                unchecked.add(r["host"])
    return out, unchecked


def verdicts(home_path, *abroad_paths):
    home, abroad = load(home_path), load(*abroad_paths)
    pages = {host: verdict(record, abroad.get(host)) for host, record in home.items()}
    resources, unchecked = resource_verdicts(home, abroad)
    return pages, resources, unchecked
