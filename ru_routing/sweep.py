"""Checking a very long list of sites a little at a time, for weeks.

A sweep keeps its targets and every check in SQLite, so it can be stopped and
picked up at any moment. From home each site gets two passes some hours
apart, and a third when they disagree; from abroad, one. The two sides run
on different machines and are put together later: `export` writes each pass
as an ordinary scan file, which `verdicts`, tools/findings.py and
tools/hostings.py already read.
"""

import json
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import probe

GAP = 6 * 3600      # seconds between two home passes of one site
ROUND = 20          # sites per job in a round; jobs and pauses are reconsidered between rounds
CONTROL = ["ya.ru", "www.google.com"]

SCHEMA = """
create table if not exists targets (
    host text primary key,
    priority integer not null,
    source text,
    passes integer not null default 0,
    last real,
    unsure integer not null default 0
);
create index if not exists targets_due on targets (passes, priority);
create table if not exists checks (host text not null, at real not null, record text not null);
create index if not exists checks_host on checks (host);
create index if not exists checks_at on checks (at);
"""


def connect(path):
    db = sqlite3.connect(path, timeout=60)
    db.executescript(SCHEMA)
    return db


def add(db, lines, source):
    """Lines of "priority host"; a host already queued keeps its better priority."""
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and not line.startswith("#"):
            rows.append((parts[1].lower(), int(parts[0]), source))
    db.executemany("""insert into targets (host, priority, source) values (?, ?, ?)
                      on conflict (host) do update set priority = min(priority, excluded.priority)""", rows)
    db.commit()
    return len(rows)


def due(db, side, limit, now):
    """Sites waiting for their next pass, best priority first.

    Abroad one pass is enough. At home a second pass comes once the first is
    GAP old, and a third only for sites whose two passes disagreed."""
    if side == "abroad":
        query, args = "select host from targets where passes = 0 order by priority limit ?", (limit,)
    else:
        query = """select host from targets
                   where passes = 0 or (passes = 1 and last < ?) or (passes = 2 and unsure and last < ?)
                   order by priority limit ?"""
        args = (now - GAP, now - GAP, limit)
    return [row[0] for row in db.execute(query, args)]


def outcome(record):
    """What a pass saw, coarsely: two passes that differ here need a third."""
    if record["status"] is None or record.get("error"):
        return f"failed at {record.get('stage')}"
    return "answered"


def record_check(db, host, record, now):
    db.execute("insert into checks values (?, ?, ?)", (host, now, json.dumps(record, ensure_ascii=False)))
    passes, = db.execute("select passes from targets where host = ?", (host,)).fetchone()
    unsure = 0
    if passes == 1:
        first = json.loads(db.execute("select record from checks where host = ? order by at limit 1",
                                      (host,)).fetchone()[0])
        unsure = int(outcome(first) != outcome(record))
    db.execute("update targets set passes = passes + 1, last = ?, unsure = ? where host = ?",
               (now, unsure, host))


def jobs_now(day, night, hours):
    start, end = hours
    hour = time.localtime().tm_hour
    return night if start <= hour < end else day


def network_up(route, resolver):
    """Both control sites failing means the home connection is down, not the sites."""
    return any(probe.fetch(host, route, resolver, deep=False)["status"] for host in CONTROL)


def status(db, side, path, state):
    total, done, twice, unsure = db.execute(
        "select count(*), sum(passes > 0), sum(passes > 1), sum(unsure) from targets").fetchone()
    hour_ago = time.time() - 3600
    last_hour, = db.execute("select count(*) from checks where at > ?", (hour_ago,)).fetchone()
    data = {"side": side, "targets": total, "checked": done or 0, "twice": twice or 0, "unsure": unsure or 0,
            "last_hour": last_hour, "updated": int(time.time()), **state}
    Path(path).write_text(json.dumps(data), encoding="utf-8")


def run(path, side, day_jobs, night_jobs, night_hours, route=None, resolver=None, pause_file=None,
        status_file=None):
    db = connect(path)
    state = {}
    while True:
        if pause_file and Path(pause_file).exists():
            state = {"paused": Path(pause_file).read_text(encoding="utf-8").strip() or "paused"}
        elif side == "home" and not network_up(route, resolver):
            state = {"paused": "no home connection"}
        else:
            jobs = jobs_now(day_jobs, night_jobs, night_hours)
            hosts = due(db, side, jobs * ROUND, time.time())
            if not hosts:
                state = {"paused": "nothing due"}
            else:
                state = {"jobs": jobs, "at": hosts[-1]}
                with ThreadPoolExecutor(jobs) as pool:
                    for host, record in zip(hosts, pool.map(lambda h: _fetch(h, route, resolver), hosts)):
                        record_check(db, host, record, time.time())
                db.commit()
        if status_file:
            status(db, side, status_file, state)
        if "paused" in state:
            print(state["paused"], file=sys.stderr, flush=True)
            time.sleep(300)


def _fetch(host, route, resolver):
    try:
        return probe.fetch(host, route, resolver)
    except Exception as e:  # noqa: BLE001 - one odd site must not stop a sweep that runs for weeks
        return {"host": host, "status": None, "bytes": 0, "stage": "scanner", "ip": None,
                "error": f"{type(e).__name__}: {e}"[:120]}


def export(path, out):
    """Each pass as its own scan file: pass-1.jsonl, pass-2.jsonl and so on."""
    db = connect(path)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files, counts, seen = {}, {}, {}
    for host, record in db.execute("select host, record from checks order by host, at"):
        n = seen[host] = seen.get(host, 0) + 1
        if n not in files:
            files[n] = (out / f"pass-{n}.jsonl").open("w", encoding="utf-8")
        files[n].write(record + "\n")
        counts[n] = counts.get(n, 0) + 1
    for f in files.values():
        f.close()
    return counts
