"""Domains that no longer exist anywhere.

Block lists keep every domain ever blocked, and most casino and cinema
mirrors in them are long gone. A domain counts as dead when several public
resolvers abroad all answer NXDOMAIN for it, in two checks a week apart:
a mirror often comes back on the same name, and one bad night proves nothing.
A timeout is not an answer.

    python tools/dead.py check names.txt -o dead-1.jsonl      # from abroad
    python tools/dead.py pick dead-1.jsonl dead-2.jsonl > data/dead
"""

import argparse
import json
import random
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
RCODES = {0: "ok", 2: "servfail", 3: "nxdomain", 5: "refused"}
MIN_DAYS = 7


def ask(server, name, timeout=3):
    """The response code a resolver gives for an A query, or "timeout"."""
    qid = random.randrange(1 << 16)
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\0\1\0\1"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for _ in range(2):
            try:
                s.sendto(query, (server, 53))
                while True:
                    reply = s.recv(4096)
                    if struct.unpack(">H", reply[:2])[0] == qid:
                        return RCODES.get(reply[3] & 0x0F, f"rcode{reply[3] & 0x0F}")
            except TimeoutError:
                continue
    return "timeout"


def check_one(name):
    try:
        name.encode("idna")
    except UnicodeError:
        return {"name": name, "answers": {}}
    ascii_name = name if name.isascii() else name.encode("idna").decode()
    return {"name": name, "answers": {server: ask(server, ascii_name) for server in RESOLVERS}}


def check(args):
    names = [line.split(":")[-1].strip() for line in Path(args.names).read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    out = Path(args.out)
    done = {json.loads(line)["name"] for line in out.read_text(encoding="utf-8").splitlines()
            if line.endswith("}")} if out.exists() else set()
    todo = [n for n in names if n not in done]
    print(f"{len(todo)} to check, {len(done)} already done", file=sys.stderr)
    with out.open("a", encoding="utf-8") as f, ThreadPoolExecutor(args.jobs) as pool:
        for i, record in enumerate(pool.map(check_one, todo), 1):
            record["at"] = datetime.now(UTC).isoformat(timespec="seconds")
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if i % 5000 == 0:
                print(f"{i}/{len(todo)}", file=sys.stderr)


def load(path):
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[record["name"]] = record
    return out


def dead(record):
    answers = record["answers"].values()
    return len(answers) == len(RESOLVERS) and all(a == "nxdomain" for a in answers)


def pick(args):
    passes = [load(p) for p in args.checks]
    when = [min(datetime.fromisoformat(r["at"]) for r in p.values()) for p in passes]
    if (max(when) - min(when)).days < MIN_DAYS:
        sys.exit(f"the checks must be at least {MIN_DAYS} days apart")
    names = sorted(n for n in set.intersection(*(set(p) for p in passes)) if all(dead(p[n]) for p in passes))
    print("# Domains from block lists that no longer exist: every resolver abroad answered")
    print("# NXDOMAIN, in checks at least a week apart. Made by tools/dead.py.\n")
    print("\n".join(names))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("check", help="ask resolvers about every name in a file")
    p.add_argument("names")
    p.add_argument("-o", "--out", default="dead.jsonl")
    p.add_argument("--jobs", type=int, default=64)
    p.set_defaults(func=check)
    p = sub.add_parser("pick", help="names dead in every check")
    p.add_argument("checks", nargs="+")
    p.set_defaults(func=pick)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
