"""How much memory the lists cost a VPN core, as close to iOS as Linux allows.

    python tools/memory.py --xray ./xray --mihomo ./mihomo dist/lite dist/standard

Each core is started twice: with a config that uses every category of the
variant, and with the same config minus the lists. The difference is what the
lists cost. Peak is the highest anonymous RSS seen while the core starts up:
iOS kills a VPN extension at the moment it crosses 50 MB, so the peak matters
more than the steady state.

Xray picks its domain matcher by OS and on Linux builds the desktop one, which
uses several times more memory than the one iOS gets. Build it with the mobile
matcher for a fair number (see tools/build-xray.sh).

Go runtime settings follow libXray on iOS: GOGC=10, GOMEMLIMIT=30MiB.
"""

import argparse
import json
import os
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ENV = {"GOGC": "10", "GOMEMLIMIT": "30MiB", "GOMAXPROCS": "2"}
SETTLE = 8  # seconds to wait after start before taking the steady value


def rss_anon(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("RssAnon:"):
                return int(line.split()[1]) / 1024
    return 0.0


def watch(cmd, cwd, env):
    """Run a core, return (peak, steady) anonymous RSS in MiB."""
    proc = subprocess.Popen(cmd, cwd=cwd, env={**os.environ, **ENV, **env},
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    peak = steady = 0.0
    start = time.monotonic()
    try:
        while time.monotonic() - start < SETTLE:
            if proc.poll() is not None:
                raise RuntimeError(f"{cmd[0]} exited: {proc.stdout.read().decode()[-500:]}")
            steady = rss_anon(proc.pid)
            peak = max(peak, steady)
            time.sleep(0.002)
    finally:
        proc.terminate()
        proc.wait()
    return peak, steady


def categories(variant, kind):
    folder = Path(variant) / "text" / kind
    return sorted(p.stem for p in folder.glob("*.txt")) if folder.exists() else []


def xray_config(sites, ips):
    rules = [{"domain": [f"geosite:{c}" for c in sites], "outboundTag": "block"}] if sites else []
    if ips:
        rules.append({"ip": [f"geoip:{c}" for c in ips], "outboundTag": "block"})
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": rules},
    }


def xray(binary, variant):
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("geosite.dat", "geoip.dat"):
            os.symlink(Path(variant, name).resolve(), Path(tmp, name))
        results = []
        for sites, ips in ((categories(variant, "geosite"), categories(variant, "geoip")), ([], [])):
            Path(tmp, "config.json").write_text(json.dumps(xray_config(sites, ips)))
            results.append(watch([str(Path(binary).resolve()), "run", "-c", "config.json"], tmp,
                                 {"XRAY_LOCATION_ASSET": tmp}))
    return results


def mihomo_config(variant, home, sites, ips):
    providers, rules = [], []
    for kind, behavior, names in (("geosite", "domain", sites), ("geoip", "ipcidr", ips)):
        for name in names:
            src = Path(variant, "mihomo", kind, f"{name}.mrs").resolve()
            if not src.exists():
                continue
            key = f"{kind}-{name}"
            # mihomo only reads providers from inside its home directory
            os.symlink(src, Path(home, f"{key}.mrs"))
            providers.append(f"  {key}:\n    type: file\n    behavior: {behavior}\n    format: mrs\n    path: ./{key}.mrs\n")
            rules.append(f"  - RULE-SET,{key},REJECT{',no-resolve' if behavior == 'ipcidr' else ''}\n")
    return ("mixed-port: 17890\nlog-level: error\nmode: rule\n"
            + ("rule-providers:\n" + "".join(providers) if providers else "")
            + "rules:\n" + "".join(rules) + "  - MATCH,DIRECT\n")


def mihomo(binary, variant):
    results = []
    for sites, ips in ((categories(variant, "geosite"), categories(variant, "geoip")), ([], [])):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "config.yaml").write_text(mihomo_config(variant, tmp, sites, ips))
            results.append(watch([str(Path(binary).resolve()), "-d", tmp, "-f", "config.yaml"], tmp, {}))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--xray")
    parser.add_argument("--mihomo")
    parser.add_argument("--runs", type=int, default=3, help="take the median of this many runs")
    parser.add_argument("--max-peak", type=float, help="fail if the lists' peak goes above this many MiB")
    parser.add_argument("variants", nargs="+")
    args = parser.parse_args()

    over = []
    print(f"{'':22}{'lists peak':>12}{'lists steady':>14}{'core total peak':>17}")
    for variant in args.variants:
        for core, run in (("xray", xray), ("mihomo", mihomo)):
            binary = getattr(args, core)
            if not binary:
                continue
            runs = [run(binary, variant) for _ in range(args.runs)]
            (peak, steady), (base_peak, base_steady) = (
                tuple(statistics.median(r[i][j] for r in runs) for j in (0, 1)) for i in (0, 1))
            label = f"{Path(variant).name} / {core}"
            print(f"{label:22}{peak - base_peak:>9.1f} MiB{steady - base_steady:>11.1f} MiB{peak:>14.1f} MiB")
            if args.max_peak and peak - base_peak > args.max_peak:
                over.append(label)
    if over:
        raise SystemExit(f"over {args.max_peak} MiB: {', '.join(over)}")


if __name__ == "__main__":
    main()
