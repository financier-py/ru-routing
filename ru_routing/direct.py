"""Getting around a VPN that is running on the same machine.

Most VPN apps add their own routes but leave the home connection in place.
Sending from the home interface (Linux, macOS) or from its address (Windows)
goes straight to the router, so a scan can run while the VPN keeps working.
A VPN with a kill switch blocks this; the scan then asks to turn it off.
"""

import ipaddress
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass

IP_BOUND_IF = 25  # macOS, netinet/in.h
VPN_INTERFACE = re.compile(r"^(tun|tap|wg|utun|ipsec|ppp|zt|tailscale|nordlynx|proton|mullvad)", re.IGNORECASE)


@dataclass(frozen=True)
class Direct:
    interface: str = ""  # Linux, macOS
    address: str = ""    # Windows
    dns: str = ""        # usually the home router

    def bind(self, sock):
        if self.address:
            sock.bind((self.address, 0))
        elif self.interface and sys.platform == "darwin":
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(self.interface))
        elif self.interface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())

    def __str__(self):
        return self.interface or self.address


def _linux():
    best = None
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.split()
            iface, dest, gateway, metric = fields[0], fields[1], fields[2], fields[6]
            if dest != "00000000" or gateway == "00000000" or VPN_INTERFACE.match(iface):
                continue
            if best is None or int(metric) < best[0]:
                gw = socket.inet_ntoa(int(gateway, 16).to_bytes(4, "little"))
                best = (int(metric), Direct(interface=iface, dns=gw))
    return best and best[1]


def _windows():
    out = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, errors="replace", check=False).stdout
    best = None
    for line in out.splitlines():
        parts = line.split()
        # Network Destination, Netmask, Gateway, Interface, Metric
        if len(parts) != 5 or parts[:2] != ["0.0.0.0", "0.0.0.0"]:
            continue
        try:
            gateway, local = ipaddress.ip_address(parts[2]), ipaddress.ip_address(parts[3])
        except ValueError:
            continue  # "On-link": a tunnel, not a router
        key = (not local.is_private, int(parts[4]))  # a home network first, then the cheapest route
        if best is None or key < best[0]:
            best = (key, Direct(address=str(local), dns=str(gateway)))
    return best and best[1]


def _macos():
    out = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, check=False).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default" and not VPN_INTERFACE.match(parts[3]):
            return Direct(interface=parts[3], dns=parts[1])
    return None


def find():
    """The home connection, or None if there is no obvious one."""
    try:
        if sys.platform.startswith("linux"):
            return _linux()
        if sys.platform == "win32":
            return _windows()
        if sys.platform == "darwin":
            return _macos()
    except OSError:
        pass
    return None


def keep_awake():
    """Stop the computer from sleeping while a long scan runs."""
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    elif sys.platform == "darwin":
        subprocess.Popen(["caffeinate", "-i", "-w", str(os.getpid())])
