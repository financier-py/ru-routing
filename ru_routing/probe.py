"""Opening a page the way a browser without a VPN would, and noting how it went.

Only the standard library: friends run this on whatever Python they have.
"""

import http.client
import re
import socket
import ssl
import struct
import time
import urllib.parse

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
LIMIT = 256 * 1024   # bytes of a page worth reading
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 10    # silence this long in the middle of a page is a stall
MAX_REDIRECTS = 5

MARKERS = {
    "geo": ["not available in your country", "not available in your region", "unavailable in your country",
            "isn't available in your country", "not supported in your country", "unavailable in your region",
            "not available in russia", "недоступен в вашем регионе", "недоступно в вашей стране",
            "недоступен в вашей стране", "unsupported_country", "location is not supported"],
    "block": ["доступ к информационному ресурсу ограничен", "eais.rkn.gov.ru", "blocked.rt.ru",
              "warning.rt.ru", "ресурс заблокирован"],
}
# Bot checks are recognised by their title: plenty of normal pages mention "captcha" somewhere.
CHALLENGE_TITLES = ["just a moment", "attention required", "checking your browser", "ddos-guard",
                    "verifying you are human", "один момент", "проверка браузера"]
_title = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def resolve_via(server, interface=None):
    """A resolver asking one DNS server directly, for when the system one is a VPN's."""
    def resolve(host):
        query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        query += b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\0\0\1\0\1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            if interface:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
            s.settimeout(4)
            s.sendto(query, (server, 53))
            reply = s.recv(4096)
        count = struct.unpack(">H", reply[6:8])[0]
        pos = len(query)
        for _ in range(count):
            pos += 2 if reply[pos] & 0xC0 == 0xC0 else reply.index(b"\0", pos) - pos + 1
            kind, _, _, size = struct.unpack(">HHIH", reply[pos:pos + 10])
            pos += 10
            if kind == 1 and size == 4:
                return socket.inet_ntoa(reply[pos:pos + 4])
            pos += size
        raise socket.gaierror(f"no A record for {host}")
    return resolve


def connect(host, port, interface=None, resolver=None):
    address = resolver(host) if resolver else socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if interface:  # Linux: leave through this interface even if a VPN owns the default route
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((address, port))
    except OSError:
        sock.close()
        raise
    return sock, address


def _page(host, path, interface, resolver, result):
    stage, body = "dns", b""
    try:
        sock, result["ip"] = connect(host, 443, interface, resolver)
        stage = "tls"
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        stage = "http"
        sock.settimeout(READ_TIMEOUT)
        conn = http.client.HTTPConnection(host)
        conn.sock = sock
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*",
                                           "Accept-Language": "ru,en;q=0.8", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        stage = "body"
        while len(body) < LIMIT:
            chunk = response.read1(65536)
            if not chunk:
                break
            body += chunk
        conn.close()
        return response.status, response.getheader("Location"), body
    except (OSError, http.client.HTTPException) as e:
        result["stage"] = stage
        result["error"] = type(e).__name__ if str(e) == "" else f"{type(e).__name__}: {e}"[:120]
        result["bytes"] = len(body)
        return None, None, None


def fetch(host, interface=None, resolver=None):
    """Open https://host/ following redirects; return what happened as a dict."""
    result = {"host": host, "status": None, "bytes": 0, "error": None, "stage": None, "ip": None}
    start = time.monotonic()
    url_host, path = host, "/"
    for _ in range(MAX_REDIRECTS + 1):
        status, location, body = _page(url_host, path, interface, resolver, result)
        if status is None:
            break
        result.update(status=status, bytes=len(body), final=url_host)
        if status in (301, 302, 303, 307, 308) and location:
            target = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://{url_host}{path}", location))
            if target.scheme != "https" or not target.hostname:
                break
            url_host, path = target.hostname, (target.path or "/") + (f"?{target.query}" if target.query else "")
            continue
        head = body[:65536].lower()
        title = _title.search(body[:65536])
        result["title"] = title.group(1).decode("utf-8", "replace").strip()[:120] if title else ""
        result["marks"] = [kind for kind, words in MARKERS.items()
                           if any(w.encode() in head for w in words)]
        if any(t in result["title"].lower() for t in CHALLENGE_TITLES) or (
                status in (403, 429, 503) and b"cf-chl" in head):
            result["marks"].append("challenge")
        break
    result["ms"] = int((time.monotonic() - start) * 1000)
    return result
