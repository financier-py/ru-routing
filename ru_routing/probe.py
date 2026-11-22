"""Opening a page the way a browser without a VPN would, and noting how it went.

Only the standard library: friends run this on whatever Python they have.
"""

import base64
import http.client
import ipaddress
import re
import socket
import ssl
import struct
import time
import urllib.parse

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
LIMIT = 128 * 1024          # bytes of a page worth reading
RESOURCE_LIMIT = 64 * 1024  # enough to tell a 16 KB stall from a full file
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 10    # silence this long in the middle of a page is a stall
MAX_REDIRECTS = 5
RESOURCES = 3       # other hosts a page loads from, checked along with it

MARKERS = {
    "geo": ["not available in your country", "not available in your region", "unavailable in your country",
            "isn't available in your country", "not supported in your country", "unavailable in your region",
            "not available in russia", "недоступен в вашем регионе", "недоступно в вашей стране",
            "недоступен в вашей стране", "unsupported_country", "location is not supported",
            "request not allowed"],
    "block": ["доступ к информационному ресурсу ограничен", "eais.rkn.gov.ru", "blocked.rt.ru",
              "warning.rt.ru", "ресурс заблокирован"],
}
# Bot checks are recognised by their title: plenty of normal pages mention "captcha" somewhere.
CHALLENGE_TITLES = ["just a moment", "attention required", "checking your browser", "ddos-guard",
                    "verifying you are human", "один момент", "проверка браузера"]
_title = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_resource = re.compile(rb"""(?:src|href)=["'](?:https:)?//([a-z0-9.-]+\.[a-z]{2,})(/[^"'\s>]*)""", re.IGNORECASE)
# A redirect to a page like /app-unavailable-in-region or ?location=unsupported is a refusal.
_refusal_url = re.compile(r"unsupported|unavailable|not[-_]available|restricted", re.IGNORECASE)


# DNS over HTTPS servers to fall back on: VPN apps on Windows catch every DNS packet
# on port 53, while HTTPS gets around them like any other traffic.
DOH = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")]
FAKE_IP = ipaddress.ip_network("198.18.0.0/15")  # where VPN apps' own DNS points everything


def _query(host):
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\0\0\1\0\1"


def _first_a(reply, query_len):
    count = struct.unpack(">H", reply[6:8])[0]
    pos = query_len
    for _ in range(count):
        pos += 2 if reply[pos] & 0xC0 == 0xC0 else reply.index(b"\0", pos) - pos + 1
        kind, _, _, size = struct.unpack(">HHIH", reply[pos:pos + 10])
        pos += 10
        if kind == 1 and size == 4:
            return socket.inet_ntoa(reply[pos:pos + 4])
        pos += size
    return None


def _ask(server, host, route, tcp):
    query = _query(host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        if route:
            route.bind(s)
        s.settimeout(3)
        if tcp:
            s.connect((server, 53))
            s.sendall(struct.pack(">H", len(query)) + query)
            size = struct.unpack(">H", s.recv(2))[0]
            reply = b""
            while len(reply) < size:
                reply += s.recv(size - len(reply))
        else:
            s.sendto(query, (server, 53))
            reply = s.recv(4096)
    return _first_a(reply, len(query))


def _ask_https(ip, name, host, route):
    query = _query(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if route:
        route.bind(sock)
    sock.settimeout(5)
    sock.connect((ip, 443))
    conn = http.client.HTTPConnection(name)
    conn.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=name)
    encoded = base64.urlsafe_b64encode(query).decode().rstrip("=")
    conn.request("GET", f"/dns-query?dns={encoded}", headers={"Accept": "application/dns-message"})
    reply = conn.getresponse().read()
    conn.close()
    return _first_a(reply, len(query))


def _ask_system(host):
    address = socket.gethostbyname(host)
    if ipaddress.ip_address(address) in FAKE_IP:
        raise OSError("the system resolver belongs to a VPN")
    return address


def resolve_via(server, route=None):
    """A resolver that asks DNS directly, for when the system one belongs to a VPN.

    Tries the router, then the router over TCP, then DNS over HTTPS, then the
    system resolver if it gives real addresses. The first way that answers is kept."""
    ways = [lambda h: _ask(server, h, route, tcp=False), lambda h: _ask(server, h, route, tcp=True)]
    ways += [lambda h, ip=ip, name=name: _ask_https(ip, name, h, route) for ip, name in DOH]
    ways.append(_ask_system)
    working = []
    cache = {}

    def resolve(host):
        if host in cache:
            return cache[host]
        for way in working or ways:
            try:
                address = way(host)
            except (OSError, http.client.HTTPException, struct.error, IndexError):
                continue
            if not working:
                working.append(way)
            if address is None:
                raise socket.gaierror(f"no A record for {host}")
            cache[host] = address
            return address
        raise socket.gaierror(f"no DNS server answered for {host}")
    return resolve


def connect(host, port, route=None, resolver=None):
    address = resolver(host) if resolver else socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if route:
        route.bind(sock)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((address, port))
    except OSError:
        sock.close()
        raise
    return sock, address


def _get(host, path, route, resolver, result, limit=LIMIT):
    stage, body = "dns", bytearray()
    try:
        sock, result["ip"] = connect(host, 443, route, resolver)
        stage = "tls"
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        stage = "http"
        sock.settimeout(READ_TIMEOUT)
        conn = http.client.HTTPConnection(host)
        conn.sock = sock
        # http.client sends the request line as ASCII; redirects may point to Cyrillic paths
        conn.request("GET", urllib.parse.quote(path, safe="/?&=%:+,;@!$'()*~#[]"), headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*",
                                           "Accept-Language": "ru,en;q=0.8", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        stage = "body"
        while len(body) < limit:
            chunk = response.read1(65536)
            if not chunk:
                break
            body += chunk
        conn.close()
        return response.status, response.getheader("Location"), bytes(body)
    except (OSError, ValueError, http.client.HTTPException) as e:
        result["stage"] = stage
        result["error"] = type(e).__name__ if str(e) == "" else f"{type(e).__name__}: {e}"[:120]
        result["bytes"] = len(body)
        return None, None, None


def _ascii(host):
    return host if host.isascii() else host.encode("idna").decode()


def split_target(target):
    """"example.com" or "https://example.com/path" -> (host, path)."""
    if "://" not in target:
        return target, "/"
    url = urllib.parse.urlsplit(target)
    return url.hostname, (url.path or "/") + (f"?{url.query}" if url.query else "")


def resources(host, body):
    """A few scripts, styles and images the page loads from other hosts, scripts first."""
    found = {}
    for m in _resource.finditer(body[:LIMIT]):
        other, path = m.group(1).decode().lower(), m.group(2).decode(errors="replace")
        if other != host and other not in found:
            found[other] = path
    ordered = sorted(found.items(), key=lambda x: not x[1].split("?")[0].endswith((".js", ".css")))
    return [f"https://{h}{p}" for h, p in ordered[:RESOURCES]]


def fetch(target, route=None, resolver=None, deep=True):
    """Open a host or an https URL, following redirects; return what happened as a dict.

    With deep=True a few resources the page pulls from other hosts are fetched too:
    a page can load fine while its scripts stall on a throttled CDN."""
    result = {"host": target, "status": None, "bytes": 0, "error": None, "stage": None, "ip": None}
    start = time.monotonic()
    url_host, path = split_target(target)
    for _ in range(MAX_REDIRECTS + 1):
        try:
            url_host = _ascii(url_host)
        except UnicodeError:
            result.update(stage="dns", error="bad host name")
            break
        status, location, body = _get(url_host, path, route, resolver, result, LIMIT if deep else RESOURCE_LIMIT)
        if status is None:
            break
        result.update(status=status, bytes=len(body), final=f"{url_host}{path}")
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://{url_host}{path}", location))
            if url.scheme != "https" or not url.hostname:
                break
            url_host, path = url.hostname, (url.path or "/") + (f"?{url.query}" if url.query else "")
            continue
        head = body[:65536].lower()
        title = _title.search(body[:65536])
        result["title"] = title.group(1).decode("utf-8", "replace").strip()[:120] if title else ""
        result["marks"] = [kind for kind, words in MARKERS.items() if any(w.encode() in head for w in words)]
        if _refusal_url.search(path):
            result["marks"].append("geo")
        if any(t in result["title"].lower() for t in CHALLENGE_TITLES) or (
                status in (403, 429, 503) and b"cf-chl" in head):
            result["marks"].append("challenge")
        if deep:
            result["resources"] = [
                {k: v for k, v in fetch(url, route, resolver, deep=False).items() if k in ("host", "status", "bytes", "stage")}
                for url in resources(url_host, body)]
        break
    result["ms"] = int((time.monotonic() - start) * 1000)
    return result
