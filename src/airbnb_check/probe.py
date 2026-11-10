"""Read-only port probing and banner grabbing (TCP connect, HTTP GET /, RTSP DESCRIBE).

The fast pass looks at ~26 usual ports; `deep_scan` checks all 65535 ports of the few devices that stayed unidentified.
"""
from __future__ import annotations

import re
import socket
import ssl
import time

from .net import pmap
from .textutil import clean

CAMERA_PORTS = (80, 81, 443, 554, 1935, 5000, 6668, 7000, 8000, 8001, 8002, 8008, 8009, 8080, 8443, 8554, 8899, 9000,
                9100, 515, 631, 34567, 37777, 49152, 49153, 62078)
HTTP_PORTS = {80, 81, 5000, 8000, 8008, 8080, 8899, 9000}
TLS_PORTS = {443, 8443}
RTSP_PORTS = {554, 8554}
UA = "airbnb-check (read-only network audit)"
DEEP_BUDGET = 45.0     # seconds for the whole deep pass
DEEP_WORKERS = 900
MAX_BANNER_PORTS = 24  # per device in the deep pass


def _scan_chunk(args: tuple[str, tuple[int, ...], float, float]) -> tuple[str, list[int], int]:
    ip, ports, timeout, deadline = args
    found, done = [], 0
    for p in ports:
        if time.monotonic() > deadline:
            break
        done += 1
        try:
            s = socket.socket()
        except OSError:  # out of file descriptors: this port stays unverified instead of crashing the scan
            done -= 1
            time.sleep(0.05)
            continue
        try:
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0:
                found.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return ip, found, done


def open_ports(hosts: list[str], ports: tuple[int, ...] | range, timeout: float) -> dict[str, list[int]]:
    ports = tuple(ports)
    chunk = max(1, min(128, len(ports) // 8))  # small lists: fan out so filtered hosts do not serialize timeouts
    far = time.monotonic() + 3600
    tasks = [(ip, ports[i:i + chunk], timeout, far) for ip in hosts for i in range(0, len(ports), chunk)]
    result: dict[str, list[int]] = {ip: [] for ip in hosts}
    for ip, found, _ in pmap(_scan_chunk, tasks):
        result[ip].extend(found)
    return {ip: sorted(v) for ip, v in result.items()}


def deep_scan(hosts: list[str], timeout: float, budget: float = DEEP_BUDGET) -> dict[str, tuple[list[int], int]]:
    """All 65535 TCP ports of each host; returns ip -> (open ports, ports actually checked).

    Chunks are interleaved across hosts (usual ports first) so a slow, filtered host cannot starve the others.
    """
    order = list(CAMERA_PORTS) + [p for p in range(1, 65536) if p not in CAMERA_PORTS]
    chunks = [tuple(order[i:i + 256]) for i in range(0, len(order), 256)]
    deadline = time.monotonic() + budget
    tasks = [(ip, c, timeout, deadline) for c in chunks for ip in hosts]
    result: dict[str, tuple[list[int], int]] = {ip: ([], 0) for ip in hosts}
    for ip, found, done in pmap(_scan_chunk, tasks, DEEP_WORKERS):
        ports, n = result[ip]
        result[ip] = (ports + found, n + done)
    return {ip: (sorted(p), n) for ip, (p, n) in result.items()}


def _exchange(ip: str, port: int, payload: bytes, timeout: float, tls: bool = False) -> bytes:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        s = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # banner only, nothing sensitive sent
            s = ctx.wrap_socket(raw, server_hostname=ip)
        with s:
            s.settimeout(timeout)
            s.sendall(payload)
            data, end = b"", time.monotonic() + 2 * timeout + 1
            while len(data) < 8192 and time.monotonic() < end:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data[:8192]
    except (OSError, ssl.SSLError):
        return b""


def parse_http(raw: str) -> dict[str, str]:
    """Parse a raw HTTP/RTSP response into status/server/realm/title (all sanitized)."""
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:60])}
    realm = re.search(r'realm="?([^",]{0,80})', hdr.get("www-authenticate", ""), re.I)
    title = re.search(r"<title[^>]{0,100}>([^<]{0,200})</title>", body, re.I)
    out = {"proto": "rtsp" if lines[0].startswith("RTSP/") else "http", "status": clean(lines[0], 60),
           "server": clean(hdr.get("server", ""), 80), "realm": clean(realm.group(1), 80) if realm else "",
           "title": clean(title.group(1), 80) if title else ""}
    return {k: v for k, v in out.items() if v}


def _describe(ip: str, port: int) -> bytes:
    return (f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n"
            f"User-Agent: {UA}\r\n\r\n").encode()


def _get(ip: str) -> bytes:
    return f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n\r\n".encode()


def banner(args: tuple[str, int, float]) -> tuple[str, int, dict[str, str]]:
    ip, port, timeout = args
    if port in RTSP_PORTS:
        data = _exchange(ip, port, _describe(ip, port), timeout)
    else:
        data = _exchange(ip, port, _get(ip), timeout, tls=port in TLS_PORTS)
    text = data.decode("utf-8", "replace")
    if not text.startswith(("HTTP/", "RTSP/")):
        return ip, port, {}
    return ip, port, parse_http(text)


def deep_banner(args: tuple[str, int, float]) -> tuple[str, int, dict[str, str]]:
    """Any open port: RTSP DESCRIBE first (servers that talk first, like SSH, also answer), then HTTP/TLS GET."""
    ip, port, timeout = args
    if port in RTSP_PORTS or port in HTTP_PORTS or port in TLS_PORTS:
        return banner(args)
    data = _exchange(ip, port, _describe(ip, port), timeout).decode("utf-8", "replace")
    if data.startswith("RTSP/"):
        return ip, port, parse_http(data)
    if data.startswith("HTTP/"):  # some web server on a custom port: ask for the page title and Server header
        return ip, port, banner((ip, port, timeout))[2] or parse_http(data)
    if not data:  # silent: maybe TLS
        text = _exchange(ip, port, _get(ip), timeout, tls=True).decode("utf-8", "replace")
        return ip, port, parse_http(text) if text.startswith("HTTP/") else {}
    first = clean(data.splitlines()[0], 60) if data.strip() else ""
    return ip, port, {"proto": "tcp", "raw": first} if first and first.isprintable() else {}


def grab_banners(open_by_host: dict[str, list[int]], timeout: float, deep: bool = False) -> dict[str, dict[int, dict[str, str]]]:
    wanted = HTTP_PORTS | TLS_PORTS | RTSP_PORTS
    tasks = [(ip, p, timeout) for ip, ps in open_by_host.items() for p in (ps[:MAX_BANNER_PORTS] if deep else ps) if deep or p in wanted]
    out: dict[str, dict[int, dict[str, str]]] = {}
    def safe(task: tuple[str, int, float]) -> tuple[str, int, dict[str, str]]:
        try:
            return (deep_banner if deep else banner)(task)
        except Exception:  # noqa: BLE001 - a malformed reply from one device must not abort the others
            return task[0], task[1], {}
    for ip, port, b in pmap(safe, tasks):
        if b:
            out.setdefault(ip, {})[port] = b
    return out
