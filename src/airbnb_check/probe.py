"""Read-only port probing and banner grabbing (TCP connect, HTTP GET /, RTSP OPTIONS)."""
from __future__ import annotations

import re
import socket
import ssl

from .net import pmap

CAMERA_PORTS = (80, 81, 443, 554, 1935, 5000, 6668, 8000, 8008, 8080, 8443, 8554, 8899, 9000, 34567, 37777, 49152, 49153)
HTTP_PORTS = {80, 81, 5000, 8000, 8008, 8080, 8899, 9000}
TLS_PORTS = {443, 8443}
RTSP_PORTS = {554, 8554}
UA = "airbnb-check (read-only network audit)"


def _scan_chunk(args: tuple[str, tuple[int, ...], float]) -> tuple[str, list[int]]:
    ip, ports, timeout = args
    found = []
    for p in ports:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                found.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return ip, found


def open_ports(hosts: list[str], ports: tuple[int, ...] | range, timeout: float) -> dict[str, list[int]]:
    ports = tuple(ports)
    chunk = max(1, min(128, len(ports) // 8))  # small lists: fan out so filtered hosts do not serialize timeouts
    tasks = [(ip, ports[i:i + chunk], timeout) for ip in hosts for i in range(0, len(ports), chunk)]
    result: dict[str, list[int]] = {ip: [] for ip in hosts}
    for ip, found in pmap(_scan_chunk, tasks):
        result[ip].extend(found)
    return {ip: sorted(v) for ip, v in result.items()}


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
            data = b""
            while len(data) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data
    except (OSError, ssl.SSLError):
        return b""


def parse_http(raw: str) -> dict[str, str]:
    """Parse a raw HTTP/RTSP response into status/server/realm/title."""
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
    realm = re.search(r'realm="?([^",]*)', hdr.get("www-authenticate", ""), re.I)
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    out = {"proto": "rtsp" if lines[0].startswith("RTSP/") else "http", "status": lines[0][:60],
           "server": hdr.get("server", ""), "realm": realm.group(1) if realm else "",
           "title": " ".join(title.group(1).split())[:80] if title else ""}
    return {k: v for k, v in out.items() if v}


def banner(args: tuple[str, int, float]) -> tuple[str, int, dict[str, str]]:
    ip, port, timeout = args
    if port in RTSP_PORTS:
        data = _exchange(ip, port, f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {UA}\r\n\r\n".encode(), timeout)
    else:
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n\r\n".encode()
        data = _exchange(ip, port, req, timeout, tls=port in TLS_PORTS)
    text = data.decode("utf-8", "replace")
    if not text.startswith(("HTTP/", "RTSP/")):
        return ip, port, {}
    return ip, port, parse_http(text)


def grab_banners(open_by_host: dict[str, list[int]], timeout: float) -> dict[str, dict[int, dict[str, str]]]:
    wanted = HTTP_PORTS | TLS_PORTS | RTSP_PORTS
    tasks = [(ip, p, timeout) for ip, ps in open_by_host.items() for p in ps if p in wanted]
    out: dict[str, dict[int, dict[str, str]]] = {}
    for ip, port, b in pmap(banner, tasks):
        if b:
            out.setdefault(ip, {})[port] = b
    return out
