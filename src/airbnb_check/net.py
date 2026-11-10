"""Network discovery: interface detection, ping sweep, ARP, SSDP, WS-Discovery, mDNS.

Everything here is read-only and limited to the subnet of the machine's own
active interface (a private RFC1918 range, /24 or smaller).
"""
from __future__ import annotations

import ipaddress
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar
from urllib.parse import urlparse

from .textutil import clean

MAX_THREADS = 300
IS_MAC = sys.platform == "darwin"
PRIVATE_RANGES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
TCP_PING_PORTS = (80, 443, 22, 445, 62078)
MDNS_TYPES = ("_rtsp._tcp", "_onvif._tcp", "_http._tcp", "_googlecast._tcp", "_hap._tcp", "_airplay._tcp",
              "_ipp._tcp", "_printer._tcp", "_companion-link._tcp")
MAX_REPLIES = 1500
MAX_PER_IP = 12        # one noisy or flooding responder must not crowd out the others
UA = "airbnb-check (read-only network audit)"
T = TypeVar("T")
R = TypeVar("R")


class ScanError(Exception):
    """User-facing error (bad network, missing command...)."""


@dataclass
class NetInfo:
    iface: str
    ip: str
    network: ipaddress.IPv4Network
    gateway: str
    clamped: bool = False


def check_target(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    """Refuse anything that is not a private RFC1918 range of /24 or smaller."""
    if net.version != 4:
        raise ScanError(f"{net}: only IPv4 networks are supported")
    if net.prefixlen < 24:
        raise ScanError(f"{net}: refusing to scan anything larger than a /24")
    if not any(net.subnet_of(p) for p in PRIVATE_RANGES):
        raise ScanError(f"{net}: not a private RFC1918 network (10/8, 172.16/12, 192.168/16)")


def raise_fd_limit(want: int = 4096) -> None:
    """macOS starts with 256 open files per process; thousands of parallel connects need more."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        top = want if hard == resource.RLIM_INFINITY else min(want, hard)
        if soft < top:
            resource.setrlimit(resource.RLIMIT_NOFILE, (top, hard))
    except (ImportError, ValueError, OSError):
        pass


def exe(name: str) -> str:
    """Absolute path of a system tool (fixed locations on macOS, PATH lookup elsewhere)."""
    if IS_MAC:
        for d in ("/sbin", "/usr/sbin", "/usr/bin", "/bin"):
            if os.path.exists(f"{d}/{name}"):
                return f"{d}/{name}"
    return shutil.which(name) or name


def clamp_network(ip: str, prefix: int) -> tuple[ipaddress.IPv4Network, bool]:
    """The interface network, or the local /24 when the interface netmask is larger. Returns (net, clamped)."""
    net = ipaddress.ip_interface(f"{ip}/{prefix}").network
    if net.prefixlen < 24:
        return ipaddress.ip_interface(f"{ip}/24").network, True
    return net, False


def run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command, returning stdout or '' if missing/failing."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def timed_map(fn: Callable[[T], R], items: Iterable[T], workers: int, budget: float) -> dict[T, R]:
    """Run fn over items on daemon threads, collecting whatever finishes within `budget` seconds."""
    todo: queue.Queue = queue.Queue()
    items = list(items)
    for i in items:
        todo.put(i)
    out: dict[T, R] = {}

    def work() -> None:
        while True:
            try:
                i = todo.get_nowait()
            except queue.Empty:
                return
            try:
                out[i] = fn(i)
            except Exception:  # noqa: BLE001 - one bad host must not stop the others
                pass
    threads = [threading.Thread(target=work, daemon=True) for _ in range(min(workers, MAX_THREADS, len(items)))]
    end = time.monotonic() + budget
    for th in threads:
        th.start()
    for th in threads:
        th.join(max(0.0, end - time.monotonic()))
    return dict(out)


def pmap(fn: Callable[[T], R], items: Iterable[T], workers: int = MAX_THREADS) -> list[R]:
    """Bounded parallel map that aborts quickly on Ctrl-C."""
    items = list(items)
    if not items:
        return []
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, 1024, len(items))))
    try:
        out = list(ex.map(fn, items))
    except BaseException:
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    ex.shutdown()
    return out


def norm_mac(mac: str) -> str:
    return ":".join(p.zfill(2) for p in mac.lower().split(":"))


def _udp_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _default_route() -> tuple[str, str]:
    if IS_MAC:
        out = run([exe("route"), "-n", "get", "default"])
        i = re.search(r"interface:\s*(\S+)", out)
        g = re.search(r"gateway:\s*(\S+)", out)
    else:
        out = run([exe("ip"), "route", "show", "default"])
        i = re.search(r"dev\s+(\S+)", out)
        g = re.search(r"via\s+(\S+)", out)
    return (i.group(1) if i else ""), (g.group(1) if g else "")


def _iface_addr(iface: str) -> tuple[str, int]:
    """Return (ip, prefixlen) for iface, or ('', 24)."""
    if IS_MAC:
        ip = run([exe("ipconfig"), "getifaddr", iface]).strip()
        mask = run([exe("ipconfig"), "getoption", iface, "subnet_mask"]).strip()
        try:
            return ip, ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            return ip, 24
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", run([exe("ip"), "-4", "-o", "addr", "show", "dev", iface]))
    return (m.group(1), int(m.group(2))) if m else ("", 24)


def detect() -> NetInfo:
    iface, gw = _default_route()
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,32}", iface) or iface.startswith("-"):
        iface = ""  # goes into argv of system tools: only plain interface names
    ip, prefix = _iface_addr(iface) if iface else ("", 24)
    if not ip:
        ip, prefix = _udp_local_ip(), 24
    if not ip:
        raise ScanError("could not find a local IPv4 address; are you connected to Wi-Fi?")
    net, clamped = clamp_network(ip, prefix)  # never more than the /24 that contains us
    check_target(net)
    try:  # the gateway is later pinged: it must be a literal IPv4 address on this very subnet, never a name or off-LAN host
        if ipaddress.ip_address(gw) not in net:
            gw = ""
    except ValueError:
        gw = ""
    return NetInfo(iface, ip, net, gw, clamped)


def _ping(args: tuple[str, float]) -> bool:
    ip, timeout = args
    wait = str(max(300, int(min(timeout, 0.6) * 1000))) if IS_MAC else "1"
    try:
        r = subprocess.run([exe("ping"), "-c1", "-W", wait, ip], capture_output=True, timeout=timeout + 3)
    except FileNotFoundError:
        raise ScanError("`ping` command not found")
    except subprocess.SubprocessError:
        return False
    return r.returncode == 0


def _tcp_alive(args: tuple[str, float]) -> bool:
    ip, timeout = args
    for port in TCP_PING_PORTS:
        s = socket.socket()
        s.settimeout(min(timeout, 0.3))
        try:
            s.connect((ip, port))
            return True
        except ConnectionRefusedError:
            return True  # a RST means the host is up
        except OSError:
            pass
        finally:
            s.close()
    return False


def sweep(net: ipaddress.IPv4Network, timeout: float) -> set[str]:
    """Ping + TCP-connect sweep. Returns live IPs."""
    hosts = [str(h) for h in net.hosts()]
    alive: set[str] = set()
    for fn, workers in ((_ping, 200), (_tcp_alive, MAX_THREADS)):
        todo = [h for h in hosts if h not in alive]
        res = pmap(fn, [(h, timeout) for h in todo], workers)
        alive.update(h for h, ok in zip(todo, res) if ok)
    return alive


def arp_table(info: NetInfo) -> dict[str, str]:
    """IP -> MAC on our interface, ignoring broadcast/multicast and other interfaces."""
    if IS_MAC:
        rx, order = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on (\S+)", re.I), (1, 2, 3)
        out = run([exe("arp"), "-an"])
    else:
        rx, order = re.compile(r"^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr ([0-9a-f:]{17})", re.I | re.M), (1, 3, 2)
        out = run([exe("ip"), "neigh"])
    table: dict[str, str] = {}
    for m in rx.finditer(out):
        ip, mac, iface = (m.group(i) for i in order)
        mac = norm_mac(mac)
        if info.iface and iface != info.iface or ipaddress.ip_address(ip) not in info.network:
            continue
        if mac == "ff:ff:ff:ff:ff:ff" or int(mac[:2], 16) & 1:  # broadcast / multicast
            continue
        table[ip] = mac
    return table


def _mcast_socket(local_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
    s.bind((local_ip, 0))
    return s


def _collect(s: socket.socket, net: ipaddress.IPv4Network, wait: float) -> list[tuple[str, str]]:
    """Gather (ip, payload) UDP replies for `wait` seconds, only from our subnet (bounded count and size)."""
    end, out, seen = time.monotonic() + wait, [], {}
    while (left := end - time.monotonic()) > 0 and len(out) < MAX_REPLIES:
        s.settimeout(left)
        try:
            data, addr = s.recvfrom(8192)
        except OSError:
            break
        if ipaddress.ip_address(addr[0]) in net and seen.get(addr[0], 0) < MAX_PER_IP:
            seen[addr[0]] = seen.get(addr[0], 0) + 1
            out.append((addr[0], data.decode("utf-8", "replace")))
    return out


def _tag(xml: str, name: str) -> str:
    """First <name>text</name> by bounded regex (never an XML parser on untrusted input)."""
    m = re.search(rf"<{name}>([^<]{{0,200}})</{name}>", xml, re.I)
    return clean(m.group(1), 80) if m else ""


def safe_location(url: str, ip: str, network: ipaddress.IPv4Network) -> tuple[str, int, str] | None:
    """SSRF guard for SSDP LOCATION: plain http, host literally equal to the responder, inside our subnet."""
    try:
        p = urlparse(url.strip())
        host, port = p.hostname, p.port or 80
        if p.scheme != "http" or not host or "@" in p.netloc or not 0 < port < 65536:
            return None
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.version != 4 or str(addr) != ip or addr not in network:
        return None
    return str(addr), port, (p.path or "/") + (f"?{p.query}" if p.query else "")


def http_get(ip: str, port: int, path: str, cap: int = 65536, timeout: float = 2.0) -> str:
    """Tiny GET with a size cap, a hard total deadline and no redirects. Returns '' on any problem.

    Raw socket on purpose: http.client resets its timeout on every received byte, so a slow-drip device could hold a
    thread (and the whole scan) forever.
    """
    if not re.fullmatch(r"/[\x21-\x7e]{0,400}", path):
        return ""
    end = time.monotonic() + 2 * timeout + 1
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
            buf = b""
            while len(buf) < cap and time.monotonic() < end:
                chunk = s.recv(min(4096, cap - len(buf)))
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return ""
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep or not re.match(rb"HTTP/1\.[01] 200\b", head):
        return ""
    return body.decode("utf-8", "replace")


def _fetch_description(args: tuple[str, str, ipaddress.IPv4Network]) -> tuple[str, dict[str, str]]:
    ip, url, network = args
    loc = safe_location(url, ip, network)
    if not loc:
        return ip, {}
    try:
        xml = http_get(*loc)
    except Exception:  # noqa: BLE001 - one broken device must not abort discovery of the others
        return ip, {}
    types = re.findall(r"<deviceType>\s*urn:[^:<]{1,60}:device:([A-Za-z0-9_.-]{1,40})", xml, re.I)
    out = {k: _tag(xml, t) for k, t in (("manufacturer", "manufacturer"), ("model", "modelName"), ("name", "friendlyName"))}
    out["types"] = " ".join(x.lower() for x in types[:10])
    return ip, out


def ssdp(info: NetInfo, wait: float = 3.0) -> dict[str, dict[str, str]]:
    """SSDP M-SEARCH; returns ip -> {server, location, manufacturer, model, name, types} (types: MediaRenderer, dial...)."""
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    s = _mcast_socket(info.ip)
    try:
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        replies = _collect(s, info.network, wait)
    finally:
        s.close()
    found: dict[str, dict[str, str]] = {}
    types: dict[str, set] = {}
    for ip, text in replies:
        d, ts = found.setdefault(ip, {}), types.setdefault(ip, set())
        for line in text.splitlines()[:40]:
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k in ("server", "location") and v:
                d.setdefault(k, clean(v, 200))
            elif k in ("st", "usn", "nt"):
                ts.update(x.lower() for x in re.findall(r"device:([A-Za-z0-9_.-]{1,40})", v))
                if "dial-multiscreen" in v.lower():
                    ts.add("dial")
    for ip, ts in types.items():
        found[ip]["types"] = " ".join(sorted(ts))
    locs = [(ip, d["location"], info.network) for ip, d in found.items() if "location" in d]
    for ip, desc in pmap(_fetch_description, locs, 20):
        types_now = set(found[ip].get("types", "").split()) | set(desc.pop("types", "").split())
        found[ip].update({k: v for k, v in desc.items() if v})
        found[ip]["types"] = " ".join(sorted(types_now))
    return found


def wsd_onvif(info: NetInfo, wait: float = 3.0) -> dict[str, str]:
    """ONVIF WS-Discovery probe; returns ip -> scopes text. Any responder is a camera signal."""
    probe = ('<?xml version="1.0" encoding="utf-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
             'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
             'xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header>'
             f"<w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>"
             "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
             "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>"
             "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>").encode()
    s = _mcast_socket(info.ip)
    try:
        s.sendto(probe, ("239.255.255.250", 3702))
        replies = _collect(s, info.network, wait)
    finally:
        s.close()
    out: dict[str, str] = {}
    for ip, text in replies:
        if "ProbeMatches" in text or "NetworkVideoTransmitter" in text:
            scopes = re.findall(r"onvif://www\.onvif\.org/(?:name|hardware)/([^\s<]{1,64})", text)
            out[ip] = clean(" ".join(scopes[:4]), 100)
    return out


def _mdns_mac(info: NetInfo, wait: float) -> dict[str, list[str]]:
    tool = exe("dns-sd")
    procs = [subprocess.Popen([tool, "-B", t, "local"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                              errors="replace") for t in MDNS_TYPES]
    time.sleep(wait)
    instances: set[tuple[str, str]] = set()
    for p in procs:
        p.terminate()
        out = p.communicate()[0] or ""
        for m in re.finditer(r"\sAdd\s+\d+\s+\d+\s+\S+\s+(_[\w-]+\._tcp)\.?\s+(.{1,100}?)\s*$", out[:200000], re.M):
            if m.group(1) in MDNS_TYPES and not m.group(2).startswith("-"):  # never let a device name act as an option
                instances.add((m.group(1), m.group(2)))

    def resolve(inst: tuple[str, str]) -> tuple[str, str, str, str]:
        typ, name = inst
        p = subprocess.Popen([tool, "-L", name, typ, "local"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                             errors="replace")
        time.sleep(2)
        p.terminate()
        m = re.search(r"can be reached at ([^\s:]{1,100}?\.local)\.?:(\d+)", (p.communicate()[0] or "")[:20000], re.I)  # .local only: no DNS leaves the LAN
        try:
            return typ, name, m.group(1) if m else "", socket.getaddrinfo(m.group(1), None, socket.AF_INET)[0][4][0] if m else ""
        except OSError:
            return typ, name, "", ""

    found: dict[str, list[str]] = {}
    for typ, name, host, ip in pmap(resolve, sorted(instances)[:40], 40):
        if ip and ipaddress.ip_address(ip) in info.network:
            cur = found.setdefault(ip, [])
            cur.append(f"{typ}: {clean(name, 60)}")
            if host and not any(x.startswith("host: ") for x in cur):
                cur.append("host: " + clean(host.removesuffix(".local"), 60))
    return found


def _in_net(addr: str, network: ipaddress.IPv4Network) -> bool:
    """Membership test for an untrusted address string (a bare `str in network` raises AttributeError)."""
    try:
        return ipaddress.ip_address(addr) in network
    except ValueError:
        return False


def _mdns_linux(info: NetInfo, wait: float) -> dict[str, list[str]]:
    out = run([exe("avahi-browse"), "-a", "-p", "-t", "-r"], timeout=wait + 6)
    found: dict[str, list[str]] = {}
    for line in out.splitlines()[:5000]:
        f = line.split(";")
        if len(f) > 7 and f[0] == "=" and f[2] == "IPv4" and f[4] in MDNS_TYPES and _in_net(f[7], info.network):
            cur = found.setdefault(f[7], [])
            cur.append(f"{f[4]}: {clean(f[3], 60)}")
            if f[6] and not any(x.startswith("host: ") for x in cur):
                cur.append("host: " + clean(f[6].removesuffix(".local"), 60))
    return found


def mdns(info: NetInfo, wait: float = 4.0) -> dict[str, list[str]]:
    """Browse a few Bonjour service types; ip -> ['_type._tcp: name', 'host: name']. Skipped if no tool."""
    tool = "dns-sd" if IS_MAC else "avahi-browse"
    if not (os.path.exists(exe(tool)) or shutil.which(tool)):
        return {}
    return (_mdns_mac if IS_MAC else _mdns_linux)(info, wait)


def reverse_dns(ips: list[str], budget: float = 4.0) -> dict[str, str]:
    """PTR names via the system resolver (normally the gateway). gethostbyaddr has no timeout, so it runs on daemon threads."""
    def one(ip: str) -> str:
        return clean(socket.gethostbyaddr(ip)[0].split(".")[0], 60)
    return {ip: n for ip, n in timed_map(one, ips, 32, budget).items() if n and n != ip}


_NBSTAT = b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01"


def _netbios_one(ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.7)
    try:
        s.connect((ip, 137))  # a connected UDP socket drops datagrams from anyone else
        s.send(_NBSTAT)
        data = s.recv(1024)
    except OSError:
        return ""
    finally:
        s.close()
    n = data[56] if len(data) > 57 else 0
    for i in range(min(n, 20)):  # 18-byte entries: 15 name + 1 suffix + 2 flags
        e = data[57 + 18 * i: 75 + 18 * i]
        if len(e) == 18 and e[15] == 0 and not e[16] & 0x80:  # workstation name, unique
            return clean(e[:15].decode("ascii", "replace"), 15)
    return ""


def netbios(ips: list[str], budget: float = 3.0) -> dict[str, str]:
    """NetBIOS name (UDP 137 NBSTAT, read-only). Most phones and TVs ignore it; Windows, Samba and printers answer."""
    return {ip: n for ip, n in timed_map(_netbios_one, ips, 64, budget).items() if n}
