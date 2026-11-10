"""Network discovery: interface detection, ping sweep, ARP, SSDP, WS-Discovery, mDNS.

Everything here is read-only and limited to the subnet of the machine's own
active interface (a private RFC1918 range, /24 or smaller).
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_THREADS = 300
IS_MAC = sys.platform == "darwin"
PRIVATE_RANGES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
TCP_PING_PORTS = (80, 443, 22, 445, 62078)
MDNS_TYPES = ("_rtsp._tcp", "_onvif._tcp", "_http._tcp", "_googlecast._tcp", "_hap._tcp", "_airplay._tcp")
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


def run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command, returning stdout or '' if missing/failing."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def pmap(fn: Callable[[T], R], items: Iterable[T], workers: int = MAX_THREADS) -> list[R]:
    """Bounded parallel map that aborts quickly on Ctrl-C."""
    items = list(items)
    if not items:
        return []
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, MAX_THREADS, len(items))))
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
        out = run(["route", "-n", "get", "default"])
        i = re.search(r"interface:\s*(\S+)", out)
        g = re.search(r"gateway:\s*(\S+)", out)
    else:
        out = run(["ip", "route", "show", "default"])
        i = re.search(r"dev\s+(\S+)", out)
        g = re.search(r"via\s+(\S+)", out)
    return (i.group(1) if i else ""), (g.group(1) if g else "")


def _iface_addr(iface: str) -> tuple[str, int]:
    """Return (ip, prefixlen) for iface, or ('', 24)."""
    if IS_MAC:
        ip = run(["ipconfig", "getifaddr", iface]).strip()
        mask = run(["ipconfig", "getoption", iface, "subnet_mask"]).strip()
        try:
            return ip, ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            return ip, 24
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", run(["ip", "-4", "-o", "addr", "show", "dev", iface]))
    return (m.group(1), int(m.group(2))) if m else ("", 24)


def detect() -> NetInfo:
    iface, gw = _default_route()
    ip, prefix = _iface_addr(iface) if iface else ("", 24)
    if not ip:
        ip, prefix = _udp_local_ip(), 24
    if not ip:
        raise ScanError("could not find a local IPv4 address; are you connected to Wi-Fi?")
    net = ipaddress.ip_interface(f"{ip}/{prefix}").network
    clamped = net.prefixlen < 24
    if clamped:  # stay inside the /24 that contains us
        net = ipaddress.ip_interface(f"{ip}/24").network
    check_target(net)
    return NetInfo(iface, ip, net, gw, clamped)


def _ping(args: tuple[str, float]) -> bool:
    ip, timeout = args
    wait = str(max(300, int(min(timeout, 0.6) * 1000))) if IS_MAC else "1"
    try:
        r = subprocess.run(["ping", "-c1", "-W", wait, ip], capture_output=True, timeout=timeout + 3)
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
        out = run(["arp", "-an"])
    else:
        rx, order = re.compile(r"^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr ([0-9a-f:]{17})", re.I | re.M), (1, 3, 2)
        out = run(["ip", "neigh"])
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
    """Gather (ip, payload) UDP replies for `wait` seconds, only from our subnet."""
    end, out = time.monotonic() + wait, []
    while (left := end - time.monotonic()) > 0:
        s.settimeout(left)
        try:
            data, addr = s.recvfrom(65535)
        except OSError:
            break
        if ipaddress.ip_address(addr[0]) in net:
            out.append((addr[0], data.decode("utf-8", "replace")))
    return out


def _tag(xml: str, name: str) -> str:
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.I | re.S)
    return m.group(1).strip() if m else ""


def _fetch_description(args: tuple[str, str]) -> tuple[str, dict[str, str]]:
    ip, url = args
    p = urlparse(url)
    if p.scheme != "http" or p.hostname != ip:  # only the device that answered us
        return ip, {}
    try:
        with urlopen(Request(url, headers={"User-Agent": UA}), timeout=2) as r:
            xml = r.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return ip, {}
    return ip, {k: _tag(xml, t) for k, t in (("manufacturer", "manufacturer"), ("model", "modelName"), ("name", "friendlyName"))}


def ssdp(info: NetInfo, wait: float = 3.0) -> dict[str, dict[str, str]]:
    """SSDP M-SEARCH; returns ip -> {server, location, manufacturer, model, name}."""
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
    for ip, text in replies:
        d = found.setdefault(ip, {})
        for line in text.splitlines():
            k, _, v = line.partition(":")
            if k.strip().lower() in ("server", "location") and v.strip():
                d.setdefault(k.strip().lower(), v.strip())
    locs = [(ip, d["location"]) for ip, d in found.items() if "location" in d]
    for ip, desc in pmap(_fetch_description, locs, 20):
        found[ip].update({k: v for k, v in desc.items() if v})
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
            scopes = re.findall(r"onvif://www\.onvif\.org/(?:name|hardware)/(\S+)", text)
            out[ip] = " ".join(scopes)
    return out


def _mdns_mac(info: NetInfo, wait: float) -> dict[str, list[str]]:
    procs = [subprocess.Popen(["dns-sd", "-B", t, "local"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
             for t in MDNS_TYPES]
    time.sleep(wait)
    instances: set[tuple[str, str]] = set()
    for p in procs:
        p.terminate()
        out = p.communicate()[0] or ""
        for m in re.finditer(r"\sAdd\s+\d+\s+\d+\s+\S+\s+(_[\w-]+\._tcp)\.?\s+(.+?)\s*$", out, re.M):
            instances.add((m.group(1), m.group(2)))

    def resolve(inst: tuple[str, str]) -> tuple[str, str, str]:
        typ, name = inst
        p = subprocess.Popen(["dns-sd", "-L", name, typ, "local"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(2)
        p.terminate()
        m = re.search(r"can be reached at (\S+?)\.?:(\d+)", p.communicate()[0] or "")
        try:
            return typ, name, socket.getaddrinfo(m.group(1), None, socket.AF_INET)[0][4][0] if m else ""
        except OSError:
            return typ, name, ""

    found: dict[str, list[str]] = {}
    for typ, name, ip in pmap(resolve, sorted(instances)[:24], 24):
        if ip and ipaddress.ip_address(ip) in info.network:
            found.setdefault(ip, []).append(f"{typ}: {name}")
    return found


def _mdns_linux(info: NetInfo, wait: float) -> dict[str, list[str]]:
    out = run(["avahi-browse", "-a", "-p", "-t", "-r"], timeout=wait + 6)
    found: dict[str, list[str]] = {}
    for line in out.splitlines():
        f = line.split(";")
        if len(f) > 7 and f[0] == "=" and f[2] == "IPv4" and f[4] in MDNS_TYPES:
            found.setdefault(f[7], []).append(f"{f[4]}: {f[3]}")
    return found


def mdns(info: NetInfo, wait: float = 4.0) -> dict[str, list[str]]:
    """Browse a few Bonjour service types; ip -> ['_type._tcp: name']. Skipped if no tool."""
    tool = "dns-sd" if IS_MAC else "avahi-browse"
    if not shutil.which(tool):
        return {}
    return (_mdns_mac if IS_MAC else _mdns_linux)(info, wait)
