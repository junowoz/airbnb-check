"""Scan orchestration: discovery -> probes -> vendor lookup -> scoring."""
from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from . import net, oui, probe
from .score import Device, score


@dataclass
class ScanResult:
    info: net.NetInfo
    devices: list[Device]
    oui_loaded: bool
    full: bool
    notes: list[str] = field(default_factory=list)
    passes: int = 1
    gap: float = 0.0


def _safe(fn: Callable[[], dict], say: Callable[[str], None], what: str) -> dict:
    try:
        return fn()
    except OSError as e:
        say(f"  {what} skipped: {e}")
        return {}


def _discover(info: net.NetInfo, timeout: float, say: Callable[[str], None]):
    with ThreadPoolExecutor(3) as ex:
        f_ssdp = ex.submit(_safe, lambda: net.ssdp(info), say, "SSDP")
        f_wsd = ex.submit(_safe, lambda: net.wsd_onvif(info), say, "ONVIF")
        f_mdns = ex.submit(_safe, lambda: net.mdns(info), say, "mDNS")
        alive = net.sweep(info.network, timeout)
        upnp, onvif, mdns = f_ssdp.result(), f_wsd.result(), f_mdns.result()
    return alive, upnp, onvif, mdns, net.arp_table(info)


def run_scan(timeout: float, full: bool, say: Callable[[str], None], passes: int = 1, gap: float = 5.0,
             early: Callable[[net.NetInfo], None] | None = None) -> ScanResult:
    info = net.detect()
    net.check_target(info.network)
    say(f"Interface {info.iface or '?'}  {info.ip}  network {info.network}  gateway {info.gateway or '?'}")
    if info.clamped:
        say(f"  (interface netmask is larger than /24; limiting scan to {info.network})")
    if early:
        early(info)  # may re-exec the whole process
    alive: set[str] = set()
    upnp: dict[str, dict[str, str]] = {}
    onvif: dict[str, str] = {}
    mdns: dict[str, list[str]] = {}
    arp: dict[str, str] = {}
    for i in range(passes):
        if i:
            say(f"Waiting {gap:g} s before discovery pass {i + 1} (some cameras sleep)...")
            time.sleep(gap)
        say(f"Discovering hosts, pass {i + 1}/{passes} (ping sweep + SSDP + ONVIF + mDNS)...")
        a, u, o, m, r = _discover(info, timeout, say)
        alive |= a
        for ip, d in u.items():
            upnp.setdefault(ip, {}).update(d)
        onvif.update(o)
        for ip, items in m.items():
            cur = mdns.setdefault(ip, [])
            cur += [x for x in items if x not in cur]
        arp.update(r)

    hosts = set(alive) | set(arp) | set(upnp) | set(onvif) | set(mdns) | {info.ip}
    if info.gateway:
        hosts.add(info.gateway)
    hosts = {h for h in hosts if ipaddress.ip_address(h) in info.network and ipaddress.ip_address(h) not in
             (info.network.network_address, info.network.broadcast_address)}
    order = sorted(hosts, key=ipaddress.ip_address)
    targets = [h for h in order if h != info.ip]
    ports = range(1, 65536) if full else probe.CAMERA_PORTS
    say(f"Probing {len(targets)} host(s) on {'all 65535' if full else len(probe.CAMERA_PORTS)} ports...")
    open_by = probe.open_ports(targets, ports, min(timeout, 1.0))
    banners = probe.grab_banners(open_by, max(timeout, 1.5))

    table = oui.load()
    devices = []
    for ip in order:
        mac = arp.get(ip, "")
        u = upnp.get(ip, {})
        d = Device(ip=ip, mac=mac, vendor=oui.lookup(mac, table) if mac else "",
                   local_admin=bool(mac) and oui.is_locally_administered(mac),
                   is_self=ip == info.ip, is_gateway=ip == info.gateway, ports=open_by.get(ip, []),
                   banners=banners.get(ip, {}), upnp=u, onvif=onvif.get(ip), mdns=mdns.get(ip, []))
        d.name = u.get("name") or u.get("model") or (d.mdns[0].split(": ", 1)[-1] if d.mdns else "")
        devices.append(score(d))
    notes = []
    if not arp and len(hosts) > 1:
        notes.append("ARP table came back empty: MAC addresses and vendors are unavailable. On macOS, allow your terminal "
                     "under System Settings > Privacy & Security > Local Network, or run `/usr/bin/python3 -m airbnb_check`. "
                     "Processes started by `uvx` cannot read MACs on macOS: use `uv tool install` or `./run.sh` instead.")
    return ScanResult(info, devices, bool(table), full, notes, passes, gap if passes > 1 else 0.0)
