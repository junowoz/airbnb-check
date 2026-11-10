"""Scan orchestration: discovery -> probes -> names and vendors -> classification -> deep pass on what is left."""
from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from . import net, oui, probe
from .classify import classify, needs_deep
from .messages import t
from .score import Device, banner_text, score  # noqa: F401
from .ui import Term


@dataclass
class ScanResult:
    info: net.NetInfo
    devices: list[Device]
    oui_loaded: bool
    full: bool
    notes: list[str] = field(default_factory=list)
    passes: int = 1
    gap: float = 0.0
    problems: list[str] = field(default_factory=list)  # anything that makes a green answer dishonest


def _safe(fn: Callable[[], dict], what: str, failed: list[str]) -> dict:
    """Run one discovery method; whatever goes wrong (including hostile input) is recorded, never fatal."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        if what not in failed:
            failed.append(what)
        return {}


def _discover(info: net.NetInfo, timeout: float, failed: list[str]):
    with ThreadPoolExecutor(3) as ex:
        f_ssdp = ex.submit(_safe, lambda: net.ssdp(info), "SSDP", failed)
        f_wsd = ex.submit(_safe, lambda: net.wsd_onvif(info), "ONVIF", failed)
        f_mdns = ex.submit(_safe, lambda: net.mdns(info), "mDNS", failed)
        alive = net.sweep(info.network, timeout)
        upnp, onvif, mdns = f_ssdp.result(), f_wsd.result(), f_mdns.result()
    return alive, upnp, onvif, mdns, net.arp_table(info)


def _merge_pass(acc: dict, found: tuple) -> None:
    alive, upnp, onvif, mdns, arp = found
    acc["alive"] |= alive
    for ip, d in upnp.items():
        cur = acc["upnp"].setdefault(ip, {})
        cur.update({k: v for k, v in d.items() if k != "types"})
        cur["types"] = " ".join(sorted(set(cur.get("types", "").split()) | set(d.get("types", "").split())))
    acc["onvif"].update(onvif)
    for ip, items in mdns.items():
        cur = acc["mdns"].setdefault(ip, [])
        cur += [x for x in items if x not in cur]
    acc["arp"].update(arp)


def run_scan(info: net.NetInfo, term: Term, timeout: float = 1.0, full: bool = False, passes: int = 2,
             gap: float = 5.0, oui_table: Callable[[], dict] = oui.load, oui_note: Callable[[], str] = lambda: "") -> ScanResult:
    net.check_target(info.network)
    net.raise_fd_limit()
    acc: dict = {"alive": set(), "upnp": {}, "onvif": {}, "mdns": {}, "arp": {}}
    failed: list[str] = []
    with term.step(t("s_find")) as st:
        for i in range(passes):
            if i:
                st.update(f"waiting {gap:g} s before pass {i + 1}")
                time.sleep(gap)
            st.update(f"pass {i + 1}/{passes}: ping sweep, SSDP, ONVIF, mDNS")
            _merge_pass(acc, _discover(info, timeout, failed))
        arp = acc["arp"]
        hosts = acc["alive"] | set(arp) | set(acc["upnp"]) | set(acc["onvif"]) | set(acc["mdns"]) | {info.ip}
        if info.gateway:
            hosts.add(info.gateway)
        edge = (info.network.network_address, info.network.broadcast_address)
        hosts = {h for h in hosts if (a := ipaddress.ip_address(h)) in info.network and a not in edge}
        order = sorted(hosts, key=ipaddress.ip_address)
        targets = [h for h in order if h != info.ip]
        st.done(t("d_find", n=len(order)))

    ports = range(1, 65536) if full else probe.CAMERA_PORTS
    with term.step(t("s_probe")) as st:
        st.update(f"{len(targets)} hosts")
        open_by = probe.open_ports(targets, ports, min(timeout, 1.0))
        banners = probe.grab_banners(open_by, max(timeout, 1.5))
        st.done(t("d_probe", n=sum(map(len, open_by.values()))))

    with term.step(t("s_names")) as st:
        st.update("reverse DNS, NetBIOS, vendor list")
        with ThreadPoolExecutor(2) as ex:
            f_dns, f_nb = ex.submit(net.reverse_dns, targets), ex.submit(net.netbios, targets)
            table = oui_table()
            rdns, nbt = f_dns.result(), f_nb.result()
        devices, failed_devices = [], []
        for ip in order:
            mac, u = arp.get(ip, ""), acc["upnp"].get(ip, {})
            m = acc["mdns"].get(ip, [])
            d = Device(ip=ip, mac=mac, vendor=oui.lookup(mac, table) if mac else "",
                       local_admin=bool(mac) and oui.is_locally_administered(mac),
                       is_self=ip == info.ip, is_gateway=ip == info.gateway, ports=open_by.get(ip, []),
                       banners=banners.get(ip, {}), upnp=u, onvif=acc["onvif"].get(ip), mdns=m)
            d.hostname = next((x[6:] for x in m if x.startswith("host: ")), "") or rdns.get(ip) or nbt.get(ip, "")
            d.name = u.get("name") or u.get("model") or next((x.split(": ", 1)[-1] for x in m if not x.startswith("host: ")), "")
            try:
                devices.append(classify(score(d)))
            except Exception:  # noqa: BLE001 - a device we could not analyze is never a green one
                d.kind, d.suspect, d.detail = "unknown", True, "could not be analyzed"
                devices.append(d)
                failed_devices.append(ip)
        st.done(t("d_names", n=sum(1 for d in devices if d.hostname or d.name), oui=oui_note() or "-"))

    deep_targets = [d for d in devices if needs_deep(d)]
    with term.step(t("s_deep")) as st:
        if deep_targets:
            st.update(", ".join(d.ip for d in deep_targets[:6]) + (" ..." if len(deep_targets) > 6 else ""))
            _deep(deep_targets, timeout)
            st.done(t("d_deep", n=len(deep_targets)))
        else:
            st.done(t("d_deep_none"))
    no_arp = not arp and len(hosts) > 1
    notes = [t("notes_arp")] if no_arp else []
    problems = [t("p_disc", what=w) for w in failed] + [t("p_device", ip=ip) for ip in failed_devices]
    problems += [t("p_alone")] if not targets else []
    problems += [t("p_arp")] if no_arp else []
    return ScanResult(info, devices, bool(table), full, notes, passes, gap if passes > 1 else 0.0, problems)


def _deep(devices: list[Device], timeout: float) -> None:
    """Every TCP port, banners, RTSP DESCRIBE and HTTP title/Server on every open port; then classify again."""
    found = probe.deep_scan([d.ip for d in devices], min(timeout, 0.3))
    banners = probe.grab_banners({ip: ports for ip, (ports, _) in found.items()}, max(timeout, 1.5), deep=True)
    for d in devices:
        ports, done = found[d.ip]
        d.ports = sorted(set(d.ports) | set(ports))
        d.banners.update(banners.get(d.ip, {}))
        d.deep, d.scanned = True, done
        try:
            classify(score(d))
        except Exception:  # noqa: BLE001 - never turn a device we could not analyze into a cleared one
            d.kind, d.suspect, d.detail = "unknown", True, "could not be analyzed"
