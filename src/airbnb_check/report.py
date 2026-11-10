"""Rendering: terminal table, JSON, Markdown report."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import TextIO

from .score import HIGH, LEVELS, LOW, MEDIUM, Device, verdict
from .scan import ScanResult

LIMITS = ("Limits: cannot see cameras on another VLAN/guest network, 4G/cellular cameras, SD-card-only "
          "recorders, or devices that are powered off. Always do the physical check too.")
POINTER = "Next: run `airbnb-check checklist` for the physical inspection checklist."
HINT_OUI = "Vendor unknown: run `airbnb-check update-oui` once (needs internet) to enable MAC vendor lookup."
COLORS = {HIGH: "1;31", MEDIUM: "33", LOW: "36"}


def use_color(stream: TextIO) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def _notes(d: Device) -> str:
    bits = [d.name]
    for b in d.banners.values():
        bits += [b.get("title", ""), b.get("server", "")]
        break
    if d.onvif is not None:
        bits.append("ONVIF")
    return "; ".join(dict.fromkeys(x for x in bits if x))[:46]


def _vendor(d: Device) -> str:
    return d.vendor or d.upnp.get("manufacturer", "") or ("(random MAC)" if d.local_admin else "?" if d.mac else "")


def format_table(res: ScanResult, color: bool, summary: bool = True) -> str:
    head = f"{'IP':<15} {'LEVEL':<12} {'MAC':<17} {'VENDOR':<26} {'PORTS':<16} NOTES"
    lines = [head, "-" * len(head)]
    for d in res.devices:
        ports = ",".join(map(str, d.ports[:6])) + ("+" if len(d.ports) > 6 else "")
        lab = f"{d.label:<12}"
        if color and not (d.is_self or d.is_gateway) and d.level in COLORS:
            lab = f"\033[{COLORS[d.level]}m{lab}\033[0m"
        lines.append(f"{d.ip:<15} {lab} {d.mac:<17} {_vendor(d)[:25]:<26} {ports:<16} {_notes(d)}")
    for d in res.devices:
        shown = [(l, t) for l, t in d.reasons if l > 0 or d.level > 0]
        if shown:
            lines.append(f"\n{d.ip} ({d.label}):")
            lines += [f"  [{LEVELS[l]}] {t}" for l, t in shown]
    lines += [""] + [f"Note: {n}" for n in res.notes]
    if summary:
        lines += [f"Verdict: {verdict(res.devices)}", LIMITS, POINTER]
    if summary and not res.oui_loaded:
        lines.append(HINT_OUI)
    return "\n".join(lines)


def to_dict(res: ScanResult) -> dict:
    return {"interface": res.info.iface, "ip": res.info.ip, "network": str(res.info.network),
            "gateway": res.info.gateway, "oui_loaded": res.oui_loaded, "verdict": verdict(res.devices),
            "notes": res.notes, "devices": [{"ip": d.ip, "label": d.label, "level": LEVELS[d.level], "mac": d.mac, "vendor": _vendor(d),
                         "name": d.name, "ports": d.ports, "banners": {str(p): b for p, b in d.banners.items()},
                         "upnp": d.upnp, "onvif": d.onvif, "mdns": d.mdns,
                         "reasons": [{"level": LEVELS[l], "text": t} for l, t in d.reasons]} for d in res.devices]}


def to_json(res: ScanResult) -> str:
    return json.dumps(to_dict(res), indent=2)


def md_devices(res: ScanResult) -> list[str]:
    out = ["| IP | Level | MAC | Vendor | Ports | Notes |", "|---|---|---|---|---|---|"]
    for d in res.devices:
        out.append(f"| {d.ip} | {d.label} | {d.mac} | {_vendor(d)} | {','.join(map(str, d.ports))} | {_notes(d)} |")
    for d in res.devices:
        if d.reasons:
            out += ["", f"### {d.ip} ({d.label})"] + [f"- [{LEVELS[l]}] {t}" for l, t in d.reasons]
    return out


def to_markdown(res: ScanResult) -> str:
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    out = [f"# airbnb-check report", "", f"- Date: {stamp}", f"- Network: {res.info.network} (interface {res.info.iface}, "
           f"gateway {res.info.gateway})", f"- Scan: {'all ports' if res.full else 'camera ports'}", "",
           f"**Verdict:** {verdict(res.devices)}", "", "| IP | Level | MAC | Vendor | Ports | Notes |", "|---|---|---|---|---|---|"]
    for d in res.devices:
        out.append(f"| {d.ip} | {d.label} | {d.mac} | {_vendor(d)} | {','.join(map(str, d.ports))} | {_notes(d)} |")
    for d in res.devices:
        if d.reasons:
            out += ["", f"### {d.ip} ({d.label})"] + [f"- [{LEVELS[l]}] {t}" for l, t in d.reasons]
    out += ["", f"> {LIMITS}", ""]
    return "\n".join(out)


def say_stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)
