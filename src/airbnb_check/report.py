"""Rendering: device table, JSON and Markdown report."""
from __future__ import annotations

import json
from datetime import datetime

from .messages import lines, t
from .scan import ScanResult
from .score import LEVELS, Device
from .textutil import md
from .ui import Term

KIND_STYLE = {"camera": ("red", "red")}


def _status(d: Device) -> tuple[str, str, str]:
    """(text key, first-cell style, row style)."""
    if d.kind == "camera":
        return "st_camera", "red", "red"
    if d.suspect:
        return "st_review", "yellow", "yellow"
    return "st_ok", "green", ""


def _who(d: Device) -> str:
    base = " ".join(x for x in (d.hostname or d.name, f"({d.vendor})" if d.vendor else "") if x)
    show = "" if d.kind in ("self", "router") else d.detail
    return " - ".join(x for x in (base, show) if x)


def _ports(d: Device) -> str:
    return ",".join(map(str, d.ports[:5])) + ("+" if len(d.ports) > 5 else "")


def _what(d: Device) -> str:
    return t(f"k_{d.kind}") + (" (?)" if d.suspect else "")


def format_table(res: ScanResult, term: Term) -> str:
    rows, styles = [], []
    for d in res.devices:
        key, first, rest = _status(d)
        rows.append([t(key), d.ip, _what(d), _ports(d), _who(d)])
        styles.append((first, rest))
    return term.table(t("th").split("|"), rows, styles, [8, 15, 26, 20, 0])


def to_dict(res: ScanResult) -> dict:
    return {"interface": res.info.iface, "ip": res.info.ip, "network": str(res.info.network),
            "gateway": res.info.gateway, "oui_loaded": res.oui_loaded, "notes": res.notes,
            "devices": [{"ip": d.ip, "kind": d.kind, "detail": d.detail, "suspect": d.suspect, "level": LEVELS[d.level],
                         "mac": d.mac, "vendor": d.vendor or d.upnp.get("manufacturer", ""), "hostname": d.hostname,
                         "name": d.name, "ports": d.ports, "ports_checked": d.scanned or None,
                         "banners": {str(p): b for p, b in d.banners.items()}, "upnp": d.upnp, "onvif": d.onvif,
                         "mdns": d.mdns, "reasons": [{"level": LEVELS[l], "text": x} for l, x in d.reasons]}
                        for d in res.devices]}


def to_json(res: ScanResult) -> str:
    return json.dumps(to_dict(res), indent=2, ensure_ascii=False)


def md_devices(res: ScanResult) -> list[str]:
    out = ["| IP | Kind | MAC | Name / vendor | Ports | Evidence |", "|---|---|---|---|---|---|"]
    for d in res.devices:
        who = " ".join(x for x in (d.hostname or d.name, d.vendor) if x)
        out.append(f"| {md(d.ip)} | {md(_what(d))} | {md(d.mac)} | {md(who)} | {md(','.join(map(str, d.ports)))} | {md(d.detail)} |")
    for d in res.devices:
        if d.reasons and (d.kind == "camera" or d.suspect):
            out += ["", f"### {md(d.ip)}"] + [f"- [{LEVELS[l]}] {md(x, 200)}" for l, x in d.reasons]
    return out
