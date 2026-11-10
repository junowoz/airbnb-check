"""Per-device scoring: HIGH / MEDIUM / LOW / INFO with human-readable reasons."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

INFO, LOW, MEDIUM, HIGH = range(4)
LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH")

VENDOR_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("hikvision", HIGH), ("dahua", HIGH), ("ezviz", HIGH), ("reolink", HIGH), ("amcrest", HIGH),
    ("foscam", HIGH), ("imou", HIGH), ("uniview", HIGH), ("hanwha", HIGH), ("axis", HIGH),
    ("vivotek", HIGH), ("annke", HIGH), ("lorex", HIGH), ("swann", HIGH),
    ("wyze", MEDIUM), ("tuya", MEDIUM), ("arlo", MEDIUM), ("ring", MEDIUM), ("eufy", MEDIUM),
    ("anker", MEDIUM), ("yi", MEDIUM), ("kami", MEDIUM), ("hangzhou", MEDIUM), ("tp-link", MEDIUM),
    ("xiaomi", MEDIUM), ("espressif", MEDIUM), ("shenzhen", LOW),
)
BANNER_STRONG = ("hikvision", "dahua", "onvif", "xmeye", "netsurveillance", "ipcam", "ip camera")
BANNER_WEAK = ("camera", "webcam", "dvr", "nvr", "rtsp", "web service")
PORT_SIGNALS: dict[int, tuple[int, str]] = {
    34567: (HIGH, "port 34567 open (XMEye/DVR protocol)"),
    37777: (HIGH, "port 37777 open (Dahua protocol)"),
    554: (MEDIUM, "port 554 open (RTSP video streaming)"),
    8554: (MEDIUM, "port 8554 open (alternate RTSP)"),
    8000: (LOW, "port 8000 open (common on IP cameras, also other devices)"),
    1935: (LOW, "port 1935 open (RTMP video streaming)"),
}


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    local_admin: bool = False
    name: str = ""
    is_self: bool = False
    is_gateway: bool = False
    ports: list[int] = field(default_factory=list)
    banners: dict[int, dict[str, str]] = field(default_factory=dict)
    upnp: dict[str, str] = field(default_factory=dict)
    onvif: str | None = None
    mdns: list[str] = field(default_factory=list)
    level: int = INFO
    reasons: list[tuple[int, str]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "THIS DEVICE" if self.is_self else "ROUTER" if self.is_gateway else LEVELS[self.level]


def vendor_signal(vendor: str) -> tuple[int, str] | None:
    """Best camera-maker keyword match in a vendor string (whole words only)."""
    best = None
    for kw, lvl in VENDOR_KEYWORDS:
        if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", vendor.lower()) and (best is None or lvl > best[0]):
            best = (lvl, kw)
    return (best[0], best[1]) if best else None


def banner_signal(text: str) -> tuple[int, str] | None:
    t = text.lower()
    for kw in BANNER_STRONG:
        if kw in t:
            return HIGH, kw
    for kw in BANNER_WEAK:
        if re.search(rf"\b{re.escape(kw)}\b", t):
            return MEDIUM, kw
    return None


def _banner_text(d: Device) -> str:
    parts = [v for b in d.banners.values() for k, v in b.items() if k in ("server", "realm", "title")]
    return " ".join(parts + [d.upnp.get("model", ""), d.upnp.get("name", ""), d.upnp.get("server", "")])


def score(d: Device) -> Device:
    sig: list[tuple[int, str]] = []
    rtsp_ports = {p for p, b in d.banners.items() if b.get("proto") == "rtsp"}
    if d.onvif is not None:
        sig.append((HIGH, "answered an ONVIF WS-Discovery probe (IP-camera protocol)"))
    for p in sorted(rtsp_ports):
        sig.append((HIGH, f"RTSP server responds on port {p}"))
    for m in d.mdns:
        if m.startswith(("_rtsp._tcp", "_onvif._tcp")):
            sig.append((HIGH, f"advertises {m.split(':')[0]} via mDNS"))
    if not (d.is_self or d.is_gateway):  # routers/this machine only count on strong protocol evidence
        for text in (d.vendor, d.upnp.get("manufacturer", "")):
            if (v := vendor_signal(text)):
                sig.append((v[0], f"vendor matches camera maker keyword '{v[1]}' ({text})"))
        for p in d.ports:
            if p in PORT_SIGNALS and p not in rtsp_ports:
                sig.append(PORT_SIGNALS[p])
        if (b := banner_signal(_banner_text(d))):
            sig.append((b[0], f"banner/description mentions '{b[1]}'"))
    if d.local_admin:
        sig.append((INFO, "randomized (locally administered) MAC: vendor cannot be identified"))
    d.reasons = sorted(sig, key=lambda s: -s[0])
    d.level = max((s[0] for s in sig), default=INFO)
    if sum(1 for s in sig if s[0] == MEDIUM) >= 2:
        d.level = HIGH
    return d


def verdict(devices: list[Device]) -> str:
    others = [d for d in devices if not d.is_self]
    n = {lvl: sum(1 for d in others if d.level == lvl) for lvl in (HIGH, MEDIUM, LOW)}
    if n[HIGH]:
        return f"{n[HIGH]} device(s) look like cameras (HIGH). Investigate them physically."
    if n[MEDIUM]:
        return f"No certain cameras, but {n[MEDIUM]} device(s) are suspicious (MEDIUM). Identify each one."
    if n[LOW]:
        return f"No clear camera signals; {n[LOW]} device(s) with weak hints (LOW)."
    return "No camera signals found on this Wi-Fi. This does NOT prove the unit is camera-free."
