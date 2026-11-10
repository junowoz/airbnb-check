"""Nearby Wi-Fi listing with camera-hotspot SSID heuristics."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .net import IS_MAC, ScanError, run

SSID_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(^|[^a-z])ipc(am)?([^a-z]|$)", "IPC / IPCAM"), (r"hdwificam", "HDWiFiCam"),
    (r"(^|[-_ ])cam([-_ 0-9]|$)", "CAM- / _CAM"), (r"v380", "V380"), (r"yoosee", "Yoosee"),
    (r"^esp[-_]", "ESP_ (ESP32/ESP8266 device)"), (r"(tuya|smartlife)[-_ ]?", "Tuya / SmartLife"),
    (r"^mv\d+", "MV + digits"), (r"camera", "'camera'"),
)


@dataclass
class Network:
    ssid: str
    signal_dbm: int | None = None
    signal_pct: int | None = None
    bssid: str = ""

    @property
    def strong(self) -> bool:
        return (self.signal_dbm is not None and self.signal_dbm >= -55) or (self.signal_pct is not None and self.signal_pct >= 70)


def flag_ssid(ssid: str) -> str | None:
    """Return the pattern name if the SSID looks like a camera hotspot."""
    for rx, name in SSID_PATTERNS:
        if re.search(rx, ssid, re.I):
            return name
    return None


def parse_macos(text: str) -> list[Network]:
    """Parse `system_profiler SPAirPortDataType` network blocks."""
    nets: list[Network] = []
    hdr_indent = name_indent = -1
    for line in text.splitlines():
        if not line.strip():
            continue
        indent, s = len(line) - len(line.lstrip()), line.strip()
        if s in ("Current Network Information:", "Other Local Wi-Fi Networks:"):
            hdr_indent, name_indent = indent, -1
        elif hdr_indent >= 0 and indent <= hdr_indent:
            hdr_indent = -1
        elif hdr_indent >= 0:
            if name_indent < 0:
                name_indent = indent
            if indent == name_indent and s.endswith(":"):
                nets.append(Network(s[:-1]))
            elif nets and (m := re.match(r"Signal / Noise:\s*(-?\d+) dBm", s)):
                nets[-1].signal_dbm = int(m.group(1))
    return nets


def parse_nmcli(text: str) -> list[Network]:
    nets = []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 3 and parts[2].isdigit():
            nets.append(Network(parts[0].replace("\\:", ":"), signal_pct=int(parts[2]), bssid=parts[1].replace("\\:", ":")))
    return nets


def scan_wifi() -> list[Network]:
    if IS_MAC:
        out = run(["system_profiler", "SPAirPortDataType"], timeout=40)
        if not out:
            raise ScanError("`system_profiler` returned nothing; cannot list Wi-Fi networks")
        return parse_macos(out)
    out = run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL", "dev", "wifi"], timeout=20)
    if not out:
        raise ScanError("`nmcli` not found or returned nothing (NetworkManager required on Linux)")
    return parse_nmcli(out)


def format_wifi(nets: list[Network]) -> str:
    if not nets:
        return "No Wi-Fi networks found."
    lines = [f"{'SSID':<32} {'SIGNAL':<12} FLAG"]
    redacted = 0
    for n in sorted(nets, key=lambda n: -(n.signal_dbm if n.signal_dbm is not None else (n.signal_pct or 0) - 100)):
        redacted += "redacted" in n.ssid.lower()
        sig = f"{n.signal_dbm} dBm" if n.signal_dbm is not None else f"{n.signal_pct}%" if n.signal_pct is not None else "?"
        hit = flag_ssid(n.ssid)
        flag = f"SUSPICIOUS: looks like {hit}" + (" and STRONG signal (probably inside the unit)" if n.strong else "") if hit else ""
        lines.append(f"{n.ssid[:31]:<32} {sig:<12} {flag}")
    if redacted:
        lines.append("\nmacOS hid SSIDs (<redacted>): grant Location permission to your terminal in "
                     "System Settings > Privacy & Security > Location Services, then retry.")
    lines.append("\nA hidden-camera hotspot is rare (most cameras join the host's Wi-Fi). Strong signal = close to you.")
    return "\n".join(lines)



def analyze(nets: list[Network]) -> dict:
    """Summary used by the `all` mode: counts and camera-like SSIDs (redacted names are not matched)."""
    hits = [(n.ssid, h, n.strong) for n in nets if (h := flag_ssid(n.ssid))]
    return {"seen": len(nets), "redacted": sum("redacted" in n.ssid.lower() for n in nets), "flagged": hits}
