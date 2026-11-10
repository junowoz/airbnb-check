"""Overall verdict: worst device level and camera-like SSIDs, in one pure function."""
from __future__ import annotations

from dataclasses import dataclass, field

from .score import HIGH, INFO, LEVELS, LOW, MEDIUM, Device

_KEY = {HIGH: "v_high", MEDIUM: "v_medium", LOW: "v_low", INFO: "v_clear"}


@dataclass
class Flag:
    kind: str          # "device" or "ssid"
    subject: str       # IP or SSID
    level: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    level: int
    flags: list[Flag]

    @property
    def level_name(self) -> str:
        return LEVELS[self.level]

    @property
    def key(self) -> str:
        return _KEY[self.level]


def aggregate(devices: list[Device], ssid_hits: list[tuple[str, str, bool]]) -> Verdict:
    """ssid_hits: (ssid, pattern name, strong signal). A camera-like SSID is MEDIUM, HIGH when strong."""
    flags = []
    for d in devices:
        if d.is_self or d.level < LOW:
            continue
        label = f"{d.ip}" + (f" ({d.vendor})" if d.vendor else "")
        flags.append(Flag("device", label, d.level, [t for l, t in d.reasons if l >= LOW]))
    for ssid, hit, strong in ssid_hits:
        flags.append(Flag("ssid", ssid, HIGH if strong else MEDIUM, [hit]))
    flags.sort(key=lambda f: -f.level)
    return Verdict(max((f.level for f in flags), default=INFO), flags)
