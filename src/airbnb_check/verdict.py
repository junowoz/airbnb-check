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


@dataclass
class Final:
    """The one answer shown to the user: 'camera', 'suspicious' or 'clear'."""
    result: str
    cameras: list[Device]
    suspects: list[Device]
    ssids: list[str]            # camera-like Wi-Fi names with a strong signal
    counts: dict[str, int]      # how many devices of each kind
    total: int
    problems: list[str] = field(default_factory=list)   # checks that failed or could not see enough


def decide(devices: list[Device], ssid_hits: list[tuple[str, str, bool]], problems: list[str] | None = None) -> Final:
    """Camera beats suspicious beats inconclusive beats clear. A green answer needs every check to have worked.
    Weak-signal SSIDs are reported elsewhere and never change the answer."""
    cameras = [d for d in devices if d.kind == "camera"]
    suspects = [d for d in devices if d.suspect and d.kind != "camera"]
    ssids = [s for s, _, strong in ssid_hits if strong]
    counts: dict[str, int] = {}
    for d in devices:
        counts[d.kind] = counts.get(d.kind, 0) + 1
    problems = list(problems or [])
    result = ("camera" if cameras else "suspicious" if suspects or ssids else "inconclusive" if problems else "clear")
    return Final(result, cameras, suspects, ssids, counts, len(devices), problems)
