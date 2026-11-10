"""`all` mode: vendor DB -> network scan (2 passes) -> nearby Wi-Fi -> verdict + checklist."""
from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from . import checklist, oui, reexec, report, wifi
from .i18n import limits, t
from .net import ScanError
from .scan import ScanResult, run_scan
from .score import LEVELS
from .verdict import Verdict, aggregate

WIDTH = 78
PASS_GAP = 5.0


@dataclass
class AllResult:
    lang: str
    oui_msg: str
    scan: ScanResult
    wifi: dict = field(default_factory=dict)       # analyze() output, or {"error": ...}
    verdict: Verdict | None = None


def _oui_step(offline: bool, lang: str) -> str:
    if offline:
        return t(lang, "oui_skip")
    if oui.cache_path().exists() and not oui.is_stale():
        return t(lang, "oui_fresh")
    try:
        return t(lang, "oui_ok", n=oui.update(timeout=20))
    except (OSError, ValueError) as e:
        return t(lang, "oui_fail", err=e)


def run_all(a, raw_args: list[str], step: Callable[[str], None], detail: Callable[[str], None]) -> AllResult:
    lang = a.lang
    step(t(lang, "p_oui"))
    oui_msg = _oui_step(a.offline, lang)
    step("  " + oui_msg)
    step(t(lang, "p_net"))
    scan = run_scan(a.timeout, a.full, detail, passes=2, gap=PASS_GAP,
                    early=lambda info: reexec.check_early(info, raw_args, step))
    step(t(lang, "p_wifi"))
    try:
        w = wifi.analyze(wifi.scan_wifi())
    except ScanError as e:
        w = {"error": str(e), "seen": 0, "redacted": 0, "flagged": []}
    return AllResult(lang, oui_msg, scan, w, aggregate(scan.devices, w["flagged"]))


def _wifi_lines(r: AllResult) -> list[str]:
    w, lang, out = r.wifi, r.lang, []
    if w.get("error"):
        return [t(lang, "wifi_unavail", err=w["error"])]
    out.append(t(lang, "wifi_seen", n=w["seen"], k=len(w["flagged"])))
    for ssid, hit, strong in w["flagged"]:
        out.append("  - " + t(lang, "wifi_flag", ssid=ssid, hit=hit, strong=t(lang, "wifi_strong") if strong else ""))
    if not w["flagged"] and not w["redacted"]:
        out.append(t(lang, "wifi_none"))
    if w["redacted"]:
        out.append(t(lang, "wifi_redacted", n=w["redacted"]))
    return out


def _verdict_lines(r: AllResult) -> list[str]:
    lang, v = r.lang, r.verdict
    lines = [t(lang, "overall", level=v.level_name), t(lang, v.key), ""]
    if v.flags:
        lines.append(t(lang, "flagged"))
        for f in v.flags:
            lines.append(f"  [{LEVELS[f.level]}] {f.subject}")
            lines += [f"      - {x}" for x in f.reasons[:4]]
    else:
        lines.append(t(lang, "flagged_none"))
    lines += ["", t(lang, "limits_title")] + [f"  - {x}" for x in limits(lang)]
    return lines


def _box(lines: list[str]) -> str:
    wrapped = []
    for ln in lines:
        indent = " " * (len(ln) - len(ln.lstrip()))
        wrapped += textwrap.wrap(ln, WIDTH - 4, subsequent_indent=indent + ("  " if ln.lstrip().startswith("-") else ""),
                                 replace_whitespace=False) or [""]
    bar = "+" + "-" * (WIDTH - 2) + "+"
    return "\n".join([bar] + [f"| {ln:<{WIDTH - 4}} |" for ln in wrapped] + [bar])


def _head(title: str) -> str:
    return f"\n=== {title} ==="


def format_text(r: AllResult, color: bool) -> str:
    lang, s = r.lang, r.scan
    info = s.info
    out = [_head(t(lang, "h_oui")), r.oui_msg,
           _head(t(lang, "h_net")), f"{info.network}  (interface {info.iface}, gateway {info.gateway or '?'})",
           t(lang, "passes", n=s.passes, gap=f"{s.gap:g}"), "",
           report.format_table(s, color, summary=False),
           _head(t(lang, "h_wifi"))] + _wifi_lines(r) + [
           _head(t(lang, "h_verdict")), _box(_verdict_lines(r)),
           _head(t(lang, "h_checklist")), checklist.render(lang)]
    if not s.oui_loaded:
        out.append("\n" + report.HINT_OUI)
    return "\n".join(out)


def to_dict(r: AllResult) -> dict:
    w = dict(r.wifi)
    w["flagged"] = [{"ssid": a, "pattern": b, "strong": c} for a, b, c in r.wifi.get("flagged", [])]
    return {"lang": r.lang, "oui": r.oui_msg, "scan": report.to_dict(r.scan), "wifi": w,
            "verdict": {"level": r.verdict.level_name, "summary": t(r.lang, r.verdict.key),
                        "flagged": [{"kind": f.kind, "subject": f.subject, "level": LEVELS[f.level], "reasons": f.reasons}
                                    for f in r.verdict.flags],
                        "limits": limits(r.lang)}}


def to_json(r: AllResult) -> str:
    return json.dumps(to_dict(r), indent=2, ensure_ascii=False)


def to_markdown(r: AllResult) -> str:
    lang, s = r.lang, r.scan
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    out = ["# airbnb-check report", "", f"- Date: {stamp}",
           f"- Network: {s.info.network} (interface {s.info.iface}, gateway {s.info.gateway})",
           f"- Scan: {'all ports' if s.full else 'camera ports'}, {t(lang, 'passes', n=s.passes, gap=f'{s.gap:g}')}", "",
           f"## {t(lang, 'h_verdict')}", "", f"**{t(lang, 'overall', level=r.verdict.level_name)}**", "", t(lang, r.verdict.key), ""]
    out += [f"- [{LEVELS[f.level]}] {f.subject}: " + "; ".join(f.reasons[:4]) for f in r.verdict.flags] or [t(lang, "flagged_none")]
    out += ["", f"**{t(lang, 'limits_title')}**", ""] + [f"- {x}" for x in limits(lang)]
    out += ["", f"## {t(lang, 'h_oui')}", "", r.oui_msg, "", f"## {t(lang, 'h_net')}", ""] + report.md_devices(s)
    out += [f"- Note: {n}" for n in s.notes]
    out += ["", f"## {t(lang, 'h_wifi')}", ""] + [f"- {x.strip(' -')}" if x.startswith("  -") else x + "  " for x in _wifi_lines(r)]
    out += ["", f"## {t(lang, 'h_checklist')}", "", "```", checklist.render(lang), "```", ""]
    return "\n".join(out)
