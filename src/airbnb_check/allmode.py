"""`all` mode: vendor list + Wi-Fi in the background, network scan, then one clear verdict and the physical checklist."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from . import __version__, checklist, net, oui, reexec, report, wifi
from .classify import KINDS
from .messages import lines, t
from .net import ScanError
from .scan import ScanResult, run_scan
from .textutil import clean, md
from .ui import Term
from .verdict import Final, decide

PASS_GAP = 5.0


@dataclass
class AllResult:
    oui_msg: str
    scan: ScanResult
    wifi: dict = field(default_factory=dict)       # wifi.analyze() output, or {"error": ...}
    final: Final | None = None
    seconds: float = 0.0


def _oui_step(offline: bool) -> str:
    if offline:
        return t("oui_skip")
    if oui.cache_path().exists() and not oui.is_stale():
        return t("oui_fresh")
    try:
        return t("oui_ok", n=oui.update(timeout=20))
    except Exception as e:  # noqa: BLE001 - a hostile network can break the download in many ways; the scan goes on
        return t("oui_fail", err=clean(e, 60))


def _wifi() -> dict:
    try:
        return wifi.analyze(wifi.scan_wifi())
    except Exception as e:  # noqa: BLE001 - this extra check never stops the network scan
        return {"error": clean(e, 80), "seen": 0, "redacted": 0, "flagged": []}


def run_all(a, raw_args: list[str], term: Term) -> AllResult:
    t0 = time.monotonic()
    info = net.detect()
    reexec.check_early(info, raw_args, term.say)  # may re-run the whole process under Apple's python
    term.say(term.paint(f"\n  airbnb-check {__version__}", "bold", err=True))
    term.say(term.paint(f"  {t('tagline')}", "dim", err=True))
    term.say(term.paint(f"  {info.iface or '?'}  {info.ip}  network {info.network}  gateway {info.gateway or '?'}"
                        + ("  (netmask larger than /24: scanning only your /24)" if info.clamped else ""), "dim", err=True))
    term.say()
    with ThreadPoolExecutor(2) as ex:
        f_oui, f_wifi = ex.submit(_oui_step, a.offline), ex.submit(_wifi)
        scan = run_scan(info, term, a.timeout, a.full, passes=2, gap=PASS_GAP,
                        oui_table=lambda: (f_oui.result(), oui.load())[1], oui_note=f_oui.result)
        with term.step(t("s_wifi")) as st:
            w = f_wifi.result()
            st.done(w["error"] if w.get("error") else t("wifi_seen", n=w["seen"], k=len(w["flagged"])), ok=not w.get("error"))
    return AllResult(f_oui.result(), scan, w, decide(scan.devices, w["flagged"], scan.problems), time.monotonic() - t0)


def _wifi_lines(r: AllResult) -> list[str]:
    w, out = r.wifi, []
    if w.get("error"):
        return [t("wifi_unavail", err=w["error"])]
    for ssid, hit, strong in w["flagged"]:
        out.append(t("wifi_flag", ssid=ssid, hit=hit, strong=t("wifi_strong") if strong else ""))
    if w["redacted"]:
        out.append(t("wifi_redacted"))
    elif not w["flagged"]:
        out.append(t("wifi_none"))
    return out


def _kinds(f: Final) -> str:
    return ", ".join(f"{f.counts[k]} {t('k_' + k)}" for k in KINDS if k in f.counts)


def _verdict_box(r: AllResult, term: Term) -> str:
    f, s = r.final, term.sym
    todo = lines("cam_todo")
    if f.result == "camera":
        body = [t("cam_sub", n=len(f.cameras))]
        for d in f.cameras:
            body += [f"  {s['dot']} {d.ip}  {d.vendor or d.hostname or d.name}", f"      {d.detail}"]
            body += [f"      {x}" for _, x in d.reasons[1:3]]
        body += ["", todo[0]] + [f"  {i}. {x}" for i, x in enumerate(todo[1:], 1)]
        return term.box(f"{s['bad']}  {t('v_camera')}", body, "red")
    if f.result == "suspicious":
        body = [t("susp_sub")]
        for d in f.suspects:
            body += [f"  {s['dot']} {d.ip}  {d.vendor or d.hostname or d.name}", f"      {d.detail}",
                     "      " + t("susp_dev", ip=d.ip, vendor=f" ({d.vendor})" if d.vendor else "")]
        body += [f"  {s['dot']} " + t("susp_ssid", ssid=x) for x in f.ssids]
        return term.box(f"{s['warn']}  {t('v_susp')}", body, "yellow")
    if f.result == "inconclusive":
        return term.box(f"{s['warn']}  {t('v_inconclusive')}", [t("incon_sub")] + [f"  {s['dot']} {x}" for x in f.problems], "yellow")
    return term.box(f"{s['ok']}  {t('v_clear')}", [t("checked", n=f.total, kinds=_kinds(f))], "green")


def format_text(r: AllResult, term: Term) -> str:
    s = r.scan
    out = ["", report.format_table(s, term)]
    out += ["", *(term.paint(f"Note: {n}", "dim") for n in s.notes)] if s.notes else []
    out += ["", *(term.paint(x, "dim") for x in _wifi_lines(r)), "", _verdict_box(r, term), "",
            term.paint(t("honest"), "bold"), term.rule(t("h_checklist")), checklist.render_quick(),
            term.paint(t("full_list"), "dim"), "", term.paint(t("done", s=f"{r.seconds:.0f}"), "dim")]
    return "\n".join(out)


def to_dict(r: AllResult) -> dict:
    f, w = r.final, dict(r.wifi)
    w["flagged"] = [{"ssid": a, "pattern": b, "strong": c} for a, b, c in r.wifi.get("flagged", [])]
    return {"scan": report.to_dict(r.scan), "wifi": w, "seconds": round(r.seconds, 1),
            "verdict": {"result": f.result, "total_devices": f.total, "kinds": f.counts,
                        "cameras": [d.ip for d in f.cameras], "suspects": [d.ip for d in f.suspects],
                        "suspicious_ssids": f.ssids, "problems": f.problems, "limits": lines("limits")}}


def to_json(r: AllResult) -> str:
    return json.dumps(to_dict(r), indent=2, ensure_ascii=False)


def to_markdown(r: AllResult) -> str:
    s, f = r.scan, r.final
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    title = t({"camera": "v_camera", "suspicious": "v_susp", "inconclusive": "v_inconclusive",
                "clear": "v_clear"}[f.result])
    out = ["# airbnb-check report", "", f"- Date: {stamp}",
           f"- Network: {md(s.info.network)} (interface {md(s.info.iface)}, gateway {md(s.info.gateway)})",
           f"- Scan: {t('passes', n=s.passes, gap=f'{s.gap:g}')}", "", f"## Verdict: {title}", ""]
    if f.result == "clear":
        out.append(md(t("checked", n=f.total, kinds=_kinds(f)), 300))
    out += [f"- Camera: {md(d.ip)} {md(d.detail, 200)}" for d in f.cameras]
    out += [f"- Suspicious: {md(d.ip)} {md(d.detail, 200)}" for d in f.suspects]
    out += [f"- Suspicious Wi-Fi name: {md(x)}" for x in f.ssids]
    out += [f"- Check problem: {md(x, 200)}" for x in f.problems]
    out += ["", t("honest"), "", f"**{t('limits_title')}**", ""] + [f"- {x}" for x in lines("limits")]
    out += ["", "## Devices", ""] + report.md_devices(s)
    out += [f"- Note: {md(n, 300)}" for n in s.notes]
    out += ["", "## Nearby Wi-Fi", ""] + [f"- {md(x, 300)}" for x in _wifi_lines(r)]
    out += ["", "## Physical check", "", "```", checklist.render(), "```", ""]
    return "\n".join(out)
