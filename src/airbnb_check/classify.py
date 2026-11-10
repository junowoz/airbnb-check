"""Decide what each device is. Camera evidence comes from score(); this adds benign identities and the camera/suspect call.

Order matters: proof of a camera wins, then the router and the known harmless kinds (printer, TV/media, phone/laptop),
then camera-like hints (suspect), then smart-home gadgets. Whatever is left is "unknown" and gets the deep port pass;
after that pass, an unknown device without camera services is cleared.
"""
from __future__ import annotations

import re

from .score import HIGH, MEDIUM, Device, banner_text, vendor_signal

KINDS = ("router", "self", "mobile", "tv", "printer", "iot", "camera", "unknown")


def _rx(*parts: str) -> "re.Pattern[str]":
    return re.compile("|".join(parts), re.I)


MOBILE_HOST = _rx(r"iphone", r"ipad", r"ipod", r"galaxy", r"android", r"macbook", r"imac", r"mac-?mini", r"pixel",
                  r"oneplus", r"redmi", r"huawei", r"oppo", r"surface", r"laptop", r"thinkpad", r"^sm-[a-z]\d",
                  r"(^|[-_ ])(pc|desktop)([-_ ]|$)", r"windows", r"^win-", r"watch")
TV_HOST = _rx(r"(^|[^a-z])tv([^a-z]|$)", r"bravia", r"roku", r"chromecast", r"fire-?tv", r"webos", r"tizen", r"apple-?tv",
              r"homepod", r"sonos", r"echo", r"nest-?(hub|mini)")
PRINTER_HOST = _rx(r"printer", r"laserjet", r"officejet", r"deskjet", r"photosmart", r"epson", r"brother", r"canon", r"^mfc-")
IOT_HOST = _rx(r"^esp[-_]", r"shelly", r"tasmota", r"^wiz", r"tuya", r"plug", r"bulb", r"lamp", r"thermostat", r"hue")
TV_VENDOR = _rx(r"samsung", r"\blg\b", r"lg elec", r"sony", r"roku", r"vizio", r"tcl", r"hisense", r"google", r"amazon",
                r"sharp", r"panasonic", r"sonos", r"harman", r"bose")
ALWAYS_TV = _rx(r"roku", r"vizio", r"tcl", r"hisense", r"sonos")
PRINTER_VENDOR = _rx(r"canon", r"epson", r"brother", r"hewlett", r"\bhp\b", r"xerox", r"lexmark", r"ricoh", r"kyocera")
MOBILE_VENDOR = _rx(r"apple", r"samsung", r"\blg\b", r"lg elec", r"sony", r"huawei", r"oppo", r"oneplus", r"motorola",
                    r"google", r"realme", r"vivo", r"honor", r"nothing tech", r"xiaomi")
IOT_VENDOR = _rx(r"espressif", r"tuya", r"shelly", r"allterco", r"signify", r"philips lighting", r"sonoff", r"itead",
                 r"ecobee", r"nest labs", r"tp-?link", r"\bwiz\b", r"lifx", r"belkin", r"amazon", r"xiaomi", r"hangzhou",
                 r"shenzhen", r"murata", r"azurewave", r"liteon", r"realtek")
ROUTERISH = _rx(r"router", r"extender", r"repeater", r"access point", r"modem", r"mesh", r"gateway")
BRAND_CAMERAS = ("wyze", "arlo", "ring", "eufy", "anker", "yi", "kami")  # hints strong enough to review with no open port
TV_PORTS, PRINTER_PORTS = {8009, 8001, 8002, 7000}, {9100, 631, 515}
STREAM_PORTS = {554, 8554, 1935}  # video streaming ports: a "benign" name or maker never clears these
CAMERA_LIKE_PORTS = {80, 81, 443, 554, 1935, 5000, 8000, 8080, 8443, 8554, 8899, 9000, 34567, 37777}


def _top(d: Device, level: int) -> str:
    return next((t for l, t in d.reasons if l >= level), "")


def _services(d: Device) -> bool:
    return bool(d.ports or d.upnp.get("types") or any(not m.startswith("host:") for m in d.mdns))


def _mdns_has(d: Device, *types: str) -> bool:
    return any(m.startswith(types) for m in d.mdns)


def identify(d: Device) -> tuple[str, str]:
    """(kind, detail) for devices that are plainly not cameras; ("unknown", "") when nothing recognizable is there."""
    vendor = " ".join([d.vendor, d.upnp.get("manufacturer", "")]).strip()
    host = " ".join([d.hostname, d.name]).strip()
    types, ports = d.upnp.get("types", ""), set(d.ports)
    if ports & PRINTER_PORTS or _mdns_has(d, "_ipp.", "_printer.") or "printer" in types:
        return "printer", "printer service"
    if PRINTER_VENDOR.search(vendor) or PRINTER_HOST.search(host):
        return "printer", f"printer maker/name ({vendor or host})"
    if _mdns_has(d, "_googlecast.", "_airplay.") or re.search(r"mediarenderer|dial|mediaserver", types):
        return "tv", "Cast / AirPlay / DLNA media device"
    if ports & TV_PORTS or TV_HOST.search(host) or ALWAYS_TV.search(vendor) or (TV_VENDOR.search(vendor) and _services(d) and not MOBILE_HOST.search(host)):
        return "tv", f"TV/media ({vendor or host})"
    if MOBILE_HOST.search(host) or 62078 in ports:
        return "mobile", f"phone/laptop name ({host})" if host else "iPhone sync port"
    if d.local_admin and not _services(d):
        return "mobile", "private (random) MAC, no services"
    if MOBILE_VENDOR.search(vendor) and not _services(d):
        return "mobile", f"{vendor}, no services"
    if re.search(r"apple", vendor, re.I):
        return "mobile", "Apple device"
    if ROUTERISH.search(banner_text(d)):
        return "router", "network equipment (extender / access point)"
    return "unknown", ""


def _streaming_hint(d: Device) -> str:
    """Evidence a harmless-looking name, maker, MAC or role cannot explain away (all of it is set by the device itself)."""
    v = vendor_signal(d.vendor)
    if set(d.ports) & STREAM_PORTS or (v and v[1] in BRAND_CAMERAS):
        return _top(d, MEDIUM) or "video streaming port open"
    return ""


def classify(d: Device) -> Device:
    """Fill d.kind, d.detail and d.suspect from the evidence already on the device (call score() first)."""
    d.suspect = False
    if d.is_self:
        d.kind, d.detail = "self", ""
    elif any(l == HIGH for l, _ in d.reasons):  # protocol/maker proof, not two weak hints adding up
        d.kind, d.detail = "camera", _top(d, HIGH)
    elif d.is_gateway:  # the gateway comes from DHCP, so the host can name a camera as the "router"
        d.kind, d.detail = "router", d.vendor or "default gateway"
        d.suspect = bool(set(d.ports) & {554, 8554})
        if d.suspect:
            d.detail = _streaming_hint(d)
    else:
        d.kind, d.detail = identify(d)
        if d.kind != "unknown" and (hint := _streaming_hint(d)):
            d.suspect, d.detail = True, hint  # e.g. random MAC / "iPhone" name / printer port, yet RTSP is open
        if d.kind == "unknown":
            v = vendor_signal(d.vendor)
            hint = _top(d, MEDIUM)
            if hint and (bool(v and v[1] in BRAND_CAMERAS) or set(d.ports) & CAMERA_LIKE_PORTS):
                d.suspect, d.detail = True, hint
            elif IOT_VENDOR.search(d.vendor) or IOT_HOST.search(d.hostname) or _mdns_has(d, "_hap."):
                d.kind, d.detail = "iot", d.vendor or "smart-home name/service"
            elif hint:
                d.suspect, d.detail = True, hint
            elif d.deep:
                d.detail = "no camera services (" + ("all 65535 ports checked)" if d.scanned >= 65535 else f"{d.scanned} of 65535 ports checked in time)")
    return d


def needs_deep(d: Device) -> bool:
    """Devices that are still unknown or only suspected get the all-ports pass."""
    return not d.deep and not d.is_self and d.kind != "camera" and (d.kind == "unknown" or d.suspect)
