"""All user-facing text (English only)."""
from __future__ import annotations

MSG: dict[str, str] = {
    "tagline": "hidden-camera check for the Wi-Fi you are on  (read-only, nothing is installed or changed)",
    "s_find": "Finding devices", "s_probe": "Probing services", "s_names": "Identifying devices",
    "s_deep": "Deep check of unidentified devices", "s_wifi": "Nearby Wi-Fi",
    "d_find": "{n} devices (2 passes, some cameras sleep)", "d_probe": "{n} open ports",
    "d_names": "{n} names found, vendor list: {oui}", "d_deep": "{n} device(s), up to 65535 ports each",
    "d_deep_none": "everything was identified, nothing to dig into",
    "oui_fresh": "up to date", "oui_ok": "downloaded ({n} prefixes)", "oui_fail": "unavailable ({err})", "oui_skip": "offline mode",
    "th": "STATUS|IP|WHAT IT IS|PORTS|NAME / VENDOR",
    "st_ok": "ok", "st_review": "REVIEW", "st_camera": "CAMERA",
    "k_router": "router", "k_self": "this computer", "k_mobile": "phone / tablet / laptop", "k_tv": "TV / media",
    "k_printer": "printer", "k_iot": "smart-home / IoT", "k_camera": "CAMERA", "k_unknown": "other (not a camera)",
    "v_camera": "CAMERA FOUND", "v_susp": "SUSPICIOUS DEVICE", "v_clear": "NO CAMERA ON THIS NETWORK",
    "v_inconclusive": "NOT SURE: SOME CHECKS FAILED",
    "incon_sub": "No camera was found, but this does NOT mean the network is clean, because:",
    "p_alone": "no other device answered (guest isolation or a failed scan), so nothing could be checked",
    "p_arp": "MAC addresses were unreadable, so the maker/private-MAC checks did not run",
    "p_disc": "{what} discovery failed",
    "p_device": "{ip} could not be analyzed",
    "checked": "Checked {n} devices, all identified: {kinds}.",
    "cam_sub": "{n} camera(s) on this network:",
    "cam_todo": "What to do:|Photograph it and where it sits. Do not touch or unplug it.|Leave if you feel unsafe.|"
                "Report it in the Airbnb app (cameras inside are banned) and ask for a refund.|"
                "In a bedroom or bathroom it is a crime in most places: call the police.",
    "susp_sub": "Camera-like signals, but no proof. Check these physically:",
    "susp_dev": "Find the gadget behind {ip}{vendor}: look at chargers, plugs, clocks, smoke detectors, speakers and shelves, "
                "especially facing the bed or shower. Ask the host what it is.",
    "susp_ssid": "Wi-Fi '{ssid}' looks like a camera hotspot and is strong, so it is probably in the room. Walk around and see "
                 "where the signal grows, then inspect that spot.",
    "honest": "A network check cannot see cameras that use 4G or only record to an SD card. Do the 2-minute physical check below.",
    "h_checklist": "Physical check (2 minutes)", "full_list": "Full list: airbnb-check checklist",
    "wifi_seen": "{n} Wi-Fi networks seen, {k} with camera-like names.",
    "wifi_none": "No camera-like network names nearby.",
    "wifi_redacted": "macOS hid the Wi-Fi names (it needs Location permission), so this extra check was skipped. "
                     "It does not change the network result above.",
    "wifi_unavail": "Could not list Wi-Fi networks ({err}); this extra check was skipped.",
    "wifi_flag": "SSID '{ssid}' looks like {hit}{strong}", "wifi_strong": " with a STRONG signal (probably inside the unit)",
    "notes_arp": "MAC addresses were unreadable, so private-MAC and vendor hints are missing. On macOS allow your terminal under "
                 "System Settings > Privacy & Security > Local Network.",
    "done": "Done in {s} s.",
    "passes": "Discovery ran in {n} passes about {gap} s apart and results were merged, because some cameras sleep.",
    "limits_title": "What this check cannot see:",
    "limits": "A different VLAN or separate guest network than the one you joined|4G/cellular cameras or anything not on this Wi-Fi|"
              "SD-card-only recorders|Devices that are powered off or asleep during the scan",
    "report_written": "Report written to {path}",
}


def t(key: str, **kw: object) -> str:
    s = MSG[key]
    return s.format(**kw) if kw else s


def lines(key: str) -> list[str]:
    """A '|'-separated message as a list."""
    return MSG[key].split("|")
