"""Physical inspection checklist (English)."""
from __future__ import annotations

CHECKLIST: list[tuple[str, list[str]]] = [
    ("1. Dark-room sweep", [
        "Lights off, curtains closed. Slowly sweep a flashlight across the room: camera lenses glint back as a small bright dot.",
        "Open your phone's FRONT camera (many show infrared) and look for faint purple/white dots: IR LEDs of night-vision cameras.",
        "Look for tiny steady or blinking LEDs where no device should be.",
    ]),
    ("2. Typical hiding spots", [
        "Smoke detectors and sensors, clocks, USB chargers and power strips, speakers, picture frames.",
        "Wi-Fi routers, TV boxes, soundbars, air purifiers, tissue boxes, plants, books, shelves facing the bed or shower.",
        "Mirrors facing the bed or shower: press a fingertip on the glass; a gap between finger and reflection is normal for a normal mirror, no gap is suspicious for two-way mirrors.",
        "Anything pointing at the bed, shower, toilet or changing area; devices that are unplugged or have no reason to be there.",
    ]),
    ("3. Cross-checks", [
        "Investigate every device the scan marked REVIEW or CAMERA.",
        "Check the listing: Airbnb requires disclosure of cameras, and bans them indoors since 2024.",
    ]),
    ("4. If you find something", [
        "Do not touch or unplug it. Photograph it and where it sits. Keep the evidence.",
        "Leave if you feel unsafe. Report in the Airbnb app (and ask for a refund).",
        "Cameras in a bedroom or bathroom are a crime in most places: call the police.",
    ]),
]

QUICK: list[str] = ["Lights off, curtains shut, sweep a flashlight slowly: a lens glints back as a small bright dot.",
           "Open your phone's FRONT camera (it often sees infrared) and look for faint purple/white dots.",
           "Check smoke detectors, clocks, USB chargers, plugs, speakers, picture frames and shelves facing the bed or shower.",
           "Anything pointing at the bed, shower or toilet, or a plugged-in gadget with no reason to be there, deserves a closer look."]


def render_quick() -> str:
    return "\n".join(f"  [ ] {i}" for i in QUICK)


def render() -> str:
    out = []
    for title, items in CHECKLIST:
        out.append(title)
        out.extend(f"  [ ] {i}" for i in items)
        out.append("")
    return "\n".join(out).rstrip()
