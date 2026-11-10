"""MAC vendor lookup from the IEEE OUI CSV (downloaded only by `update-oui`)."""
from __future__ import annotations

import csv
import io
import os
from pathlib import Path
from urllib.request import Request, urlopen

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "airbnb-check" / "oui.csv"


def parse_oui(text: str) -> dict[str, str]:
    """Parse IEEE CSV (Registry,Assignment,Organization Name,...) into {'AABBCC': 'Org'}."""
    table: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and len(row[1]) == 6 and all(c in "0123456789ABCDEFabcdef" for c in row[1]):
            table[row[1].upper()] = row[2].strip()
    return table


def load(path: Path | None = None) -> dict[str, str]:
    p = path or cache_path()
    try:
        return parse_oui(p.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def lookup(mac: str, table: dict[str, str]) -> str:
    key = "".join(c for c in mac if c.isalnum()).upper()[:6]
    if key == "000000":  # placeholder MAC some routers use on the LAN side, not a real vendor
        return ""
    return table.get(key, "")


def is_locally_administered(mac: str) -> bool:
    """Second-least-significant bit of the first octet: randomized/private MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0b10)
    except ValueError:
        return False


def update(path: Path | None = None) -> int:
    """Download the IEEE CSV over HTTPS to the cache; returns number of entries."""
    p = path or cache_path()
    req = Request(OUI_URL, headers={"User-Agent": "airbnb-check"})
    with urlopen(req, timeout=60) as r:
        data = r.read().decode("utf-8", "replace")
    table = parse_oui(data)
    if not table:
        raise ValueError("downloaded file did not look like the IEEE OUI CSV")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8")
    return len(table)
