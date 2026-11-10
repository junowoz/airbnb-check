"""MAC vendor lookup from the IEEE OUI CSV (downloaded only by `update-oui`)."""
from __future__ import annotations

import csv
import io
import os
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .textutil import clean

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
MAX_BYTES = 10 * 1024 * 1024


def cache_path() -> Path:
    """AIRBNB_CHECK_CACHE (a directory) wins; run.sh points it at a temp dir so nothing persists."""
    override = os.environ.get("AIRBNB_CHECK_CACHE")
    if override:
        return Path(override) / "oui.csv"
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "airbnb-check" / "oui.csv"


class _HttpsOnly(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise URLError("refusing redirect to non-HTTPS URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_oui(text: str) -> dict[str, str]:
    """Parse IEEE CSV (Registry,Assignment,Organization Name,...) into {'AABBCC': 'Org'}."""
    table: dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and len(row[1]) == 6 and all(c in "0123456789ABCDEFabcdef" for c in row[1]):
            table[row[1].upper()] = clean(row[2], 60)
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


def is_stale(path: Path | None = None, days: int = 90) -> bool:
    p = path or cache_path()
    try:
        return time.time() - p.stat().st_mtime > days * 86400
    except OSError:
        return True


def update(path: Path | None = None, timeout: float = 60) -> int:
    """Download the IEEE CSV over HTTPS (size-capped) and replace the cache atomically; returns number of entries."""
    p = path or cache_path()
    if not OUI_URL.startswith("https://"):
        raise ValueError("vendor list URL must be HTTPS")
    with build_opener(_HttpsOnly).open(Request(OUI_URL, headers={"User-Agent": "airbnb-check"}), timeout=timeout) as r:
        raw, end = b"", time.monotonic() + timeout
        while len(raw) <= MAX_BYTES:
            chunk = r.read(65536)
            if not chunk:
                break
            raw += chunk
            if time.monotonic() > end:  # a slow-drip server on a hostile network must not stall the scan
                raise ValueError("vendor list download too slow; giving up")
    if len(raw) > MAX_BYTES:
        raise ValueError("vendor list is larger than 10 MB; refusing it")
    data = raw.decode("utf-8", "replace")
    entries = len(parse_oui(data))
    if not entries:
        raise ValueError("downloaded file did not look like the IEEE OUI CSV")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(data, encoding="utf-8")
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)
    return entries
