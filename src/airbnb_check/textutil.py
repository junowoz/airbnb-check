"""Sanitizing of untrusted strings (banners, hostnames, SSIDs, mDNS/SSDP fields...) before they are shown or saved."""
from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]{0,200}(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")
# C0/C1 controls, DEL, soft hyphen, zero-width/bidi marks and overrides/isolates, line/paragraph separators, tag characters
_BAD = re.compile("[\x00-\x1f\x7f-\x9f\xad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]")
_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~&-])")


def clean(value: object, limit: int = 120) -> str:
    """Drop terminal escape sequences and control/bidi characters, collapse spaces, truncate."""
    s = _BAD.sub(" ", _ANSI.sub("", str(value)))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: max(0, limit - 3)] + "..."


def md(value: object, limit: int = 120) -> str:
    """clean() plus Markdown escaping, for report tables and lists."""
    return _MD.sub(r"\\\1", clean(value, limit))
