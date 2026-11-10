"""Terminal UI with plain ANSI: colours, spinner steps, aligned tables and boxes.

Respects NO_COLOR and non-TTY output, and falls back to ASCII when the locale is not UTF-8.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
import threading
from typing import Iterable, Sequence, TextIO

from .textutil import clean

CODES = {"red": "1;31", "green": "1;32", "yellow": "1;33", "cyan": "36", "dim": "2", "bold": "1"}
UNI = {"ok": "✓", "warn": "!", "bad": "✗", "dot": "•", "spin": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "box": "╭╮╰╯─│", "rule": "─"}
ASC = {"ok": "ok", "warn": "!", "bad": "x", "dot": "-", "spin": "|/-\\", "box": "++++-|", "rule": "-"}


def is_utf8(stream: TextIO, env: dict | None = None) -> bool:
    env = os.environ if env is None else env
    loc = next((env[k] for k in ("LC_ALL", "LC_CTYPE", "LANG") if env.get(k)), "")
    if loc and "utf" not in loc.lower():
        return False
    return "utf" in (getattr(stream, "encoding", "") or "").lower()


class Term:
    def __init__(self, out: TextIO | None = None, err: TextIO | None = None, quiet: bool = False) -> None:
        self.out, self.err, self.quiet = out or sys.stdout, err or sys.stderr, quiet
        plain = bool(os.environ.get("NO_COLOR")) or os.environ.get("TERM") == "dumb"
        self.color = self.out.isatty() and not plain
        self.ecolor = self.err.isatty() and not plain
        self.live = self.err.isatty() and not quiet and os.environ.get("TERM") != "dumb"
        self.sym = UNI if is_utf8(self.out) and is_utf8(self.err) else ASC

    @property
    def width(self) -> int:
        return max(60, min(shutil.get_terminal_size((100, 24)).columns, 100))

    def paint(self, s: str, *styles: str, err: bool = False) -> str:
        if not (self.ecolor if err else self.color) or not styles:
            return s
        return f"\033[{';'.join(CODES[x] for x in styles)}m{s}\033[0m"

    def say(self, msg: str = "") -> None:
        if not self.quiet:
            print(msg, file=self.err, flush=True)

    def show(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    def step(self, title: str) -> "Step":
        return Step(self, title)

    def rule(self, title: str) -> str:
        line = self.sym["rule"] * max(3, self.width - len(title) - 4)
        return self.paint(f"\n{self.sym['rule'] * 2} {title} {line}", "bold")

    def box(self, title: str, lines: Iterable[str], style: str) -> str:
        """Bordered box; `lines` are wrapped to the box width, `title` is bold and coloured."""
        w, (tl, tr, bl, br, h, v) = min(self.width, 80), self.sym["box"]
        inner = w - 4
        rows = [(title, True)] + [("", False)] + [(x, False) for x in lines]
        body = []
        for text, strong in rows:
            ind = " " * (len(text) - len(text.lstrip()))
            for seg in textwrap.wrap(text, inner, subsequent_indent=ind + "  ") or [""]:
                pad = seg.ljust(inner)
                body.append(self.paint(v, style) + " " + (self.paint(pad, style) if strong else pad) + " " + self.paint(v, style))
        return "\n".join([self.paint(tl + h * (w - 2) + tr, style)] + body + [self.paint(bl + h * (w - 2) + br, style)])

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]], styles: Sequence[tuple[str, str]],
              widths: Sequence[int]) -> str:
        """Aligned table. The last column takes the remaining width; widths[i] is the max for the other columns.
        styles[i] = (style of the first cell, style of the rest of the row)."""
        cols = [min(w, max(len(headers[i]), *(len(clean(r[i])) for r in rows))) if rows else len(headers[i])
                for i, w in enumerate(widths[:-1])]
        last = max(10, self.width - sum(cols) - 2 * len(cols) - 2)
        cols.append(last)

        def line(cells: Sequence[str], first: str = "", rest: str = "") -> str:
            f = [self._fit(clean(c), n) for c, n in zip(cells, cols)]
            return self.paint(f[0], *filter(None, [first])) + "  " + self.paint("  ".join(f[1:]), *filter(None, [rest]))
        head = line(headers, "dim", "dim")
        return "\n".join([head] + [line(r, *s) for r, s in zip(rows, styles)])

    @staticmethod
    def _fit(s: str, n: int) -> str:
        return (s if len(s) <= n else s[: n - 1] + "~").ljust(n)


class Step:
    """`with term.step("Doing X") as st: ... st.update("half way"); st.done("result")`."""

    def __init__(self, term: Term, title: str) -> None:
        self.term, self.title, self.text, self.detail, self.ok = term, title, "", "", True
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def update(self, text: str) -> None:
        self.text = clean(text, 80)

    def done(self, detail: str = "", ok: bool = True) -> None:
        self.detail, self.ok = detail, ok

    def _spin(self) -> None:
        frames, i, t = self.term.sym["spin"], 0, self.term
        while not self._stop.wait(0.1):
            msg = f"  {frames[i % len(frames)]} {self.title}  {self.text}"[: t.width - 1]
            t.err.write("\r\033[K" + t.paint(msg, "cyan", err=True))
            t.err.flush()
            i += 1

    def __enter__(self) -> "Step":
        if self.term.live:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, et, ev, tb) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
            self.term.err.write("\r\033[K")
        if self.term.quiet:
            return
        ok = self.ok and et is None
        s = self.term.sym
        mark = self.term.paint(f"{s['ok'] if ok else s['warn']:<2}", "green" if ok else "yellow", err=True)
        detail = self.term.paint(self.detail, "dim", err=True) if self.detail else ""
        self.term.say(f"  {mark} {self.title}  {detail}".rstrip())
