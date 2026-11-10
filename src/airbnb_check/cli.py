"""Command-line interface for airbnb-check."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, allmode, checklist, i18n, oui, report, wifi
from .net import ScanError

COMMANDS = ("all", "scan", "wifi", "checklist", "update-oui")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--timeout", type=float, metavar="SEC", help="per-connection timeout in seconds (default 1.0)")
    common.add_argument("--lang", choices=i18n.LANGS, help="output language (default: from LANG / LC_ALL)")
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")
    common.add_argument("--report", nargs="?", const="", metavar="FILE.md",
                        help="also write a Markdown report (default name airbnb-check-YYYYMMDD-HHMM.md)")
    common.add_argument("--full", action="store_true", help="probe all ports 1-65535 (slow)")
    common.add_argument("--offline", action="store_true", help="never download anything (skip the vendor list update)")
    p = argparse.ArgumentParser(
        prog="airbnb-check", parents=[common],
        description="Defensive, read-only check of the Wi-Fi you are a guest on for hidden cameras. "
                    "Only scans your own private subnet; never logs in to or changes any device. "
                    "With no command, runs `all`: vendor list, network scan, nearby Wi-Fi, verdict and checklist.")
    p.add_argument("--version", action="version", version=f"airbnb-check {__version__}")
    sub = p.add_subparsers(dest="command", metavar="{all,scan,wifi,checklist,update-oui}")
    sub.add_parser("all", parents=[common], help="everything in one go (default)")
    sub.add_parser("scan", parents=[common], help="scan the current network only")
    sub.add_parser("wifi", parents=[common], help="list nearby Wi-Fi networks and flag camera-like SSIDs")
    sub.add_parser("checklist", parents=[common], help="print the physical inspection checklist")
    sub.add_parser("update-oui", parents=[common], help="download the IEEE MAC vendor list (needs internet)")
    return p


def _report_path(a: argparse.Namespace) -> Path:
    return Path(a.report or datetime.now().strftime("airbnb-check-%Y%m%d-%H%M.md"))


def _write_report(a: argparse.Namespace, text: str) -> None:
    path = _report_path(a)
    path.write_text(text, encoding="utf-8")
    print(i18n.t(a.lang, "report_written", path=path), file=sys.stderr)


def cmd_scan(a: argparse.Namespace) -> int:
    from .scan import run_scan  # lazy: keeps --help instant
    quiet = a.json or not sys.stderr.isatty()
    res = run_scan(a.timeout, a.full, (lambda m: None) if quiet else report.say_stderr)
    print(report.to_json(res) if a.json else report.format_table(res, report.use_color(sys.stdout)))
    if a.report is not None:
        _write_report(a, report.to_markdown(res))
    return 0


def cmd_all(a: argparse.Namespace, raw: list[str]) -> int:
    detail = report.say_stderr if (sys.stderr.isatty() and not a.json) else (lambda m: None)
    res = allmode.run_all(a, raw, report.say_stderr, detail)
    print(allmode.to_json(res) if a.json else allmode.format_text(res, report.use_color(sys.stdout)))
    if a.report is not None:
        _write_report(a, allmode.to_markdown(res))
    return 0


def cmd_update_oui(_: argparse.Namespace) -> int:
    try:
        n = oui.update()
    except (OSError, ValueError) as e:
        raise ScanError(f"could not download the OUI list: {e}")
    print(f"Saved {n} vendor prefixes to {oui.cache_path()}")
    return 0


def _main(argv: list[str] | None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not any(a in COMMANDS for a in args) and not {"-h", "--help", "--version"} & set(args):
        args.insert(0, "all")  # default command
    a = build_parser().parse_args(args)
    # SUPPRESS parents: apply defaults here
    a.timeout, a.lang = getattr(a, "timeout", 1.0), getattr(a, "lang", None) or i18n.detect_lang()
    for k, v in (("json", False), ("full", False), ("offline", False), ("report", None)):
        setattr(a, k, getattr(a, k, v))
    if a.command == "all":
        return cmd_all(a, args)
    if a.command == "scan":
        return cmd_scan(a)
    if a.command == "wifi":
        print(wifi.format_wifi(wifi.scan_wifi()))
    elif a.command == "checklist":
        print(checklist.render(a.lang))
    elif a.command == "update-oui":
        return cmd_update_oui(a)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except ScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
