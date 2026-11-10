"""Command-line interface for airbnb-check."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, allmode, checklist, net, oui, reexec, report, wifi
from .messages import t
from .net import ScanError
from .ui import Term

COMMANDS = ("all", "scan", "wifi", "checklist", "update-oui")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--timeout", type=float, metavar="SEC", help="per-connection timeout in seconds (default 1.0)")
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")
    common.add_argument("--report", nargs="?", const="", metavar="FILE.md",
                        help="also write a Markdown report (default name airbnb-check-YYYYMMDD-HHMM.md)")
    common.add_argument("--full", action="store_true", help="fast pass over all ports 1-65535 for every device (slow)")
    common.add_argument("--offline", action="store_true", help="never download anything (skip the vendor list update)")
    p = argparse.ArgumentParser(
        prog="airbnb-check", parents=[common],
        description="Read-only check of the Wi-Fi you are a guest on for hidden cameras. Only scans your own private "
                    "subnet; never logs in to or changes any device. With no command it runs `all` and ends with a clear verdict.")
    p.add_argument("--version", action="version", version=f"airbnb-check {__version__}")
    sub = p.add_subparsers(dest="command", metavar="{all,scan,wifi,checklist,update-oui}")
    sub.add_parser("all", parents=[common], help="everything in one go (default)")
    sub.add_parser("scan", parents=[common], help="scan the current network and list devices only")
    sub.add_parser("wifi", parents=[common], help="list nearby Wi-Fi networks and flag camera-like SSIDs")
    sub.add_parser("checklist", parents=[common], help="print the full physical inspection checklist")
    sub.add_parser("update-oui", parents=[common], help="download the IEEE MAC vendor list (needs internet)")
    return p


def _write_report(a: argparse.Namespace, text: str, term: Term) -> None:
    path = Path(a.report or datetime.now().strftime("airbnb-check-%Y%m%d-%H%M.md"))
    path.write_text(text, encoding="utf-8")
    term.say(t("report_written", path=path))


def cmd_scan(a: argparse.Namespace, raw: list[str], term: Term) -> int:
    from .scan import run_scan  # lazy: keeps --help instant
    info = net.detect()
    reexec.check_early(info, raw, term.say)
    res = run_scan(info, term, a.timeout, a.full, passes=1, oui_note=lambda: "")
    term.show(report.to_json(res) if a.json else report.format_table(res, term))
    if a.report is not None:
        _write_report(a, "\n".join(report.md_devices(res)), term)
    return 0


def cmd_all(a: argparse.Namespace, raw: list[str], term: Term) -> int:
    res = allmode.run_all(a, raw, term)
    term.show(allmode.to_json(res) if a.json else allmode.format_text(res, term))
    if a.report is not None:
        _write_report(a, allmode.to_markdown(res), term)
    return 0


def _main(argv: list[str] | None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not any(a in COMMANDS for a in args) and not {"-h", "--help", "--version"} & set(args):
        args.insert(0, "all")  # default command
    a = build_parser().parse_args(args)
    a.timeout = getattr(a, "timeout", 1.0)
    for k, v in (("json", False), ("full", False), ("offline", False), ("report", None)):
        setattr(a, k, getattr(a, k, v))
    term = Term(quiet=a.json)
    if a.command == "all":
        return cmd_all(a, args, term)
    if a.command == "scan":
        return cmd_scan(a, args, term)
    if a.command == "wifi":
        print(wifi.format_wifi(wifi.scan_wifi()))
    elif a.command == "checklist":
        print(checklist.render())
    elif a.command == "update-oui":
        try:
            n = oui.update()
        except Exception as e:  # noqa: BLE001
            raise ScanError(f"could not download the OUI list: {e}")
        print(f"Saved {n} vendor prefixes to {oui.cache_path()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # a device name must never crash the final print on a non-UTF-8 terminal
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
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
