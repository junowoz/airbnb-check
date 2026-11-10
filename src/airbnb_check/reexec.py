"""macOS: Homebrew/uv Pythons get an empty ARP table (Local Network privacy); Apple's python3 does not.
Detect that early and transparently re-run the same command under /usr/bin/python3."""
from __future__ import annotations

import os
import sys
from typing import Callable, Mapping

APPLE_PYTHON = "/usr/bin/python3"
ENV_FLAG = "AIRBNB_CHECK_REEXEC"
# /usr/bin/python3 is a shim that may report the real Apple binary path
APPLE_PREFIXES = ("/Library/Developer/CommandLineTools/", "/Applications/Xcode")


def should_reexec(platform: str, executable: str, arp_has_macs: bool, env: Mapping[str, str],
                  apple_exists: bool = True) -> bool:
    is_apple = executable == APPLE_PYTHON or executable.startswith(APPLE_PREFIXES)
    return platform == "darwin" and not arp_has_macs and not is_apple and apple_exists and not env.get(ENV_FLAG)


def reexec(args: list[str], say: Callable[[str], None]) -> None:
    """Replace this process (only returns if exec fails)."""
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT")}
    env["PYTHONPATH"] = pkg_parent  # only our own code, never whatever the caller's environment had
    env[ENV_FLAG] = "1"
    say("macOS blocks this Python from reading MAC addresses (Local Network privacy); "
        "re-running with Apple's /usr/bin/python3...")
    try:
        sys.stdout.flush(); sys.stderr.flush()
        os.execve(APPLE_PYTHON, [APPLE_PYTHON, "-B", "-s", "-m", "airbnb_check", *args], env)
    except OSError as e:
        say(f"  re-exec failed ({e}); continuing here, MAC addresses may be missing.")


def check_early(info, args: list[str], say: Callable[[str], None]) -> None:
    """Quick `arp -an` test before the long scan; re-exec if MACs are unreadable."""
    from . import net
    if not should_reexec(sys.platform, sys.executable, False, os.environ, os.path.exists(APPLE_PYTHON)):
        return
    if info.gateway:
        net._ping((info.gateway, 1.0))  # make sure the gateway has an ARP entry
    if net.arp_table(info):
        return
    reexec(args, say)
