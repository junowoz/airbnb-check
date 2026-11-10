import ipaddress
import subprocess
import unittest
from pathlib import Path

import _path  # noqa: F401

from airbnb_check import messages, net
from airbnb_check.net import safe_location
from airbnb_check.textutil import clean, md

NET = ipaddress.ip_network("192.168.0.0/24")


class SanitizeTests(unittest.TestCase):
    def test_ansi_and_controls(self):
        self.assertEqual(clean("\x1b[31mred\x1b[0m"), "red")
        self.assertEqual(clean("\x1b]0;evil title\x07ok"), "ok")
        self.assertEqual(clean("a\x00b\x07c\x7fd\x85e\nf\tg"), "a b c d e f g")

    def test_bidi_and_zero_width(self):
        self.assertEqual(clean("abc‮txt.exe⁦x⁩"), "abc txt.exe x")
        self.assertNotIn("​", clean("a​b"))

    def test_truncate(self):
        out = clean("x" * 500, 50)
        self.assertEqual(len(out), 50)
        self.assertTrue(out.endswith("..."))

    def test_markdown_escape(self):
        self.assertEqual(md("a|b *c* [d](e) <x>"), r"a\|b \*c\* \[d\]\(e\) \<x\>")
        self.assertEqual(md("\x1b[31m| evil"), r"\| evil")


class SsrfTests(unittest.TestCase):
    def test_accepts_responder_in_subnet(self):
        self.assertEqual(safe_location("http://192.168.0.9:8008/desc.xml", "192.168.0.9", NET), ("192.168.0.9", 8008, "/desc.xml"))
        self.assertEqual(safe_location("http://192.168.0.9/a?b=1", "192.168.0.9", NET)[2], "/a?b=1")

    def test_rejects(self):
        bad = [("https://192.168.0.9/x", "192.168.0.9"),          # not http
               ("http://192.168.0.10/x", "192.168.0.9"),          # not the responder
               ("http://10.0.0.5/x", "10.0.0.5"),                 # outside scanned subnet
               ("http://169.254.169.254/x", "169.254.169.254"),   # metadata address
               ("http://evil.example.com/x", "192.168.0.9"),      # hostname
               ("http://user@192.168.0.9/x", "192.168.0.9"),      # userinfo trick
               ("http://192.168.0.9:99999/x", "192.168.0.9"),     # bad port
               ("file:///etc/passwd", "192.168.0.9"), ("", "192.168.0.9")]
        for url, ip in bad:
            self.assertIsNone(safe_location(url, ip, NET), url)


class SubnetTests(unittest.TestCase):
    def test_clamp(self):
        n, clamped = net.clamp_network("192.168.4.77", 24)
        self.assertEqual((str(n), clamped), ("192.168.4.0/24", False))
        n, clamped = net.clamp_network("192.168.139.3", 23)
        self.assertEqual((str(n), clamped), ("192.168.139.0/24", True))
        n, clamped = net.clamp_network("10.20.30.40", 8)
        self.assertEqual((str(n), clamped), ("10.20.30.0/24", True))

    def test_small_networks_kept(self):
        self.assertEqual(str(net.clamp_network("10.0.0.5", 26)[0]), "10.0.0.0/26")


class MiscTests(unittest.TestCase):
    def test_run_sh_syntax(self):
        script = Path(__file__).resolve().parent.parent / "run.sh"
        self.assertEqual(subprocess.run(["sh", "-n", str(script)]).returncode, 0)

    def test_messages_format(self):
        self.assertIn("2", messages.t("passes", n=2, gap=5))
        self.assertEqual(len(messages.lines("limits")), 4)

    def test_fixed_tool_paths(self):
        if net.IS_MAC:
            self.assertEqual(net.exe("arp"), "/usr/sbin/arp")
            self.assertEqual(net.exe("ping"), "/sbin/ping")


if __name__ == "__main__":
    unittest.main()
