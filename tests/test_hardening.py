"""Regression tests for the adversarial review: hostile LAN devices, honest verdicts, launcher safety."""
import ipaddress
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import _path  # noqa: F401

from airbnb_check import net, oui, probe, scan
from airbnb_check.classify import classify, needs_deep
from airbnb_check.score import Device, score
from airbnb_check.textutil import clean
from airbnb_check.ui import Term
from airbnb_check.verdict import decide
from airbnb_check.wifi import parse_nmcli

ROOT = Path(__file__).resolve().parent.parent
NET = ipaddress.ip_network("192.168.0.0/24")


def make(ip="192.168.0.20", **kw):
    return classify(score(Device(ip, **kw)))


class InvisibleCharTests(unittest.TestCase):
    def test_more_format_chars(self):
        for ch in ("­", "؜", "⁠", "⁤", "\U000e0041", "￹"):
            self.assertEqual(clean(f"a{ch}b"), "a b", repr(ch))


class VerdictIntegrityTests(unittest.TestCase):
    def test_random_mac_with_rtsp_port_is_not_a_phone(self):
        d = make(mac="ae:a3:62:00:00:01", local_admin=True, ports=[554])
        self.assertTrue(d.suspect)
        self.assertEqual(decide([d], []).result, "suspicious")
        self.assertTrue(needs_deep(d))

    def test_name_cannot_clear_streaming_ports(self):
        self.assertTrue(make(hostname="Juno-iPhone", ports=[8080, 8554]).suspect)
        self.assertTrue(make(ports=[9100, 554]).suspect)                       # "printer" with RTSP
        self.assertTrue(make(vendor="Samsung Electronics", ports=[8001, 554]).suspect)
        self.assertTrue(make(vendor="Wyze Labs", hostname="iphone-9").suspect)  # camera brand, phone-like name
        self.assertFalse(make(vendor="Samsung Electronics", ports=[8001, 8002]).suspect)

    def test_gateway_cannot_hide_a_camera(self):
        self.assertEqual(make(is_gateway=True, ports=[80, 37777]).kind, "camera")
        self.assertEqual(make(is_gateway=True, ports=[34567]).kind, "camera")
        self.assertTrue(make(is_gateway=True, ports=[80, 554]).suspect)
        d = make(is_gateway=True, ports=[80, 443])
        self.assertEqual((d.kind, d.suspect), ("router", False))

    def test_problems_block_green(self):
        d = make(is_self=True)
        self.assertEqual(decide([d], [], []).result, "clear")
        f = decide([d], [], ["something failed"])
        self.assertEqual((f.result, f.problems), ("inconclusive", ["something failed"]))
        self.assertEqual(decide([make(onvif="")], [], ["x"]).result, "camera")          # camera still wins
        self.assertEqual(decide([make(ports=[554])], [], ["x"]).result, "suspicious")


def run_scan_with(**patches):
    info = net.NetInfo("en0", "192.168.0.4", NET, "192.168.0.1")
    base = dict(sweep=lambda n, t: set(), ssdp=lambda i: {}, wsd_onvif=lambda i: {}, mdns=lambda i: {},
                arp_table=lambda i: {}, raise_fd_limit=lambda: None, reverse_dns=lambda ips: {}, netbios=lambda ips: {})
    base.update(patches)
    with mock.patch.multiple(net, **base), mock.patch.object(probe, "open_ports", lambda h, p, t: {}), \
            mock.patch.object(probe, "grab_banners", lambda *a, **k: {}), \
            mock.patch.object(probe, "deep_scan", lambda hosts, t, **k: {h: ([], 65535) for h in hosts}):
        return scan.run_scan(info, Term(quiet=True), 0.1, False, passes=1, oui_table=lambda: {})


class ScanHonestyTests(unittest.TestCase):
    def test_empty_network_is_not_green(self):
        res = run_scan_with()
        f = decide(res.devices, [], res.problems)
        self.assertEqual(f.result, "inconclusive")
        self.assertGreaterEqual(len(res.problems), 1)

    def test_discovery_failure_is_recorded_not_fatal(self):
        def boom(i):
            raise ValueError("malformed packet")
        res = run_scan_with(ssdp=boom, sweep=lambda n, t: {"192.168.0.9"},
                            arp_table=lambda i: {"192.168.0.9": "aa:bb:cc:00:00:01", "192.168.0.1": "aa:bb:cc:00:00:02"})
        self.assertTrue(any("SSDP" in p for p in res.problems))
        self.assertEqual(decide(res.devices, [], res.problems).result, "inconclusive")

    def test_unanalyzable_device_is_never_green(self):
        with mock.patch.object(scan, "classify", side_effect=RuntimeError("boom")):
            res = run_scan_with(sweep=lambda n, t: {"192.168.0.9"},
                                arp_table=lambda i: {"192.168.0.9": "aa:bb:cc:00:00:01"})
        self.assertNotEqual(decide(res.devices, [], res.problems).result, "clear")

    def test_healthy_scan_can_be_green(self):
        res = run_scan_with(sweep=lambda n, t: {"192.168.0.9"},
                            arp_table=lambda i: {"192.168.0.9": "ae:a3:62:00:00:01", "192.168.0.1": "aa:bb:cc:00:00:02"})
        self.assertEqual(res.problems, [])
        self.assertEqual(decide(res.devices, [], res.problems).result, "clear")


class NetworkHardeningTests(unittest.TestCase):
    def test_avahi_output_with_string_ips_does_not_crash(self):
        out = ("=;en0;IPv4;Cam;_rtsp._tcp;local;cam.local;192.168.0.50;554;\n"
               "=;en0;IPv4;Evil;_rtsp._tcp;local;evil.local;8.8.8.8;554;\n"
               "=;en0;IPv4;Bad;_rtsp._tcp;local;bad.local;not-an-ip;554;\n")
        info = net.NetInfo("en0", "192.168.0.4", NET, "192.168.0.1")
        with mock.patch.object(net, "run", return_value=out):
            found = net._mdns_linux(info, 1)
        self.assertEqual(list(found), ["192.168.0.50"])

    def test_run_survives_non_utf8_output(self):
        out = net.run(["/bin/sh", "-c", "printf 'ssid \\377\\376 end'"])
        self.assertIn("ssid", out)

    def test_gateway_must_be_a_literal_ip_in_the_subnet(self):
        for gw in ("link#12", "8.8.8.8", "evil.example.com", "-c9"):
            with mock.patch.object(net, "_default_route", return_value=("en0", gw)), \
                    mock.patch.object(net, "_iface_addr", return_value=("192.168.0.4", 24)):
                self.assertEqual(net.detect().gateway, "", gw)
        with mock.patch.object(net, "_default_route", return_value=("-evil", "192.168.0.1")), \
                mock.patch.object(net, "_iface_addr", return_value=("192.168.0.4", 24)) as ia:
            info = net.detect()
        self.assertEqual((info.iface, info.gateway), ("", "192.168.0.1"))
        ia.assert_not_called()

    def test_collect_caps_replies_per_source(self):
        class Flood:
            def __init__(self):
                self.n = 0
            def settimeout(self, t):
                pass
            def recvfrom(self, n):
                self.n += 1
                if self.n > 100:
                    raise OSError
                return b"x", ("192.168.0.66" if self.n <= 60 else "192.168.0.7", 1900)
        got = net._collect(Flood(), NET, 1.0)
        ips = [ip for ip, _ in got]
        self.assertEqual(ips.count("192.168.0.66"), net.MAX_PER_IP)
        self.assertEqual(ips.count("192.168.0.7"), net.MAX_PER_IP)

    def test_http_get_has_a_hard_deadline_against_slow_drip(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        stop = threading.Event()

        def drip():
            c, _ = srv.accept()
            c.recv(1024)
            try:
                c.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
                while not stop.is_set():
                    c.sendall(b"x")
                    time.sleep(0.1)
            except OSError:
                pass
            finally:
                c.close()
        threading.Thread(target=drip, daemon=True).start()
        t0 = time.monotonic()
        body = net.http_get("127.0.0.1", srv.getsockname()[1], "/", timeout=0.3)
        stop.set()
        srv.close()
        self.assertLess(time.monotonic() - t0, 4)
        self.assertTrue(body.startswith("x"))

    def test_http_get_rejects_bad_paths_and_non_200(self):
        with mock.patch("socket.create_connection", side_effect=AssertionError("must not connect")):
            for path in ("/a b", "/a\r\nHost: x", "x", "/é"):
                self.assertEqual(net.http_get("192.168.0.9", 80, path), "", path)

    def test_netbios_asks_only_the_target(self):
        calls = []

        class S:
            def settimeout(self, t): pass
            def connect(self, addr): calls.append(addr)
            def send(self, d): pass
            def recv(self, n): return b""
            def close(self): pass
        with mock.patch("socket.socket", return_value=S()):
            net._netbios_one("192.168.0.9")
        self.assertEqual(calls, [("192.168.0.9", 137)])

    def test_scan_chunk_survives_fd_exhaustion(self):
        with mock.patch("socket.socket", side_effect=OSError(24, "Too many open files")):
            ip, found, done = probe._scan_chunk(("192.168.0.9", (80, 554), 0.1, time.monotonic() + 5))
        self.assertEqual((found, done), ([], 0))

    def test_banner_task_errors_do_not_abort_the_batch(self):
        def bad(args):
            if args[1] == 80:
                raise RuntimeError("malformed")
            return args[0], args[1], {"server": "x"}
        with mock.patch.object(probe, "banner", bad):
            out = probe.grab_banners({"192.168.0.9": [80, 8080]}, 0.1)
        self.assertEqual(out, {"192.168.0.9": {8080: {"server": "x"}}})


class OuiTests(unittest.TestCase):
    def test_slow_drip_download_gives_up(self):
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n):
                time.sleep(0.15)
                return b"x"
        class Op:
            def open(self, *a, **k): return R()
        with mock.patch.object(oui, "build_opener", return_value=Op()), tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                oui.update(Path(d) / "oui.csv", timeout=0.3)


class WifiParseTests(unittest.TestCase):
    def test_ssid_ending_in_backslash_is_not_dropped(self):
        nets = parse_nmcli("IPCAM\\\\:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80\nMy\\:Net:11\\:22\\:33\\:44\\:55\\:66:40\n")
        self.assertEqual([n.ssid for n in nets], ["IPCAM\\", "My:Net"])
        self.assertEqual([n.signal_pct for n in nets], [80, 40])


class LauncherTests(unittest.TestCase):
    script = ROOT / "run.sh"

    def test_syntax_posix_and_dash(self):
        self.assertEqual(subprocess.run(["sh", "-n", str(self.script)]).returncode, 0)
        dash = shutil.which("dash")
        if dash:
            self.assertEqual(subprocess.run([dash, "-n", str(self.script)]).returncode, 0)

    def test_everything_is_inside_main_and_called_last(self):
        text = self.script.read_text()
        code = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        self.assertEqual(code[0], "main() {")
        self.assertEqual(code[-2:], ['main "$@"', "exit $?"])
        for bad in ("eval ", "sudo", "http://", "| sh", "| bash"):
            self.assertNotIn(bad, "\n".join(code))
        self.assertIn("--proto '=https'", text)

    def test_truncated_script_runs_nothing(self):
        text = self.script.read_text()
        cut = text[: len(text) // 2]
        r = subprocess.run(["sh"], input=cut, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Downloading", r.stdout + r.stderr)

    def test_clone_run_leaves_nothing_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, TMPDIR=tmp, HOME=tmp)
            r = subprocess.run(["sh", str(self.script), "--version"], capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("airbnb-check", r.stdout)
            self.assertEqual(os.listdir(tmp), [])


if __name__ == "__main__":
    unittest.main()
