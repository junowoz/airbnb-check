import unittest

import _path  # noqa: F401

from airbnb_check.classify import classify, needs_deep
from airbnb_check.score import Device, score
from airbnb_check.verdict import decide


def make(ip="192.168.0.20", **kw):
    return classify(score(Device(ip, **kw)))


class KindTests(unittest.TestCase):
    def test_router_and_self(self):
        self.assertEqual(make(is_gateway=True, ports=[80, 443]).kind, "router")
        self.assertEqual(make(is_self=True).kind, "self")

    def test_camera_proofs(self):
        self.assertEqual(make(onvif="").kind, "camera")
        self.assertEqual(make(ports=[554], banners={554: {"proto": "rtsp", "status": "RTSP/1.0 401"}}).kind, "camera")
        self.assertEqual(make(vendor="Hangzhou Hikvision Digital").kind, "camera")
        self.assertEqual(make(upnp={"types": "networkvideotransmitter"}).kind, "camera")
        self.assertEqual(make(mdns=["_rtsp._tcp: cam"]).kind, "camera")
        self.assertEqual(make(is_gateway=True, onvif="").kind, "camera")  # even a "router" that speaks ONVIF

    def test_tv(self):
        self.assertEqual(make(vendor="Samsung Electronics", ports=[8001, 8002]).kind, "tv")
        self.assertEqual(make(upnp={"types": "mediarenderer dial"}).kind, "tv")
        self.assertEqual(make(mdns=["_googlecast._tcp: Living room"]).kind, "tv")

    def test_mobile(self):
        self.assertEqual(make(mac="ae:a3:62:00:00:01", local_admin=True).kind, "mobile")  # private MAC, no services
        self.assertEqual(make(hostname="Juno-iPhone", ports=[8080]).kind, "mobile")
        self.assertEqual(make(vendor="Apple, Inc.").kind, "mobile")

    def test_printer_and_iot(self):
        self.assertEqual(make(ports=[9100]).kind, "printer")
        self.assertEqual(make(vendor="Espressif Inc.").kind, "iot")  # chip alone, no services

    def test_suspicious(self):
        d = make(vendor="Espressif Inc.", ports=[80])
        self.assertTrue(d.suspect)
        self.assertEqual(d.kind, "unknown")
        self.assertTrue(make(vendor="Wyze Labs").suspect)       # camera brand, no open port needed
        self.assertTrue(make(ports=[554]).suspect)               # RTSP-like port that did not answer
        self.assertFalse(make(vendor="Espressif Inc.", ports=[80], mdns=["_googlecast._tcp: x"]).suspect)  # identified TV

    def test_unknown_then_deep(self):
        d = make(ports=[49152])
        self.assertEqual(d.kind, "unknown")
        self.assertTrue(needs_deep(d))
        d.deep, d.scanned = True, 65535
        classify(score(d))
        self.assertFalse(needs_deep(d))
        self.assertFalse(d.suspect)
        self.assertIn("no camera services", d.detail)

    def test_deep_pass_can_find_camera(self):
        d = make(ports=[49152])
        d.deep, d.ports = True, [49152, 8555]
        d.banners[8555] = {"proto": "rtsp", "status": "RTSP/1.0 401"}
        self.assertEqual(classify(score(d)).kind, "camera")


class VerdictTests(unittest.TestCase):
    def test_green(self):
        f = decide([make(is_self=True), make(is_gateway=True), make(mac="ae:a3:62:00:00:01", local_admin=True)], [])
        self.assertEqual((f.result, f.total), ("clear", 3))
        self.assertEqual(f.counts, {"self": 1, "router": 1, "mobile": 1})

    def test_green_with_cleared_unknown_and_weak_ssid(self):
        d = make(ports=[49152])
        d.deep = True
        classify(score(d))
        self.assertEqual(decide([d], [("IPC-12", "IPC", False)]).result, "clear")

    def test_yellow_device_and_ssid(self):
        self.assertEqual(decide([make(vendor="Tuya Smart", ports=[80])], []).result, "suspicious")
        self.assertEqual(decide([make(is_self=True)], [("IPC-12", "IPC", True)]).result, "suspicious")

    def test_red_beats_yellow(self):
        f = decide([make(onvif=""), make(vendor="Tuya Smart", ports=[80])], [("IPC-1", "IPC", True)])
        self.assertEqual((f.result, len(f.cameras), len(f.suspects)), ("camera", 1, 1))


if __name__ == "__main__":
    unittest.main()
